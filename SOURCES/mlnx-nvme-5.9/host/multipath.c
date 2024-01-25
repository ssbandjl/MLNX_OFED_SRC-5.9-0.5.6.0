// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2017-2018 Christoph Hellwig.
 */

#ifdef HAVE_BLK_TYPES_REQ_DRV
#include <linux/backing-dev.h>
#include <linux/moduleparam.h>
#include <linux/vmalloc.h>
#include <trace/events/block.h>
#include "nvme.h"

bool multipath = true;
module_param(multipath, bool, 0444);
MODULE_PARM_DESC(multipath,
	"turn on native support for multiple controllers per subsystem");

static const char *nvme_iopolicy_names[] = {
	[NVME_IOPOLICY_NUMA]	= "numa",
	[NVME_IOPOLICY_RR]	= "round-robin",
};

static int iopolicy = NVME_IOPOLICY_NUMA;

#ifdef HAVE_CHECK_OLD_SET_PARAM
static int nvme_set_iopolicy(const char *val, struct kernel_param *kp)
#else
static int nvme_set_iopolicy(const char *val, const struct kernel_param *kp)
#endif
{
	if (!val)
		return -EINVAL;
	if (!strncmp(val, "numa", 4))
		iopolicy = NVME_IOPOLICY_NUMA;
	else if (!strncmp(val, "round-robin", 11))
		iopolicy = NVME_IOPOLICY_RR;
	else
		return -EINVAL;

	return 0;
}

static int nvme_get_iopolicy(char *buf, const struct kernel_param *kp)
{
	return sprintf(buf, "%s\n", nvme_iopolicy_names[iopolicy]);
}

module_param_call(iopolicy, nvme_set_iopolicy, nvme_get_iopolicy,
	&iopolicy, 0644);
MODULE_PARM_DESC(iopolicy,
	"Default multipath I/O policy; 'numa' (default) or 'round-robin'");

void nvme_mpath_default_iopolicy(struct nvme_subsystem *subsys)
{
	subsys->iopolicy = iopolicy;
}

void nvme_mpath_unfreeze(struct nvme_subsystem *subsys)
{
	struct nvme_ns_head *h;

	lockdep_assert_held(&subsys->lock);
	list_for_each_entry(h, &subsys->nsheads, entry)
		if (h->disk)
			blk_mq_unfreeze_queue(h->disk->queue);
}

void nvme_mpath_wait_freeze(struct nvme_subsystem *subsys)
{
	struct nvme_ns_head *h;

	lockdep_assert_held(&subsys->lock);
	list_for_each_entry(h, &subsys->nsheads, entry)
		if (h->disk)
			blk_mq_freeze_queue_wait(h->disk->queue);
}

void nvme_mpath_start_freeze(struct nvme_subsystem *subsys)
{
	struct nvme_ns_head *h;

	lockdep_assert_held(&subsys->lock);
	list_for_each_entry(h, &subsys->nsheads, entry)
		if (h->disk)
			blk_freeze_queue_start(h->disk->queue);
}

void nvme_failover_req(struct request *req)
{
	struct nvme_ns *ns = req->q->queuedata;
	u16 status = nvme_req(req)->status & 0x7ff;
	unsigned long flags;
	struct bio *bio;

	nvme_mpath_clear_current_path(ns);

	/*
	 * If we got back an ANA error, we know the controller is alive but not
	 * ready to serve this namespace.  Kick of a re-read of the ANA
	 * information page, and just try any other available path for now.
	 */
	if (nvme_is_ana_error(status) && ns->ctrl->ana_log_buf) {
		set_bit(NVME_NS_ANA_PENDING, &ns->flags);
		queue_work(nvme_wq, &ns->ctrl->ana_work);
	}

	spin_lock_irqsave(&ns->head->requeue_lock, flags);
	for (bio = req->bio; bio; bio = bio->bi_next) {
#ifdef HAVE_BIO_BI_DISK
		bio->bi_disk = ns->head->disk;
#else
		bio_set_dev(bio, ns->head->disk->part0);
#endif
#ifdef HAVE_BIO_BI_COOKIE
		if (bio->bi_opf & REQ_POLLED) {
			bio->bi_opf &= ~REQ_POLLED;
			bio->bi_cookie = BLK_QC_T_NONE;
		}
#endif
	}
	blk_steal_bios(&ns->head->requeue_list, req);
	spin_unlock_irqrestore(&ns->head->requeue_lock, flags);

	blk_mq_end_request(req, 0);
	kblockd_schedule_work(&ns->head->requeue_work);
}

void nvme_kick_requeue_lists(struct nvme_ctrl *ctrl)
{
	struct nvme_ns *ns;

	down_read(&ctrl->namespaces_rwsem);
	list_for_each_entry(ns, &ctrl->namespaces, list) {
#ifdef HAVE_DISK_UEVENT
		if (!ns->head->disk)
			continue;
		kblockd_schedule_work(&ns->head->requeue_work);
		if (ctrl->state == NVME_CTRL_LIVE)
			disk_uevent(ns->head->disk, KOBJ_CHANGE);
#else
	if (ns->head->disk)
		kblockd_schedule_work(&ns->head->requeue_work);
#endif
	}
	up_read(&ctrl->namespaces_rwsem);
}

static const char *nvme_ana_state_names[] = {
	[0]				= "invalid state",
	[NVME_ANA_OPTIMIZED]		= "optimized",
	[NVME_ANA_NONOPTIMIZED]		= "non-optimized",
	[NVME_ANA_INACCESSIBLE]		= "inaccessible",
	[NVME_ANA_PERSISTENT_LOSS]	= "persistent-loss",
	[NVME_ANA_CHANGE]		= "change",
};

bool nvme_mpath_clear_current_path(struct nvme_ns *ns)
{
	struct nvme_ns_head *head = ns->head;
	bool changed = false;
	int node;

	if (!head)
		goto out;

	for_each_node(node) {
		if (ns == rcu_access_pointer(head->current_path[node])) {
			rcu_assign_pointer(head->current_path[node], NULL);
			changed = true;
		}
	}
out:
	return changed;
}

void nvme_mpath_clear_ctrl_paths(struct nvme_ctrl *ctrl)
{
	struct nvme_ns *ns;

	down_read(&ctrl->namespaces_rwsem);
	list_for_each_entry(ns, &ctrl->namespaces, list) {
		nvme_mpath_clear_current_path(ns);
		kblockd_schedule_work(&ns->head->requeue_work);
	}
	up_read(&ctrl->namespaces_rwsem);
}

void nvme_mpath_revalidate_paths(struct nvme_ns *ns)
{
	struct nvme_ns_head *head = ns->head;
	sector_t capacity = get_capacity(head->disk);
	int node;
	int srcu_idx;

	srcu_idx = srcu_read_lock(&head->srcu);
	list_for_each_entry_rcu(ns, &head->list, siblings) {
		if (capacity != get_capacity(ns->disk))
			clear_bit(NVME_NS_READY, &ns->flags);
	}
	srcu_read_unlock(&head->srcu, srcu_idx);

	for_each_node(node)
		rcu_assign_pointer(head->current_path[node], NULL);
	kblockd_schedule_work(&head->requeue_work);
}

static bool nvme_path_is_disabled(struct nvme_ns *ns)
{
	/*
	 * We don't treat NVME_CTRL_DELETING as a disabled path as I/O should
	 * still be able to complete assuming that the controller is connected.
	 * Otherwise it will fail immediately and return to the requeue list.
	 */
	if (ns->ctrl->state != NVME_CTRL_LIVE &&
	    ns->ctrl->state != NVME_CTRL_DELETING)
		return true;
	if (test_bit(NVME_NS_ANA_PENDING, &ns->flags) ||
	    !test_bit(NVME_NS_READY, &ns->flags))
		return true;
	return false;
}

static struct nvme_ns *__nvme_find_path(struct nvme_ns_head *head, int node)
{
	int found_distance = INT_MAX, fallback_distance = INT_MAX, distance;
	struct nvme_ns *found = NULL, *fallback = NULL, *ns;

	list_for_each_entry_rcu(ns, &head->list, siblings) {
		if (nvme_path_is_disabled(ns))
			continue;

		if (READ_ONCE(head->subsys->iopolicy) == NVME_IOPOLICY_NUMA)
			distance = node_distance(node, ns->ctrl->numa_node);
		else
			distance = LOCAL_DISTANCE;

		switch (ns->ana_state) {
		case NVME_ANA_OPTIMIZED:
			if (distance < found_distance) {
				found_distance = distance;
				found = ns;
			}
			break;
		case NVME_ANA_NONOPTIMIZED:
			if (distance < fallback_distance) {
				fallback_distance = distance;
				fallback = ns;
			}
			break;
		default:
			break;
		}
	}

	if (!found)
		found = fallback;
	if (found)
		rcu_assign_pointer(head->current_path[node], found);
	return found;
}

static struct nvme_ns *nvme_next_ns(struct nvme_ns_head *head,
		struct nvme_ns *ns)
{
	ns = list_next_or_null_rcu(&head->list, &ns->siblings, struct nvme_ns,
			siblings);
	if (ns)
		return ns;
	return list_first_or_null_rcu(&head->list, struct nvme_ns, siblings);
}

static struct nvme_ns *nvme_round_robin_path(struct nvme_ns_head *head,
		int node, struct nvme_ns *old)
{
	struct nvme_ns *ns, *found = NULL;

	if (list_is_singular(&head->list)) {
		if (nvme_path_is_disabled(old))
			return NULL;
		return old;
	}

	for (ns = nvme_next_ns(head, old);
	     ns && ns != old;
	     ns = nvme_next_ns(head, ns)) {
		if (nvme_path_is_disabled(ns))
			continue;

		if (ns->ana_state == NVME_ANA_OPTIMIZED) {
			found = ns;
			goto out;
		}
		if (ns->ana_state == NVME_ANA_NONOPTIMIZED)
			found = ns;
	}

	/*
	 * The loop above skips the current path for round-robin semantics.
	 * Fall back to the current path if either:
	 *  - no other optimized path found and current is optimized,
	 *  - no other usable path found and current is usable.
	 */
	if (!nvme_path_is_disabled(old) &&
	    (old->ana_state == NVME_ANA_OPTIMIZED ||
	     (!found && old->ana_state == NVME_ANA_NONOPTIMIZED)))
		return old;

	if (!found)
		return NULL;
out:
	rcu_assign_pointer(head->current_path[node], found);
	return found;
}

static inline bool nvme_path_is_optimized(struct nvme_ns *ns)
{
	return ns->ctrl->state == NVME_CTRL_LIVE &&
		ns->ana_state == NVME_ANA_OPTIMIZED;
}

inline struct nvme_ns *nvme_find_path(struct nvme_ns_head *head)
{
	int node = numa_node_id();
	struct nvme_ns *ns;

	ns = srcu_dereference(head->current_path[node], &head->srcu);
	if (unlikely(!ns))
		return __nvme_find_path(head, node);

	if (READ_ONCE(head->subsys->iopolicy) == NVME_IOPOLICY_RR)
		return nvme_round_robin_path(head, node, ns);
	if (unlikely(!nvme_path_is_optimized(ns)))
		return __nvme_find_path(head, node);
	return ns;
}

static bool nvme_available_path(struct nvme_ns_head *head)
{
	struct nvme_ns *ns;

	list_for_each_entry_rcu(ns, &head->list, siblings) {
		if (test_bit(NVME_CTRL_FAILFAST_EXPIRED, &ns->ctrl->flags))
			continue;
		switch (ns->ctrl->state) {
		case NVME_CTRL_LIVE:
		case NVME_CTRL_RESETTING:
		case NVME_CTRL_CONNECTING:
			/* fallthru */
			return true;
		default:
			break;
		}
	}
	return false;
}

#ifdef HAVE_BLOCK_DEVICE_OPERATIONS_SUBMIT_BIO
#ifdef HAVE_BIO_BI_COOKIE
static void nvme_ns_head_submit_bio(struct bio *bio)
#else
static blk_qc_t nvme_ns_head_submit_bio(struct bio *bio)
#endif
#else
static blk_qc_t nvme_ns_head_make_request(struct request_queue *q,
	struct bio *bio)
#endif
{
#ifdef HAVE_BIO_BI_DISK
	struct nvme_ns_head *head = bio->bi_disk->private_data;
#else
	struct nvme_ns_head *head = bio->bi_bdev->bd_disk->private_data;
#endif
	struct device *dev = disk_to_dev(head->disk);
	struct nvme_ns *ns;
#ifndef HAVE_BIO_BI_COOKIE
	blk_qc_t ret = BLK_QC_T_NONE;
#endif
	int srcu_idx;

	/*
	 * The namespace might be going away and the bio might be moved to a
	 * different queue via blk_steal_bios(), so we need to use the bio_split
	 * pool from the original queue to allocate the bvecs from.
	 */
#ifdef HAVE_BIO_SPLIT_TO_LIMITS
	bio = bio_split_to_limits(bio);
#else
#ifdef HAVE_BLK_QUEUE_SPLIT_1_PARAM
 	blk_queue_split(&bio);
#else
	blk_queue_split(q, &bio);
#endif
#endif

	srcu_idx = srcu_read_lock(&head->srcu);
	ns = nvme_find_path(head);
	if (likely(ns)) {
#ifdef HAVE_BIO_BI_DISK
		bio->bi_disk = ns->disk;
#else
		bio_set_dev(bio, ns->disk->part0);
#endif
		bio->bi_opf |= REQ_NVME_MPATH;
#ifdef HAVE_TRACE_BLOCK_BIO_REMAP_4_PARAM
		trace_block_bio_remap(bio->bi_disk->queue, bio,
				      disk_devt(ns->head->disk),
				      bio->bi_iter.bi_sector);
#else
		trace_block_bio_remap(bio, disk_devt(ns->head->disk),
 				      bio->bi_iter.bi_sector);
#endif
#ifdef HAVE_SUBMIT_BIO_NOACCT
#ifdef HAVE_BIO_BI_COOKIE
		submit_bio_noacct(bio);
#else
		ret = submit_bio_noacct(bio);
#endif
#else
		ret = direct_make_request(bio);
#endif
	} else if (nvme_available_path(head)) {
		dev_warn_ratelimited(dev, "no usable path - requeuing I/O\n");

		spin_lock_irq(&head->requeue_lock);
		bio_list_add(&head->requeue_list, bio);
		spin_unlock_irq(&head->requeue_lock);
	} else {
		dev_warn_ratelimited(dev, "no available path - failing I/O\n");

		bio_io_error(bio);
	}

	srcu_read_unlock(&head->srcu, srcu_idx);
#ifndef HAVE_BIO_BI_COOKIE
	return ret;
#endif
}

static int nvme_ns_head_open(struct block_device *bdev, fmode_t mode)
{
	if (!nvme_tryget_ns_head(bdev->bd_disk->private_data))
		return -ENXIO;
	return 0;
}

static void nvme_ns_head_release(struct gendisk *disk, fmode_t mode)
{
	nvme_put_ns_head(disk->private_data);
}

#ifdef CONFIG_BLK_DEV_ZONED
static int nvme_ns_head_report_zones(struct gendisk *disk, sector_t sector,
		unsigned int nr_zones, report_zones_cb cb, void *data)
{
	struct nvme_ns_head *head = disk->private_data;
	struct nvme_ns *ns;
	int srcu_idx, ret = -EWOULDBLOCK;

	srcu_idx = srcu_read_lock(&head->srcu);
	ns = nvme_find_path(head);
	if (ns)
		ret = nvme_ns_report_zones(ns, sector, nr_zones, cb, data);
	srcu_read_unlock(&head->srcu, srcu_idx);
	return ret;
}
#else
#define nvme_ns_head_report_zones	NULL
#endif /* CONFIG_BLK_DEV_ZONED */

const struct block_device_operations nvme_ns_head_ops = {
	.owner		= THIS_MODULE,
#ifdef HAVE_BLOCK_DEVICE_OPERATIONS_SUBMIT_BIO
	.submit_bio	= nvme_ns_head_submit_bio,
#endif
	.open		= nvme_ns_head_open,
	.release	= nvme_ns_head_release,
	.ioctl		= nvme_ns_head_ioctl,
#ifdef HAVE_BLKDEV_COMPAT_PTR_IOCTL
	.compat_ioctl	= blkdev_compat_ptr_ioctl,
#endif
	.getgeo		= nvme_getgeo,
#ifdef HAVE_BLK_QUEUE_MAX_ACTIVE_ZONES
	.report_zones	= nvme_ns_head_report_zones,
#endif
	.pr_ops		= &nvme_pr_ops,
};

static inline struct nvme_ns_head *cdev_to_ns_head(struct cdev *cdev)
{
	return container_of(cdev, struct nvme_ns_head, cdev);
}

static int nvme_ns_head_chr_open(struct inode *inode, struct file *file)
{
	if (!nvme_tryget_ns_head(cdev_to_ns_head(inode->i_cdev)))
		return -ENXIO;
	return 0;
}

static int nvme_ns_head_chr_release(struct inode *inode, struct file *file)
{
	nvme_put_ns_head(cdev_to_ns_head(inode->i_cdev));
	return 0;
}

static const struct file_operations nvme_ns_head_chr_fops = {
	.owner		= THIS_MODULE,
	.open		= nvme_ns_head_chr_open,
	.release	= nvme_ns_head_chr_release,
	.unlocked_ioctl	= nvme_ns_head_chr_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
#ifdef HAVE_FILE_OPERATIONS_URING_CMD
	.uring_cmd	= nvme_ns_head_chr_uring_cmd,
#endif
};

#ifdef HAVE_DEVICE_ADD_DISK_3_ARGS
static int nvme_add_ns_head_cdev(struct nvme_ns_head *head)
{
	int ret;

	head->cdev_device.parent = &head->subsys->dev;
	ret = dev_set_name(&head->cdev_device, "ng%dn%d",
			   head->subsys->instance, head->instance);
	if (ret)
		return ret;
	ret = nvme_cdev_add(&head->cdev, &head->cdev_device,
			    &nvme_ns_head_chr_fops, THIS_MODULE);
	return ret;
}
#endif

static void nvme_requeue_work(struct work_struct *work)
{
	struct nvme_ns_head *head =
		container_of(work, struct nvme_ns_head, requeue_work);
	struct bio *bio, *next;

	spin_lock_irq(&head->requeue_lock);
	next = bio_list_get(&head->requeue_list);
	spin_unlock_irq(&head->requeue_lock);

	while ((bio = next) != NULL) {
		next = bio->bi_next;
		bio->bi_next = NULL;

#ifdef HAVE_SUBMIT_BIO_NOACCT
		submit_bio_noacct(bio);
#else
		generic_make_request(bio);
#endif
	}
}

int nvme_mpath_alloc_disk(struct nvme_ctrl *ctrl, struct nvme_ns_head *head)
{
#ifndef HAVE_BLK_ALLOC_DISK
	struct request_queue *q;
#endif
	bool vwc = false;

	mutex_init(&head->lock);
	bio_list_init(&head->requeue_list);
	spin_lock_init(&head->requeue_lock);
	INIT_WORK(&head->requeue_work, nvme_requeue_work);

	/*
	 * Add a multipath node if the subsystems supports multiple controllers.
	 * We also do this for private namespaces as the namespace sharing data could
	 * change after a rescan.
	 */
	if (!(ctrl->subsys->cmic & NVME_CTRL_CMIC_MULTI_CTRL) || !multipath)
		return 0;

#ifdef HAVE_BLK_ALLOC_DISK
	head->disk = blk_alloc_disk(ctrl->numa_node);
#else
#ifdef HAVE_BLOCK_DEVICE_OPERATIONS_SUBMIT_BIO
	q = blk_alloc_queue(ctrl->numa_node);
#else
#ifdef HAVE_BLK_QUEUE_MAKE_REQUEST
#ifdef HAVE_BLK_ALLOC_QUEUE_NODE_3_ARGS
	q = blk_alloc_queue_node(GFP_KERNEL, NUMA_NO_NODE, NULL);
#else
#ifdef HAVE_BLK_ALLOC_QUEUE_RH
	q = blk_alloc_queue_rh(nvme_ns_head_make_request, ctrl->numa_node);
#else
	q = blk_alloc_queue_node(GFP_KERNEL, ctrl->numa_node);
#endif
#endif
#else
	q = blk_alloc_queue(nvme_ns_head_make_request, ctrl->numa_node);
#endif
#endif /* HAVE_BLOCK_DEVICE_OPERATIONS_SUBMIT_BIO */
	if (!q)
		goto out;
#if defined(HAVE_BLK_QUEUE_MAKE_REQUEST) && !defined(HAVE_BLK_ALLOC_QUEUE_RH)
	blk_queue_make_request(q, nvme_ns_head_make_request);
#endif
	blk_queue_flag_set(QUEUE_FLAG_NONROT, q);
	/* set to a default value for 512 until disk is validated */
	blk_queue_logical_block_size(q, 512);
	blk_set_stacking_limits(&q->limits);

	/* we need to propagate up the VMC settings */
	if (ctrl->vwc & NVME_CTRL_VWC_PRESENT)
		vwc = true;
	blk_queue_write_cache(q, vwc, vwc);

	head->disk = alloc_disk(0);
#endif /* HAVE_BLK_ALLOC_DISK */
	if (!head->disk)
#ifdef HAVE_BLK_ALLOC_DISK
		return -ENOMEM;
#else
		goto out_cleanup_queue;
#endif
	head->disk->fops = &nvme_ns_head_ops;
	head->disk->private_data = head;
#ifndef HAVE_BLK_ALLOC_DISK
	head->disk->queue = q;
#endif
#ifdef HAVE_GENHD_FL_EXT_DEVT
	head->disk->flags = GENHD_FL_EXT_DEVT;
#endif
	sprintf(head->disk->disk_name, "nvme%dn%d",
			ctrl->subsys->instance, head->instance);

#ifdef HAVE_BLK_ALLOC_DISK
	blk_queue_flag_set(QUEUE_FLAG_NONROT, head->disk->queue);
	blk_queue_flag_set(QUEUE_FLAG_NOWAIT, head->disk->queue);
	/*
	 * This assumes all controllers that refer to a namespace either
	 * support poll queues or not.  That is not a strict guarantee,
	 * but if the assumption is wrong the effect is only suboptimal
	 * performance but not correctness problem.
	 */
	if (ctrl->tagset->nr_maps > HCTX_TYPE_POLL &&
	    ctrl->tagset->map[HCTX_TYPE_POLL].nr_queues)
		blk_queue_flag_set(QUEUE_FLAG_POLL, head->disk->queue);

	/* set to a default value of 512 until the disk is validated */
	blk_queue_logical_block_size(head->disk->queue, 512);
	blk_set_stacking_limits(&head->disk->queue->limits);
	blk_queue_dma_alignment(head->disk->queue, 3);

	/* we need to propagate up the VMC settings */
	if (ctrl->vwc & NVME_CTRL_VWC_PRESENT)
		vwc = true;
	blk_queue_write_cache(head->disk->queue, vwc, vwc);
	return 0;
#else
	return 0;

 out_cleanup_queue:
	blk_cleanup_queue(q);
 out:
	return -ENOMEM;
#endif
}

static void nvme_mpath_set_live(struct nvme_ns *ns)
{
	struct nvme_ns_head *head = ns->head;
#ifdef HAVE_DEVICE_ADD_DISK_RETURN
	int rc;
#endif

	if (!head->disk)
		return;

	/*
	 * test_and_set_bit() is used because it is protecting against two nvme
	 * paths simultaneously calling device_add_disk() on the same namespace
	 * head.
	 */
#ifdef HAVE_DEVICE_ADD_DISK_3_ARGS
	if (!test_and_set_bit(NVME_NSHEAD_DISK_LIVE, &head->flags)) {
#ifdef HAVE_DEVICE_ADD_DISK_RETURN
		rc = device_add_disk(&head->subsys->dev, head->disk,
				     nvme_ns_id_attr_groups);
		if (rc) {
			clear_bit(NVME_NSHEAD_DISK_LIVE, &ns->flags);
			return;
		}
#else
		device_add_disk(&head->subsys->dev, head->disk,
				nvme_ns_id_attr_groups);
#endif
		nvme_add_ns_head_cdev(head);
	}
#else
	if (!test_and_set_bit(NVME_NSHEAD_DISK_LIVE, &head->flags)) {
		device_add_disk(&head->subsys->dev, head->disk);
		if (sysfs_create_group(&disk_to_dev(head->disk)->kobj,
				&nvme_ns_id_attr_group))
			dev_warn(&head->subsys->dev,
				 "failed to create id group.\n");
	}
#endif

	mutex_lock(&head->lock);
	if (nvme_path_is_optimized(ns)) {
		int node, srcu_idx;

		srcu_idx = srcu_read_lock(&head->srcu);
		for_each_node(node)
			__nvme_find_path(head, node);
		srcu_read_unlock(&head->srcu, srcu_idx);
	}
	mutex_unlock(&head->lock);

	synchronize_srcu(&head->srcu);
	kblockd_schedule_work(&head->requeue_work);
}

static int nvme_parse_ana_log(struct nvme_ctrl *ctrl, void *data,
		int (*cb)(struct nvme_ctrl *ctrl, struct nvme_ana_group_desc *,
			void *))
{
	void *base = ctrl->ana_log_buf;
	size_t offset = sizeof(struct nvme_ana_rsp_hdr);
	int error, i;

	lockdep_assert_held(&ctrl->ana_lock);

	for (i = 0; i < le16_to_cpu(ctrl->ana_log_buf->ngrps); i++) {
		struct nvme_ana_group_desc *desc = base + offset;
		u32 nr_nsids;
		size_t nsid_buf_size;

		if (WARN_ON_ONCE(offset > ctrl->ana_log_size - sizeof(*desc)))
			return -EINVAL;

		nr_nsids = le32_to_cpu(desc->nnsids);
#ifdef flex_array_size
		nsid_buf_size = flex_array_size(desc, nsids, nr_nsids);
#else
		nsid_buf_size = nr_nsids * sizeof(__le32);
#endif

		if (WARN_ON_ONCE(desc->grpid == 0))
			return -EINVAL;
		if (WARN_ON_ONCE(le32_to_cpu(desc->grpid) > ctrl->anagrpmax))
			return -EINVAL;
		if (WARN_ON_ONCE(desc->state == 0))
			return -EINVAL;
		if (WARN_ON_ONCE(desc->state > NVME_ANA_CHANGE))
			return -EINVAL;

		offset += sizeof(*desc);
		if (WARN_ON_ONCE(offset > ctrl->ana_log_size - nsid_buf_size))
			return -EINVAL;

		error = cb(ctrl, desc, data);
		if (error)
			return error;

		offset += nsid_buf_size;
	}

	return 0;
}

static inline bool nvme_state_is_live(enum nvme_ana_state state)
{
	return state == NVME_ANA_OPTIMIZED || state == NVME_ANA_NONOPTIMIZED;
}

static void nvme_update_ns_ana_state(struct nvme_ana_group_desc *desc,
		struct nvme_ns *ns)
{
	ns->ana_grpid = le32_to_cpu(desc->grpid);
	ns->ana_state = desc->state;
	clear_bit(NVME_NS_ANA_PENDING, &ns->flags);
	/*
	 * nvme_mpath_set_live() will trigger I/O to the multipath path device
	 * and in turn to this path device.  However we cannot accept this I/O
	 * if the controller is not live.  This may deadlock if called from
	 * nvme_mpath_init_identify() and the ctrl will never complete
	 * initialization, preventing I/O from completing.  For this case we
	 * will reprocess the ANA log page in nvme_mpath_update() once the
	 * controller is ready.
	 */
	if (nvme_state_is_live(ns->ana_state) &&
	    ns->ctrl->state == NVME_CTRL_LIVE)
		nvme_mpath_set_live(ns);
}

static int nvme_update_ana_state(struct nvme_ctrl *ctrl,
		struct nvme_ana_group_desc *desc, void *data)
{
	u32 nr_nsids = le32_to_cpu(desc->nnsids), n = 0;
	unsigned *nr_change_groups = data;
	struct nvme_ns *ns;

	dev_dbg(ctrl->device, "ANA group %d: %s.\n",
			le32_to_cpu(desc->grpid),
			nvme_ana_state_names[desc->state]);

	if (desc->state == NVME_ANA_CHANGE)
		(*nr_change_groups)++;

	if (!nr_nsids)
		return 0;

	down_read(&ctrl->namespaces_rwsem);
	list_for_each_entry(ns, &ctrl->namespaces, list) {
		unsigned nsid;
again:
		nsid = le32_to_cpu(desc->nsids[n]);
		if (ns->head->ns_id < nsid)
			continue;
		if (ns->head->ns_id == nsid)
			nvme_update_ns_ana_state(desc, ns);
		if (++n == nr_nsids)
			break;
		if (ns->head->ns_id > nsid)
			goto again;
	}
	up_read(&ctrl->namespaces_rwsem);
	return 0;
}

static int nvme_read_ana_log(struct nvme_ctrl *ctrl)
{
	u32 nr_change_groups = 0;
	int error;

	mutex_lock(&ctrl->ana_lock);
	error = nvme_get_log(ctrl, NVME_NSID_ALL, NVME_LOG_ANA, 0, NVME_CSI_NVM,
			ctrl->ana_log_buf, ctrl->ana_log_size, 0);
	if (error) {
		dev_warn(ctrl->device, "Failed to get ANA log: %d\n", error);
		goto out_unlock;
	}

	error = nvme_parse_ana_log(ctrl, &nr_change_groups,
			nvme_update_ana_state);
	if (error)
		goto out_unlock;

	/*
	 * In theory we should have an ANATT timer per group as they might enter
	 * the change state at different times.  But that is a lot of overhead
	 * just to protect against a target that keeps entering new changes
	 * states while never finishing previous ones.  But we'll still
	 * eventually time out once all groups are in change state, so this
	 * isn't a big deal.
	 *
	 * We also double the ANATT value to provide some slack for transports
	 * or AEN processing overhead.
	 */
	if (nr_change_groups)
		mod_timer(&ctrl->anatt_timer, ctrl->anatt * HZ * 2 + jiffies);
	else
		del_timer_sync(&ctrl->anatt_timer);
out_unlock:
	mutex_unlock(&ctrl->ana_lock);
	return error;
}

static void nvme_ana_work(struct work_struct *work)
{
	struct nvme_ctrl *ctrl = container_of(work, struct nvme_ctrl, ana_work);

	if (ctrl->state != NVME_CTRL_LIVE)
		return;

	nvme_read_ana_log(ctrl);
}

void nvme_mpath_update(struct nvme_ctrl *ctrl)
{
	u32 nr_change_groups = 0;

	if (!ctrl->ana_log_buf)
		return;

	mutex_lock(&ctrl->ana_lock);
	nvme_parse_ana_log(ctrl, &nr_change_groups, nvme_update_ana_state);
	mutex_unlock(&ctrl->ana_lock);
}

#ifdef HAVE_TIMER_SETUP
static void nvme_anatt_timeout(struct timer_list *t)
{
	struct nvme_ctrl *ctrl = from_timer(ctrl, t, anatt_timer);
#else
static void nvme_anatt_timeout(unsigned long data)
{
	struct nvme_ctrl *ctrl = (struct nvme_ctrl *)data;
#endif

	dev_info(ctrl->device, "ANATT timeout, resetting controller.\n");
	nvme_reset_ctrl(ctrl);
}

void nvme_mpath_stop(struct nvme_ctrl *ctrl)
{
	if (!nvme_ctrl_use_ana(ctrl))
		return;
	del_timer_sync(&ctrl->anatt_timer);
	cancel_work_sync(&ctrl->ana_work);
}

#define SUBSYS_ATTR_RW(_name, _mode, _show, _store)  \
	struct device_attribute subsys_attr_##_name =	\
		__ATTR(_name, _mode, _show, _store)

static ssize_t nvme_subsys_iopolicy_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct nvme_subsystem *subsys =
		container_of(dev, struct nvme_subsystem, dev);

	return sysfs_emit(buf, "%s\n",
			  nvme_iopolicy_names[READ_ONCE(subsys->iopolicy)]);
}

static ssize_t nvme_subsys_iopolicy_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct nvme_subsystem *subsys =
		container_of(dev, struct nvme_subsystem, dev);
	int i;

	for (i = 0; i < ARRAY_SIZE(nvme_iopolicy_names); i++) {
		if (sysfs_streq(buf, nvme_iopolicy_names[i])) {
			WRITE_ONCE(subsys->iopolicy, i);
			return count;
		}
	}

	return -EINVAL;
}
SUBSYS_ATTR_RW(iopolicy, S_IRUGO | S_IWUSR,
		      nvme_subsys_iopolicy_show, nvme_subsys_iopolicy_store);

static ssize_t ana_grpid_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	return sysfs_emit(buf, "%d\n", nvme_get_ns_from_dev(dev)->ana_grpid);
}
DEVICE_ATTR_RO(ana_grpid);

static ssize_t ana_state_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	struct nvme_ns *ns = nvme_get_ns_from_dev(dev);

	return sysfs_emit(buf, "%s\n", nvme_ana_state_names[ns->ana_state]);
}
DEVICE_ATTR_RO(ana_state);

static int nvme_lookup_ana_group_desc(struct nvme_ctrl *ctrl,
		struct nvme_ana_group_desc *desc, void *data)
{
	struct nvme_ana_group_desc *dst = data;

	if (desc->grpid != dst->grpid)
		return 0;

	*dst = *desc;
	return -ENXIO; /* just break out of the loop */
}

void nvme_mpath_add_disk(struct nvme_ns *ns, __le32 anagrpid)
{
	if (nvme_ctrl_use_ana(ns->ctrl)) {
		struct nvme_ana_group_desc desc = {
			.grpid = anagrpid,
			.state = 0,
		};

		mutex_lock(&ns->ctrl->ana_lock);
		ns->ana_grpid = le32_to_cpu(anagrpid);
		nvme_parse_ana_log(ns->ctrl, &desc, nvme_lookup_ana_group_desc);
		mutex_unlock(&ns->ctrl->ana_lock);
		if (desc.state) {
			/* found the group desc: update */
			nvme_update_ns_ana_state(&desc, ns);
		} else {
			/* group desc not found: trigger a re-read */
			set_bit(NVME_NS_ANA_PENDING, &ns->flags);
			queue_work(nvme_wq, &ns->ctrl->ana_work);
		}
	} else {
		ns->ana_state = NVME_ANA_OPTIMIZED;
		nvme_mpath_set_live(ns);
	}
#ifdef HAVE_QUEUE_FLAG_STABLE_WRITES
	if (blk_queue_stable_writes(ns->queue) && ns->head->disk)
		blk_queue_flag_set(QUEUE_FLAG_STABLE_WRITES,
				   ns->head->disk->queue);
#else
	if (bdi_cap_stable_pages_required(ns->queue->backing_dev_info)) {
		struct gendisk *disk = ns->head->disk;

		if (disk)
			disk->queue->backing_dev_info->capabilities |=
					 BDI_CAP_STABLE_WRITES;
	}
#endif

#ifdef CONFIG_BLK_DEV_ZONED
	if (blk_queue_is_zoned(ns->queue) && ns->head->disk)
#ifdef HAVE_GENDISK_CONV_ZONES_BITMAP
		ns->head->disk->nr_zones = ns->disk->nr_zones;
#else
		ns->head->disk->queue->nr_zones = ns->queue->nr_zones;
#endif
#endif
}

void nvme_mpath_shutdown_disk(struct nvme_ns_head *head)
{
	if (!head->disk)
		return;
	kblockd_schedule_work(&head->requeue_work);
#ifdef HAVE_DEVICE_ADD_DISK_3_ARGS
	if (test_bit(NVME_NSHEAD_DISK_LIVE, &head->flags)) {
		nvme_cdev_del(&head->cdev, &head->cdev_device);
		del_gendisk(head->disk);
	}
#else
	if (test_bit(NVME_NSHEAD_DISK_LIVE, &head->flags)) {
		sysfs_remove_group(&disk_to_dev(head->disk)->kobj,
				   &nvme_ns_id_attr_group);
		del_gendisk(head->disk);
	}
#endif
}

void nvme_mpath_remove_disk(struct nvme_ns_head *head)
{
	if (!head->disk)
		return;
#ifdef HAVE_BLK_MARK_DISK_DEAD
	blk_mark_disk_dead(head->disk);
#else
	blk_set_queue_dying(head->disk->queue);
#endif
	/* make sure all pending bios are cleaned up */
	kblockd_schedule_work(&head->requeue_work);
	flush_work(&head->requeue_work);
#ifdef HAVE_BLK_ALLOC_DISK
#ifdef HAVE_BLK_CLEANUP_DISK
	blk_cleanup_disk(head->disk);
#else
	put_disk(head->disk);
#endif
#else
	blk_cleanup_queue(head->disk->queue);
	if (!test_bit(NVME_NSHEAD_DISK_LIVE, &head->flags))
		head->disk->queue = NULL;
	put_disk(head->disk);
#endif
}

void nvme_mpath_init_ctrl(struct nvme_ctrl *ctrl)
{
	mutex_init(&ctrl->ana_lock);
#ifdef HAVE_TIMER_SETUP
	timer_setup(&ctrl->anatt_timer, nvme_anatt_timeout, 0);
#else
	init_timer(&ctrl->anatt_timer);
	ctrl->anatt_timer.data = (unsigned long)ctrl;
	ctrl->anatt_timer.function = nvme_anatt_timeout;
#endif
	INIT_WORK(&ctrl->ana_work, nvme_ana_work);
}

int nvme_mpath_init_identify(struct nvme_ctrl *ctrl, struct nvme_id_ctrl *id)
{
	size_t max_transfer_size = ctrl->max_hw_sectors << SECTOR_SHIFT;
	size_t ana_log_size;
	int error = 0;

	/* check if multipath is enabled and we have the capability */
	if (!multipath || !ctrl->subsys ||
	    !(ctrl->subsys->cmic & NVME_CTRL_CMIC_ANA))
		return 0;

	if (!ctrl->max_namespaces ||
	    ctrl->max_namespaces > le32_to_cpu(id->nn)) {
		dev_err(ctrl->device,
			"Invalid MNAN value %u\n", ctrl->max_namespaces);
		return -EINVAL;
	}

	ctrl->anacap = id->anacap;
	ctrl->anatt = id->anatt;
	ctrl->nanagrpid = le32_to_cpu(id->nanagrpid);
	ctrl->anagrpmax = le32_to_cpu(id->anagrpmax);

	ana_log_size = sizeof(struct nvme_ana_rsp_hdr) +
		ctrl->nanagrpid * sizeof(struct nvme_ana_group_desc) +
		ctrl->max_namespaces * sizeof(__le32);
	if (ana_log_size > max_transfer_size) {
		dev_err(ctrl->device,
			"ANA log page size (%zd) larger than MDTS (%zd).\n",
			ana_log_size, max_transfer_size);
		dev_err(ctrl->device, "disabling ANA support.\n");
		goto out_uninit;
	}
	if (ana_log_size > ctrl->ana_log_size) {
		nvme_mpath_stop(ctrl);
		nvme_mpath_uninit(ctrl);
		ctrl->ana_log_buf = kvmalloc(ana_log_size, GFP_KERNEL);
		if (!ctrl->ana_log_buf)
			return -ENOMEM;
	}
	ctrl->ana_log_size = ana_log_size;
	error = nvme_read_ana_log(ctrl);
	if (error)
		goto out_uninit;
	return 0;

out_uninit:
	nvme_mpath_uninit(ctrl);
	return error;
}

void nvme_mpath_uninit(struct nvme_ctrl *ctrl)
{
	kvfree(ctrl->ana_log_buf);
	ctrl->ana_log_buf = NULL;
	ctrl->ana_log_size = 0;
}
#endif /* HAVE_BLK_TYPES_REQ_DRV */
