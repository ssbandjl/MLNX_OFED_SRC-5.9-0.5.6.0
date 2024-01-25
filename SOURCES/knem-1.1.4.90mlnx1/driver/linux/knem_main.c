/*
 * Copyright © Inria 2009-2014
 * Brice Goglin <Brice.Goglin@inria.fr>
 *
 * This file is distributed under the GNU General Pulic License version 2.
 */

#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/cpumask.h>
#include <linux/mman.h>
#include <linux/kref.h>
#include <linux/workqueue.h>
#include <linux/idr.h>
#include <linux/random.h>
#include <linux/cred.h>
#include <asm/uaccess.h>

#include "knem_io.h"
#include "knem_hal.h"

/********************
 * Module parameters
 */

#ifdef KNEM_DRIVER_DEBUG
static int knem_debug = 1;
#else
static int knem_debug = 0;
#endif
module_param_named(debug, knem_debug, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(debug, "Verbose debug messages");

#define KNEM__THREAD_DEFAULT 1
static int knem__thread = KNEM__THREAD_DEFAULT;
module_param_named(thread, knem__thread, uint, S_IRUGO);
MODULE_PARM_DESC(thread, "Support offloading of work to a kernel thread");

static int knem_binding = 1;
module_param_named(binding, knem_binding, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(binding, "Bind the kernel thread with-the-user-process (1), anywhere-else (-1) or anywhere (0)");

#define KNEM__DMACPY_DEFAULT 1
static int knem__dmacpy = KNEM__DMACPY_DEFAULT;
module_param_named(dma, knem__dmacpy, uint, S_IRUGO);
MODULE_PARM_DESC(dma, "Support offloading of copies to dma engine");

static unsigned int knem_dma_chunk_min = 1024;
module_param_named(dmamin, knem_dma_chunk_min, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(dmamin, "Minimal chunk size to offload copy on dma engine");

#define KNEM__PINLOCAL_DEFAULT 0
static int knem__pinlocal = KNEM__PINLOCAL_DEFAULT;
module_param_named(pinlocal, knem__pinlocal, uint, S_IRUGO);
MODULE_PARM_DESC(pinlocal, "Enforce page pinning on the local side");

#define KNEM__PINLOCALREAD_DEFAULT 1
static int knem__pinlocalread = KNEM__PINLOCALREAD_DEFAULT;
module_param_named(pinlocalread, knem__pinlocalread, uint, S_IRUGO);
MODULE_PARM_DESC(pinlocalread, "Enforce no page pinning on the local side for read");

#define KNEM__SYNC_DEFAULT 0
static int knem__sync = KNEM__SYNC_DEFAULT;
module_param_named(sync, knem__sync, uint, S_IRUGO);
MODULE_PARM_DESC(sync, "Enforce synchronous copy");

static unsigned int knem_force_flags = 0;
module_param_named(forceflags, knem_force_flags, uint, S_IRUGO);
MODULE_PARM_DESC(forceflags, "Mask of flags to be forced on");

static unsigned int knem_ignore_flags = 0;
module_param_named(ignoreflags, knem_ignore_flags, uint, S_IRUGO);
MODULE_PARM_DESC(ignoreflags, "Mask of flags to be ignored");

static unsigned long knem_stats_buflen = PAGE_SIZE;
module_param_named(statslen, knem_stats_buflen, ulong, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(statslen, "Maximal size of statistics buffer len");

static int knem_stats_verbose = 0;
module_param_named(statsverbose, knem_stats_verbose, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(statsverbose, "List currently open instances and regions together with stats");

/************************************
 * Types, constants, macros, globals
 */

#define dprintk(args...) do { if (unlikely(knem_debug)) printk(KERN_INFO "knem: " args); } while (0)

#ifdef KNEM_SRC_VERSION
#define KNEM_VERSION_STR PACKAGE_VERSION " (" KNEM_SRC_VERSION ")"
#else
#define KNEM_VERSION_STR PACKAGE_VERSION
#endif

/* Cookies are made of a context id, some flags, and a region id */

#define KNEM_COOKIE_CTX_BITS 31
#define KNEM_COOKIE_CTX_MASK ((1ULL<<KNEM_COOKIE_CTX_BITS)-1)
#define KNEM_COOKIE_CTX_SHIFT 0
typedef u32 knem_context_id_t;

#define KNEM_COOKIE_FLAGS_BITS 1
#define KNEM_COOKIE_FLAG_SINGLEUSE (1<<0)
#define KNEM_COOKIE_FLAGS_MASK ((1ULL<<KNEM_COOKIE_FLAGS_BITS)-1)
#define KNEM_COOKIE_FLAGS_SHIFT KNEM_COOKIE_CTX_BITS

#define KNEM_COOKIE_REGION_BITS 32
#define KNEM_COOKIE_REGION_MASK ((1ULL<<KNEM_COOKIE_REGION_BITS)-1)
#define KNEM_COOKIE_REGION_SHIFT (KNEM_COOKIE_CTX_BITS+KNEM_COOKIE_FLAGS_BITS)
typedef u32 knem_region_id_t;

/* knem_cookie_t is a u64 */
#if KNEM_COOKIE_CTX_BITS + KNEM_COOKIE_FLAGS_BITS + KNEM_COOKIE_REGION_BITS > 64
#error Cannot store that many cookie bits
#endif

#define KNEM_BUILD_COOKIE(ctx, region, flags) ((						\
	 (((knem_cookie_t) (region)->id) & KNEM_COOKIE_REGION_MASK) << KNEM_COOKIE_REGION_SHIFT	\
	) | (											\
	 (((knem_cookie_t) (flags)) & KNEM_COOKIE_FLAGS_MASK) << KNEM_COOKIE_FLAGS_SHIFT	\
	) | (											\
	 (((knem_cookie_t) (ctx)->id) & KNEM_COOKIE_CTX_MASK) << KNEM_COOKIE_CTX_SHIFT		\
	))
#define KNEM_COOKIE_TO_CTX_ID(cookie) ((knem_context_id_t) ((cookie >> KNEM_COOKIE_CTX_SHIFT) & KNEM_COOKIE_CTX_MASK))
#define KNEM_COOKIE_TO_FLAGS(cookie) ((unsigned long) ((cookie >> KNEM_COOKIE_FLAGS_SHIFT) & KNEM_COOKIE_FLAGS_MASK))
#define KNEM_COOKIE_TO_REGION_ID(cookie) ((knem_region_id_t) ((cookie >> KNEM_COOKIE_REGION_SHIFT) & KNEM_COOKIE_REGION_MASK))

#ifdef KNEM_HAVE_RCU_IDR
/* IDR is used for lookup, keep a single list for listing all regions */
#define KNEM_REGION_HTBL_SIZE 1
#define KNEM_REGION_ID_HTBL_KEY(region_id) 0
#else
/* Hash-table is used for lookup. IDA/IDR is only used for ID allocation.
 * Hash regions using the last bits of the region-id part of the cookie.
 */
#define KNEM_REGION_HTBL_BITS 6
#define KNEM_REGION_HTBL_SIZE (1ULL << KNEM_REGION_HTBL_BITS)
#define KNEM_REGION_ID_HTBL_KEY(region_id) ((region_id) & (KNEM_REGION_HTBL_SIZE-1))
#endif

struct knem_context {
	/* Contexts are obtained from the file descriptor private data (always valid as long as it's open)
	 * or by looking up the context array using cookies.
	 * No reference counter is used since other processes only use the context temporarily
	 * under RCU lock to lookup the region.
	 * The context is destroyed when closing the file descriptor, after waiting for other processes
	 * to be gone (by waiting for RCU grace period to expire).
	 */

	knem_context_id_t id;
	unsigned int force_flags;
	unsigned int ignore_flags;
	knem_kuid_t uid;

#define KNEM_STATUS_ARRAY_UNUSED 0 /* status_array is NULL, no mmap yet, no async request */
#define KNEM_STATUS_ARRAY_READY 1 /* status_array and friends are allocated and ready */
#define KNEM_STATUS_ARRAY_CREATING -1 /* status is being allocated by mmap, cannot be used yet, but nobody yes can mmap anymore */
	int status_array_state;
	unsigned long status_index_max; /* number of knem_status_t slots (<= U32MAX+1 because knem_io.h uses u32 for async_status_index) */
	knem_status_t * status_array; /* array of status_index_max knem_status_t slots */
	struct page ** status_pages; /* physical pages containing the status_array */

	u32 *notify_fd_array;
	unsigned long notify_fd_pending;
	u32 notify_fd_next_write;
	u32 notify_fd_to_read;
	spinlock_t notify_fd_lock;
	wait_queue_head_t notify_fd_wq;

	/* regions are protected by a spinlock and RCU lock */
	spinlock_t regions_lock;
	struct list_head region_list_head[KNEM_REGION_HTBL_SIZE]; /* Hash-table for lookup, or single list for listing when IDR is used for lookup */
	struct knem_regions_idr regions_idr; /* Used for ID allocation. And for lookup if IDR is RCU-aware */
	unsigned region_id_magic;

	cpumask_t kthread_cpumask;
	unsigned kthread_cpumask_enforced : 1;
	struct task_struct *kthread_task; /* only if in async mode, i.e. if status_array_state == KNEM_STATUS_ARRAY_READY */
	wait_queue_head_t kthread_work_wq;
	struct list_head kthread_work_list;
	spinlock_t kthread_work_lock;

#ifdef KNEM_HAVE_DMA_ENGINE
	struct dma_chan *dmacpy_chan;
	struct list_head dmacpy_cleanup_work_list;
	spinlock_t dmacpy_cleanup_work_lock;
	struct timer_list dmacpy_cleanup_timer;
#endif

	/* deferred destroying */
	struct work_struct destroy_work;
	struct rcu_head destroy_rcu_head;
};

#define KNEM_DMACPY_CLEANUP_TIMEOUT HZ /* cleanup after 1 second if nobody did it */

struct knem_region {
	/* Reference counter that is initialized when the region is queued for the first time
	 * (never initialized for temporary local regions during inline copy).
	 * A reference is held as long as the region is queued.
	 * Other processes take a reference while using a region, and release it when
	 * their work is completed.
	 * The region is unpinned/freed when the last user goes away, either because it
	 * got destroyed by its owner, or because another process finished using it.
	 */
	struct kref refcount;

	/* Region are queued into a list in the context
	 * (except emporary local regions during inline copy).
	 */
	struct list_head region_list_elt;

	knem_region_id_t id;
	unsigned single_use : 1;
	unsigned dirty : 1;
	unsigned any_user : 1;
	unsigned protection;
	unsigned long length; /* sum of all iovec lengths, in bytes */

	/* only usable during inline_copy and create_region */
	unsigned long uiovec_nr;		/* valid uiovecs */
	struct knem_cmd_param_iovec *uiovecs;	/* allocated with the region, no need to free explicitly */

	/* always consistent so that knem_unpin_region() works, but may be empty before the region gets pinned */
	unsigned long piovec_nr;		/* valid piovecs (more than that may actually be allocated) */
	struct knem_pinned_iovec *piovecs;	/* allocated with the region, no need to free explicitly */

	/* deferred destroying */
	struct work_struct destroy_work;
	struct rcu_head destroy_rcu_head;
};

struct knem_pinned_iovec {
	unsigned long aligned_vaddr;
	unsigned first_page_offset;
	unsigned long len;
	unsigned long page_nr;
	int vmalloced;
	struct page ** pages;
};

enum knem_work_type {
	KNEM_WORK_MEMCPY_PINNED,
	KNEM_WORK_MEMCPY_TO_USER, /* cannot be offloaded */
	KNEM_WORK_MEMCPY_FROM_USER, /* cannot be offloaded */
	KNEM_WORK_DMACPY,
};

struct knem_work {
	struct list_head list_elt;
	enum knem_work_type type;
	unsigned int flags;
	struct knem_region *src_region;
	unsigned long src_offset;
	struct knem_region *dst_region;
	unsigned long dst_offset;
	struct knem_region *local_region; /* one fo the above region might be local to this work */
	unsigned long length; /* actual bytes to copy, which may stop before the end of some regions */
	knem_status_t *status;
	unsigned long status_index; /* only valid for async requests */
	union {
#ifdef KNEM_HAVE_DMA_ENGINE
		struct {
			dma_cookie_t last_cookie;
		} dmacpy;
#endif
	};
};

/* forward declarations */
static void knem_put_region(struct knem_region *region);
static void knem_put_region_rcu(struct rcu_head *rcu_head);
static void knem_free_work(struct knem_work *work);
static void knem_do_work(struct knem_context *ctx, struct knem_work *work);
#ifdef KNEM_HAVE_DMA_ENGINE
static void knem_dmacpy_partial_cleanup_until(struct knem_context *ctx, dma_cookie_t cookie);
#endif
static int knem_foreach_ctx_region(struct knem_context * ctx, int (*cb)(int, void *, void *), void *data);
static int knem_foreach_context(int (*cb)(int, void *, void *), void *data);

/********
 * Flags
 */

static inline int
knem_setup_flags(void)
{
	if (!knem__dmacpy) {
		dprintk("Adding DMA (0x%x) to ignored flags (%s)\n",
			(unsigned) KNEM_FLAG_DMA,
			knem__dmacpy != KNEM__DMACPY_DEFAULT ? "module param" : "default");
		knem_ignore_flags |= KNEM_FLAG_DMA;
	}

	if (knem__pinlocal) {
		dprintk("Adding PINLOCAL (0x%x) to forced flags (%s)\n",
			(unsigned) KNEM_FLAG_PINLOCAL,
			knem__pinlocal != KNEM__PINLOCAL_DEFAULT ? "module param" : "default");
		knem_force_flags |= KNEM_FLAG_PINLOCAL;
	}

	if (knem__sync) {
		dprintk("Adding ANY_ASYNC_MASK (0x%x) to ignored flags (%s)\n",
			(unsigned) KNEM_FLAG_ANY_ASYNC_MASK,
			knem__sync != KNEM__SYNC_DEFAULT ? "module param" : "default");
		knem_ignore_flags |= KNEM_FLAG_ANY_ASYNC_MASK;
	}

	if (!knem__thread) {
		dprintk("Adding ANY_THREAD_MASK (0x%x) to ignored flags (%s)\n",
			(unsigned) KNEM_FLAG_ANY_THREAD_MASK,
			knem__thread != KNEM__THREAD_DEFAULT ? "module param" : "default");
		knem_ignore_flags |= KNEM_FLAG_ANY_THREAD_MASK;
	}

	dprintk("Forcing flags 0x%x, ignoring 0x%x\n",
		knem_force_flags, knem_ignore_flags);

	if (knem_force_flags & knem_ignore_flags) {
		dprintk("Cannot ignore and force flags 0x%x\n",
			knem_force_flags & knem_ignore_flags);
		return -EINVAL;
	}

	return 0;
}

#define KNEM_FIX_COPY_FLAGS(ctx, flags) (((flags) | ctx->force_flags) & ~ctx->ignore_flags & KNEM_FLAG_ANY_COPY_MASK)
#define KNEM_FIX_CREATE_FLAGS(ctx, flags) (((flags) | ctx->force_flags) & ~ctx->ignore_flags & KNEM_FLAG_ANY_CREATE_MASK)

/***********
 * Counters
 */

enum knem_counter_index_e {
	KNEM_COUNTER_SUBMITTED = 0,
	KNEM_COUNTER_PROCESSED,
	KNEM_COUNTER_PROCESSED_DMA,
	KNEM_COUNTER_PROCESSED_THREAD,
	KNEM_COUNTER_PROCESSED_PINLOCAL,
	KNEM_COUNTER_REJECTED_INVALIDFLAGS,
	KNEM_COUNTER_REJECTED_NOMEM,
	KNEM_COUNTER_REJECTED_READCMD,
	KNEM_COUNTER_REJECTED_FINDREGION,
	KNEM_COUNTER_REJECTED_PIN,
	KNEM_COUNTER_FAILED_MEMCPY_USER,
	KNEM_COUNTER_FAILED_DMACPY,
	KNEM_COUNTER_DMACPY_CLEANUP_TIMEOUT,
	KNEM_COUNTER_MAX,
};

static unsigned long long knem_counters[KNEM_COUNTER_MAX];

#ifdef KNEM_DRIVER_DEBUG
static spinlock_t knem_counters_spinlock;
#define knem_counters_lock_init()	spin_lock_init(&knem_counters_spinlock)
#define knem_counters_lock()		spin_lock(&knem_counters_spinlock)
#define knem_counters_unlock()		spin_unlock(&knem_counters_spinlock)
#else
#define knem_counters_lock_init()
#define knem_counters_lock()
#define knem_counters_unlock()
#endif

#define knem_counter_inc(name) do {		\
	knem_counters_lock();			\
	knem_counters[KNEM_COUNTER_##name]++;	\
	knem_counters_unlock();			\
} while (0)

#define knem_counter_read(name) knem_counters[KNEM_COUNTER_##name]

static void
knem_clear_counters(void)
{
	knem_counters_lock();
	memset(&knem_counters, 0, sizeof(knem_counters));
	knem_counters_unlock();
}

static void
knem_init_counters(void)
{
	knem_counters_lock_init();
	knem_clear_counters();
}

struct knem_foreach_context_snprintf_data {
	unsigned nr_contexts_shown;
	unsigned nr_contexts_hidden;
	unsigned nr_regions;
	char *current_buffer;
	size_t remaining_length;
};

static int
knem_foreach_ctx_region_snprintf_cb(int id, void *p, void *d)
{
	struct knem_region *region = p;
	struct knem_foreach_context_snprintf_data *data = d;
	unsigned int tmplen;

	data->nr_regions++;
	tmplen = snprintf(data->current_buffer, data->remaining_length,
			  "  Region %08x%s\n",
			  (unsigned) region->id,
			  region->single_use ? " SingleUse" : "");
	tmplen = tmplen >= data->remaining_length ? data->remaining_length : tmplen; data->current_buffer += tmplen; data->remaining_length -= tmplen;
	return 0;
}

static int
knem_foreach_context_snprintf_cb(int id, void *p, void *d)
{
	struct knem_context *ctx = p;
	struct knem_foreach_context_snprintf_data *data = d;
	unsigned int tmplen;

	if (!knem_uid_eq(current_uid(), ctx->uid) && !capable(CAP_SYS_ADMIN)) {
		data->nr_contexts_hidden++;
		return 0;
	}
	data->nr_contexts_shown++;

	tmplen = snprintf(data->current_buffer, data->remaining_length,
			  " Context %08x\n",
			  (unsigned) ctx->id);
	tmplen = tmplen >= data->remaining_length ? data->remaining_length : tmplen; data->current_buffer += tmplen; data->remaining_length -= tmplen;

	data->nr_regions = 0;
	knem_foreach_ctx_region(ctx, knem_foreach_ctx_region_snprintf_cb, data);

	tmplen = snprintf(data->current_buffer, data->remaining_length, "  Listed %d regions\n", data->nr_regions);
	tmplen = tmplen >= data->remaining_length ? data->remaining_length : tmplen; data->current_buffer += tmplen; data->remaining_length -= tmplen;
	return 0;
}

static ssize_t
knem_read_counters(char __user * buff, size_t count, loff_t* offp)
{
	ssize_t ret = 0;
	char *buffer, *tmp;
	unsigned int rlen, tmplen;

	rlen = knem_stats_buflen;
	buffer = kmalloc(rlen, GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto out;
	}
	tmp = buffer;

	tmplen = snprintf(tmp, rlen,
			  "knem " KNEM_VERSION_STR "\n");
	tmplen = tmplen >= rlen ? rlen : tmplen; tmp += tmplen; rlen -= tmplen;

	tmplen = snprintf(tmp, rlen,
			  " Driver ABI=0x%x\n", KNEM_ABI_VERSION);
	tmplen = tmplen >= rlen ? rlen : tmplen; tmp += tmplen; rlen -= tmplen;

	tmplen = snprintf(tmp, rlen,
			  " Flags: forcing 0x%x, ignoring 0x%x\n", knem_force_flags, knem_ignore_flags);
	tmplen = tmplen >= rlen ? rlen : tmplen; tmp += tmplen; rlen -= tmplen;

#ifdef CONFIG_NET_DMA
	if (!knem__dmacpy)
		tmplen = snprintf(tmp, rlen,
				  " DMAEngine: KernelSupported Disabled\n");
	else if (!knem_dma_channel_avail())
		tmplen = snprintf(tmp, rlen,
				  " DMAEngine: KernelSupported Enabled NoChannelAvailable\n");
	else
		tmplen = snprintf(tmp, rlen,
				  " DMAEngine: KernelSupported Enabled ChansAvail ChunkMin=%dB\n",
				  knem_dma_chunk_min);
#else
	tmplen = snprintf(tmp, rlen,
			  " DMAEngine: NoKernelSupport\n");
#endif
	tmplen = tmplen >= rlen ? rlen : tmplen; tmp += tmplen; rlen -= tmplen;

#ifdef KNEM_DRIVER_DEBUG
	tmplen = snprintf(tmp, rlen,
			  " Debug: BuiltIn %s\n",
			  knem_debug ? "Enabled" : "Disabled");
#else
	tmplen = snprintf(tmp, rlen,
			  " Debug: NotBuilt\n");
#endif
	tmplen = tmplen >= rlen ? rlen : tmplen; tmp += tmplen; rlen -= tmplen;

	tmplen = snprintf(tmp, rlen,
			  " Requests submitted                           : %lld\n"
			  " Requests processed (total)                   : %lld\n"
			  "          processed (using DMA)               : %lld\n"
			  "          processed (offloaded to thread)     : %lld\n"
			  "          processed (with pinned local pages) : %lld\n"
			  " Requests rejected (invalid flags)            : %lld\n"
			  "          rejected (not enough memory)        : %lld\n"
			  "          rejected (invalid ioctl argument)   : %lld\n"
			  "          rejected (unexisting region cookie) : %lld\n"
			  "          rejected (failed to pin local pages): %lld\n"
			  " Requests failed during memcpy from/to user   : %lld\n"
			  "          failed during DMA copy              : %lld\n"
			  " DMA copy cleanup timeout                     : %lld\n",
			  knem_counter_read(SUBMITTED),
			  knem_counter_read(PROCESSED),
			  knem_counter_read(PROCESSED_DMA),
			  knem_counter_read(PROCESSED_THREAD),
			  knem_counter_read(PROCESSED_PINLOCAL),
			  knem_counter_read(REJECTED_INVALIDFLAGS),
			  knem_counter_read(REJECTED_NOMEM),
			  knem_counter_read(REJECTED_READCMD),
			  knem_counter_read(REJECTED_FINDREGION),
			  knem_counter_read(REJECTED_PIN),
			  knem_counter_read(FAILED_MEMCPY_USER),
			  knem_counter_read(FAILED_DMACPY),
			  knem_counter_read(DMACPY_CLEANUP_TIMEOUT));
	tmplen = tmplen >= rlen ? rlen : tmplen; tmp += tmplen; rlen -= tmplen;

	if (knem_stats_verbose) {
		struct knem_foreach_context_snprintf_data data = {
			.nr_contexts_shown = 0,
			.nr_contexts_hidden = 0,
			.current_buffer = tmp,
			.remaining_length = rlen,
		};

		rcu_read_lock();
		knem_foreach_context(knem_foreach_context_snprintf_cb, &data);
		rcu_read_unlock();

		tmp = data.current_buffer;
		rlen = data.remaining_length;
		if (data.nr_contexts_hidden)
			tmplen = snprintf(tmp, rlen, " Listed %d contexts (%d hidden)\n", data.nr_contexts_shown, data.nr_contexts_hidden);
		else
			tmplen = snprintf(tmp, rlen, " Listed %d contexts\n", data.nr_contexts_shown);
		tmplen = tmplen >= rlen ? rlen : tmplen; tmp += tmplen;	rlen -= tmplen;
	}

	if (!rlen)
		*(tmp-1) = '\0';

	if (*offp > tmp-buffer)
		goto out_with_buffer;

	if (*offp + count > tmp-buffer)
		count = tmp-buffer - *offp;

	ret = copy_to_user(buff, buffer + *offp, count);
	if (ret)
		ret = -EFAULT;
	else
		ret = count;

	*offp += count;

 out_with_buffer:
	kfree(buffer);
 out:
	return ret;
}

/*************************
 * Context IDs Management
 */

/* Contexts are created/released under a lock, and traversed under RCU lock */
static spinlock_t knem_contexts_lock;
static knem_context_id_t knem_context_id_magic;

#define KNEM_CTX_INDEX_TO_ID(index) (knem_context_id_t) ((index) ^ knem_context_id_magic)
#define KNEM_CTX_ID_TO_INDEX(id) (unsigned) ((id) ^ knem_context_id_magic)

#ifdef KNEM_HAVE_RCU_IDR

static struct idr knem_contexts_idr;
#define KNEM_CTX_MAX (KNEM_COOKIE_CTX_MASK+1)

#else /* KNEM_HAVE_RCU_IDR */

static struct knem_context __rcu **knem_contexts;
static int knem_contexts_nr_free;
#define KNEM_CTX_MAX 1024
#if KNEM_CTX_MAX > KNEM_COOKIE_CTX_MASK+1
#error Cannot store context id in cookie bits
#endif

#endif /* KNEM_HAVE_RCU_IDR */

static int
knem_contexts_init(void)
{
	spin_lock_init(&knem_contexts_lock);

#ifdef KNEM_HAVE_RCU_IDR
	idr_init(&knem_contexts_idr);
#else /* KNEM_HAVE_RCU_IDR */
	knem_contexts = kzalloc(KNEM_CTX_MAX * sizeof(*knem_contexts), GFP_KERNEL);
	if (!knem_contexts) {
		dprintk("Failed to alloc the context array\n");
		return -ENOMEM;
	}
	knem_contexts_nr_free = KNEM_CTX_MAX;
#endif /* KNEM_HAVE_RCU_IDR */

	get_random_bytes(&knem_context_id_magic, sizeof(knem_context_id_magic));
	knem_context_id_magic &= KNEM_COOKIE_CTX_MASK;

	dprintk("Supporting %ld contexts, masking ids with %08x\n",
		(unsigned long) KNEM_CTX_MAX, (unsigned) knem_context_id_magic);
	return 0;
}

static void
knem_contexts_exit(void)
{
#ifdef KNEM_HAVE_RCU_IDR
	idr_destroy(&knem_contexts_idr);
#else /* KNEM_HAVE_RCU_IDR */
	BUG_ON(knem_contexts_nr_free != KNEM_CTX_MAX);
	kfree(knem_contexts);
#endif /* KNEM_HAVE_RCU_IDR */
}

static int
knem_assign_context_id(struct knem_context *ctx)
{
	int id;

#ifdef KNEM_HAVE_IDR_PRELOAD
	int err;
	idr_preload(GFP_KERNEL);
	spin_lock(&knem_contexts_lock);
	err = idr_alloc(&knem_contexts_idr, ctx, 0, 0, GFP_NOWAIT);
	spin_unlock(&knem_contexts_lock);
	idr_preload_end();
	if (err < 0)
		return err;
	id = err;
#elif defined KNEM_HAVE_RCU_IDR
	int err;
	if (!idr_pre_get(&knem_contexts_idr, GFP_KERNEL))
		return -ENOMEM;
	spin_lock(&knem_contexts_lock);
	err = idr_get_new(&knem_contexts_idr, ctx, &id);
	if (err) {
		spin_unlock(&knem_contexts_lock);
		return err;
	}
#ifdef MAX_ID_MASK
	id &= MAX_ID_MASK; /* mask out internal idr bits that old kernels may leave in there */
#endif
	if (id > KNEM_COOKIE_CTX_MASK) {
		idr_remove(&knem_contexts_idr, id);
		spin_unlock(&knem_contexts_lock);
		return -EBUSY;
	}
	spin_unlock(&knem_contexts_lock);
#else /* !KNEM_HAVE_IDR_PRELOAD && !KNEM_HAVE_RCU_IDR */
	spin_lock(&knem_contexts_lock);
	/* is there a context available? */
	if (!knem_contexts_nr_free) {
		dprintk("No more contexts available\n");
		spin_unlock(&knem_contexts_lock);
		return -EBUSY;
	}
	/* get a context and mark it as used */
	for(id=0; id<KNEM_CTX_MAX; id++)
		if (!rcu_access_pointer(knem_contexts[id]))
			break;
	rcu_assign_pointer(knem_contexts[id], ctx);
	knem_contexts_nr_free--;
	spin_unlock(&knem_contexts_lock);
#endif /* !KNEM_HAVE_IDR_PRELOAD && !KNEM_HAVE_RCU_IDR */

	ctx->id = KNEM_CTX_INDEX_TO_ID(id);
	dprintk("Inserted new context %08x (#%x)\n", (unsigned) ctx->id, id);
	return 0;
}

static void
knem_release_context_id(struct knem_context *ctx)
{
	knem_context_id_t ctx_id = ctx->id;
	unsigned ctx_index = KNEM_CTX_ID_TO_INDEX(ctx_id);

	spin_lock(&knem_contexts_lock);
#ifdef KNEM_HAVE_RCU_IDR
	idr_remove(&knem_contexts_idr, ctx_index);
#else /* KNEM_HAVE_RCU_IDR */
	knem_contexts_nr_free++;
	RCU_INIT_POINTER(knem_contexts[ctx_index], NULL);
#endif /* KNEM_HAVE_RCU_IDR */
	spin_unlock(&knem_contexts_lock);

	dprintk("Unlinked context %08x (#%x)\n", (unsigned) ctx->id, ctx_index);
}

/* Called under RCU lock */
static struct knem_context *
knem_find_context_by_id(knem_context_id_t ctx_id)
{
	unsigned ctx_index = KNEM_CTX_ID_TO_INDEX(ctx_id);
	struct knem_context * ctx;

#ifdef KNEM_HAVE_RCU_IDR
	ctx = idr_find(&knem_contexts_idr, ctx_index);
	if (unlikely(!ctx)) {
		dprintk("Failed to find remote cookie context %08x (#%x)\n",
			(unsigned) ctx_id, (unsigned) ctx_index);
		return NULL;
	}
#else /* KNEM_HAVE_RCU_IDR */
	if (ctx_index >= KNEM_CTX_MAX) {
		dprintk("Invalid remote cookie context %08x (#%x)\n",
			(unsigned) ctx_id, (unsigned) ctx_index);
		return NULL;
	}
	ctx = rcu_dereference(knem_contexts[ctx_index]);
	if (unlikely(!ctx)) {
		dprintk("Failed to find remote cookie context %08x (#%x)\n",
			(unsigned) ctx_id, (unsigned) ctx_index);
		return NULL;
	}
#endif /* KNEM_HAVE_RCU_IDR */

	return ctx;
}

/* Called under RCU lock */
static int
knem_foreach_context(int (*cb)(int, void *, void *), void *data)
{
	int err = 0;

#ifdef KNEM_HAVE_RCU_IDR
	err = idr_for_each(&knem_contexts_idr, cb, data);
#else /* KNEM_HAVE_RCU_IDR */
	int i;
	for(i=0; i<KNEM_CTX_MAX; i++) {
		struct knem_context *ctx = rcu_dereference(knem_contexts[i]);
		if (!ctx)
			continue;
		err = cb(ctx->id, ctx, data);
		if (err)
			return err;
	}
#endif /* KNEM_HAVE_RCU_IDR */

	return err;
}


/************************
 * Region IDs Management
 */

#define KNEM_CTX_REGION_INDEX_TO_ID(ctx, index) (knem_region_id_t) ((index) ^ ((ctx)->region_id_magic))
#define KNEM_CTX_REGION_ID_TO_INDEX(ctx, id) (unsigned) ((id) ^ ((ctx)->region_id_magic))

static void
knem_ctx_regions_init(struct knem_context * ctx)
{
	int i;
	for(i=0; i<KNEM_REGION_HTBL_SIZE; i++)
		INIT_LIST_HEAD(&ctx->region_list_head[i]);
	spin_lock_init(&ctx->regions_lock);
	knem_regions_idr_init(&ctx->regions_idr);

	get_random_bytes(&ctx->region_id_magic, sizeof(ctx->region_id_magic));
	ctx->region_id_magic &= KNEM_COOKIE_REGION_MASK;
}

static int
knem_ctx_regions_destroy(struct knem_context * ctx)
{
	struct knem_region *region, *nregion;
	knem_context_id_t ctx_id = ctx->id;
	int count = 0;
	int i;

	/* remove remaining regions */
	spin_lock(&ctx->regions_lock);
	for(i=0; i<KNEM_REGION_HTBL_SIZE; i++)
		list_for_each_entry_safe(region, nregion, &ctx->region_list_head[i], region_list_elt) {
			dprintk("Destroying region %08x on context %08x close\n",
				(unsigned) region->id, (unsigned) ctx_id);
			list_del_rcu(&region->region_list_elt);
			knem_regions_idr_remove(&ctx->regions_idr, KNEM_CTX_REGION_ID_TO_INDEX(ctx, region->id));
			call_rcu(&region->destroy_rcu_head, knem_put_region_rcu);
			count++;
		}
	knem_regions_idr_destroy(&ctx->regions_idr);
	spin_unlock(&ctx->regions_lock);

	return count;
}

static int
knem_insert_ctx_region(struct knem_context * ctx, struct knem_region *region)
{
	int htbl_key;
	int err;
	int id;

#ifdef KNEM_HAVE_IDR_PRELOAD
	idr_preload(GFP_KERNEL);
	spin_lock(&ctx->regions_lock);

	err = idr_alloc(&ctx->regions_idr, region, 0, 0, GFP_NOWAIT);
	if (err > KNEM_COOKIE_CTX_MASK) {
		idr_remove(&ctx->regions_idr, err);
		err = -EBUSY;
	}
	if (err < 0)
		goto out_with_lock;
	id = err;

	region->id = KNEM_CTX_REGION_INDEX_TO_ID(ctx, id);
	htbl_key = KNEM_REGION_ID_HTBL_KEY(region->id);
	list_add_tail_rcu(&region->region_list_elt, &ctx->region_list_head[htbl_key]);

	spin_unlock(&ctx->regions_lock);
	idr_preload_end();
#else /* !KNEM_HAVE_IDR_PRELOAD */
	if (!knem_regions_idr_pre_get(&ctx->regions_idr, GFP_KERNEL))
		return -ENOMEM;

	spin_lock(&ctx->regions_lock);

	err = knem_regions_idr_get_new(&ctx->regions_idr, region, &id);
	if (err < 0)
		goto out_with_lock;

#ifdef MAX_ID_MASK
	id &= MAX_ID_MASK; /* mask out internal idr bits that old kernels may leave in there */
#endif
	if (id > KNEM_COOKIE_CTX_MASK) {
		knem_regions_idr_remove(&ctx->regions_idr, id);
		err = -EBUSY;
		goto out_with_lock;
	}

	region->id = KNEM_CTX_REGION_INDEX_TO_ID(ctx, id);
	htbl_key = KNEM_REGION_ID_HTBL_KEY(region->id);
	list_add_tail_rcu(&region->region_list_elt, &ctx->region_list_head[htbl_key]);

	spin_unlock(&ctx->regions_lock);
#endif /* !KNEM_HAVE_IDR_PRELOAD */

	dprintk("Inserted region %08x in context %08x\n",
		(unsigned) region->id, (unsigned) ctx->id);
	return 0;

 out_with_lock:
	spin_unlock(&ctx->regions_lock);
#ifdef KNEM_HAVE_IDR_PRELOAD
	idr_preload_end();
#endif
	return err;
}

/* Called under RCU lock */
static struct knem_region *
knem_find_ctx_region_by_id(struct knem_context * ctx, knem_region_id_t region_id, int write, int singleuse)
{
	int region_index = KNEM_CTX_REGION_ID_TO_INDEX(ctx, region_id);
	struct knem_region * region;

#ifdef KNEM_HAVE_RCU_IDR
	region = idr_find(&ctx->regions_idr, region_index);
	if (region)
		goto found;
#else /* KNEM_HAVE_RCU_IDR */
	int htbl_key = KNEM_REGION_ID_HTBL_KEY(region_id);
	list_for_each_entry_rcu(region, &ctx->region_list_head[htbl_key], region_list_elt)
		if (likely(region->id == region_id))
			goto found;
#endif /* KNEM_HAVE_RCU_IDR */

	/* not found */
	dprintk("Failed to find region %08x in context %08x\n",
		(unsigned) region_id, (unsigned) ctx->id);
	return ERR_PTR(-EINVAL);

 found:
	if (!region->any_user && !knem_uid_eq(ctx->uid, current_uid()))
		return ERR_PTR(-EPERM);
	if ((write && !(region->protection & PROT_WRITE))
	    || (!write && !(region->protection & PROT_READ)))
		return ERR_PTR(-EACCES);

	if (singleuse) {
		/* keep the existing refcount since we're dequeueing */
		list_del_rcu(&region->region_list_elt);
		knem_regions_idr_remove(&ctx->regions_idr, region_index);
	} else {
		kref_get(&region->refcount);
	}
	return region;
}

static struct knem_region *
knem_remove_ctx_region_by_id(struct knem_context * ctx, knem_region_id_t region_id)
{
	int region_index = KNEM_CTX_REGION_ID_TO_INDEX(ctx, region_id);
	struct knem_region * region;

#ifdef KNEM_HAVE_RCU_IDR
	spin_lock(&ctx->regions_lock);
	region = idr_find(&ctx->regions_idr, region_index);
	if (region)
		goto found;
	spin_unlock(&ctx->regions_lock);
#else /* KNEM_HAVE_RCU_IDR */
	int htbl_key = KNEM_REGION_ID_HTBL_KEY(region_id);
	spin_lock(&ctx->regions_lock);
	list_for_each_entry(region, &ctx->region_list_head[htbl_key], region_list_elt)
		if (likely(region->id == region_id))
			goto found;
	spin_unlock(&ctx->regions_lock);
#endif /* KNEM_HAVE_RCU_IDR */

	/* not found */
	dprintk("Failed to remove region %08x from context %08x\n",
		(unsigned) region_id, (unsigned) ctx->id);
	return ERR_PTR(-EINVAL);

 found:
	/* keep the existing refcount since we're dequeueing */
	list_del_rcu(&region->region_list_elt);
	knem_regions_idr_remove(&ctx->regions_idr, region_index);
	spin_unlock(&ctx->regions_lock);
	dprintk("Removed region %08x from context %08x\n",
		(unsigned) region->id, (unsigned) ctx->id);
	return region;
}

/* Called under RCU locks */
static int
knem_foreach_ctx_region(struct knem_context * ctx, int (*cb)(int, void *, void *), void *data)
{
	struct knem_region *region;
	int err = 0;
	int i;

	for(i=0; i<KNEM_REGION_HTBL_SIZE; i++)
		list_for_each_entry_rcu(region, &ctx->region_list_head[i], region_list_elt) {
			err = cb(region->id, region, data);
			if (err)
				return err;
		}

	return err;
}


/************************
 * Pinning and unpinning
 */

#define KNEM_IOVEC_VMALLOC_PAGES_THRESHOLD 4096

/*
 * always returns the region in a coherent state that knem_unpin_region() can free,
 * which means piovec_nr must be valid.
 */
static int
knem_pin_region(struct knem_region *region, int write)
{
	struct knem_cmd_param_iovec *uiovec;
	struct knem_pinned_iovec *piovec;
	unsigned long uiovec_nr = region->uiovec_nr;
	unsigned long i;
	int err = 0;

	BUG_ON(region->piovecs == NULL);
	BUG_ON(region->uiovecs == NULL);
	BUG_ON(region->piovec_nr != 0);

	uiovec = &region->uiovecs[0];
	piovec = &region->piovecs[0];

	for(i=0; i<uiovec_nr; i++, uiovec++) {
		unsigned long aligned_vaddr, offset, len, aligned_len, page_nr;
		struct page **pages;

		if (unlikely(!uiovec->len))
			continue;

		aligned_vaddr = uiovec->base & PAGE_MASK;
		len = uiovec->len;
		offset = uiovec->base & (~PAGE_MASK);
		aligned_len = PAGE_ALIGN(offset + len);
		page_nr = aligned_len >> PAGE_SHIFT;

		piovec->aligned_vaddr = aligned_vaddr;
		piovec->first_page_offset = offset;
		piovec->len = len;

		if (page_nr > KNEM_IOVEC_VMALLOC_PAGES_THRESHOLD) {
			pages = vmalloc(page_nr * sizeof(struct page *));
			piovec->vmalloced = 1;
		} else {
			pages = kmalloc(page_nr * sizeof(struct page *), GFP_KERNEL);
			piovec->vmalloced = 0;
		}
		if (unlikely(!pages)) {
			dprintk("Failed to allocate iovec array for %ld pages\n", page_nr);
			err = -ENOMEM;
			goto out;
		}

		/* keep region in a coherent state */
		piovec->pages = pages;
		piovec->page_nr = 0;
		region->piovec_nr++;

		err = knem_get_user_pages_fast(aligned_vaddr, page_nr, write, pages);
		if (unlikely(err != page_nr)) {
			dprintk("Failed to pin iovec, got %d instead of %ld\n", err, page_nr);
			if (err > 0)
				piovec->page_nr = err;
			err = -EFAULT;
			goto out;
		}
		piovec->page_nr = page_nr;

		piovec++;
	}

 out:
	return err;
}

static void
knem_unpin_region(const struct knem_region *region)
{
	const struct knem_pinned_iovec *piovec, *piovec_max;
	unsigned long piovec_nr = region->piovec_nr;
	int j;

	BUG_ON(region->dirty && !(region->protection & PROT_WRITE));

	piovec_max = &region->piovecs[piovec_nr];
	for(piovec = &region->piovecs[0]; piovec < piovec_max; piovec++) {
		struct page **pages = piovec->pages;
		for(j=0; j<piovec->page_nr; j++) {
			if (region->dirty)
				set_page_dirty_lock(pages[j]);
			put_page(pages[j]);
		}
		if (piovec->vmalloced)
			vfree(pages);
		else
			kfree(pages);
	}
}


/*******************
 * Managing regions
 */

static void
knem_free_region(struct knem_region *region)
{
	/* no need to free piovecs or uiovecs, they are allocated with the region */
	knem_unpin_region(region);
	kfree(region);
}

static void
knem_free_region_work(knem_work_struct_data_t data)
{
	struct knem_region *region = KNEM_WORK_STRUCT_DATA(data, struct knem_region, destroy_work);
	knem_free_region(region);
}

/* called when the last reference on a region is being released */
static void
knem_kref_free_region(struct kref *kref)
{
	struct knem_region *region = container_of(kref, struct knem_region, refcount);
	/* the last reference is usually a RCU callback, so we can't free the region there (needs vmalloc) */
	KNEM_INIT_WORK(&region->destroy_work, knem_free_region_work, region);
	schedule_work(&region->destroy_work);
}

static void
knem_put_region(struct knem_region *region)
{
	kref_put(&region->refcount, knem_kref_free_region);
}

/* called to release a reference on a region after a RCU grace period */
static void
knem_put_region_rcu(struct rcu_head *rcu_head)
{
	struct knem_region *region = container_of(rcu_head, struct knem_region, destroy_rcu_head);
	knem_put_region(region);
}

static struct knem_region *
knem_find_region(knem_cookie_t cookie, int write)
{
	struct knem_context * remote_ctx;
	struct knem_region * region;
	knem_context_id_t cookie_ctx_id;
	knem_region_id_t region_id;
	unsigned long cookie_flags;

	cookie_ctx_id = KNEM_COOKIE_TO_CTX_ID(cookie);
	region_id = KNEM_COOKIE_TO_REGION_ID(cookie);
	cookie_flags = KNEM_COOKIE_TO_FLAGS(cookie);

	rcu_read_lock();

	remote_ctx = knem_find_context_by_id(cookie_ctx_id);
	if (!remote_ctx) {
		rcu_read_unlock();
		return ERR_PTR(-EINVAL);
	}

	if (cookie_flags & KNEM_COOKIE_FLAG_SINGLEUSE) {
		spin_lock(&remote_ctx->regions_lock);
		region = knem_find_ctx_region_by_id(remote_ctx, region_id, write, 1);
		spin_unlock(&remote_ctx->regions_lock);
		/* nobody else could acquire this single-use region, so we won't have to wait until the RCU grace period expires */
	} else {
		region = knem_find_ctx_region_by_id(remote_ctx, region_id, write, 0);
	}

	rcu_read_unlock();

	return region;
}

static struct knem_region *
knem_dequeue_local_region(struct knem_context * ctx, knem_cookie_t cookie)
{
	struct knem_region * region;
	knem_region_id_t region_id;

	region_id = KNEM_COOKIE_TO_REGION_ID(cookie);
	region = knem_remove_ctx_region_by_id(ctx, region_id);

	return region;
}


/**************
 * Poll Events
 */

static void
knem_notify_fd_add(struct knem_context * ctx, u32 status_index)
{
	spin_lock(&ctx->notify_fd_lock);
	/* add an event */
	ctx->notify_fd_pending--;
	ctx->notify_fd_array[ctx->notify_fd_next_write] = status_index;
	ctx->notify_fd_to_read++;
	/* update next write */
	ctx->notify_fd_next_write++;
	if (ctx->notify_fd_next_write == ctx->status_index_max)
		ctx->notify_fd_next_write = 0;
        wake_up_interruptible(&ctx->notify_fd_wq);
	spin_unlock(&ctx->notify_fd_lock);
}

static ssize_t
knem_notify_fd_read(struct knem_context * ctx, struct file * file, char __user * buff, size_t count, loff_t* offp)
{
	int ret = 0, err;

	if (count % sizeof(u32))
		return -EINVAL;

	while (count) {
		spin_lock(&ctx->notify_fd_lock);
		/* read as many slots as available/needed */
		while (count && ctx->notify_fd_to_read) {
			/* take one slot */
			u32 next_read;
			u32 index;

			next_read = ctx->notify_fd_next_write - ctx->notify_fd_to_read;
			if (ctx->notify_fd_next_write < ctx->notify_fd_to_read)
				next_read += ctx->status_index_max;
			BUG_ON(next_read >= ctx->status_index_max);

			ctx->notify_fd_to_read--;
			index = ctx->notify_fd_array[next_read];

			spin_unlock(&ctx->notify_fd_lock);

			/* give it to user-space */
			put_user(index, (u32 __user *) buff);
			buff += sizeof(u32);
			ret += sizeof(u32);
			count -= sizeof(u32);
			if (!count)
				/* we're done! */
				goto done;

			spin_lock(&ctx->notify_fd_lock);
		}
		spin_unlock(&ctx->notify_fd_lock);

		/* not enough slots, return or sleep */
		if (file->f_flags & O_NONBLOCK) {
			if (!ret)
				ret = -EAGAIN;
			break;
		}
		err = wait_event_interruptible(ctx->notify_fd_wq, ctx->notify_fd_to_read != 0);
		if (err) {
			if (!ret)
				ret = -EINTR;
			break;
		}
	}

done:
	return ret;
}

static inline unsigned int
knem_notify_fd_poll(struct knem_context * ctx, struct file * file, struct poll_table_struct *wait)
{
        unsigned int mask = 0;

	if (ctx->status_array_state != KNEM_STATUS_ARRAY_READY) {
                mask |= POLLERR;
                goto out;
        }

        poll_wait(file, &ctx->notify_fd_wq, wait);
        if (ctx->notify_fd_to_read)
                mask |= POLLIN;

out:
        return mask;

}

/***********************************************
 * Copying between pinned iovecs and user-space
 */

static int
knem_memcpy_pinned_user(unsigned long loc_addr,
			struct page * const * rem_page, unsigned rem_first_page_offset,
			unsigned long remaining, int write)
{
	int err;

	while (remaining) {
		unsigned long chunk = remaining;
		void *rem_addr;

		if (likely(rem_first_page_offset + chunk > PAGE_SIZE))
			chunk = PAGE_SIZE - rem_first_page_offset;

		rem_addr = kmap(*rem_page);
		if (write)
			err = copy_from_user(rem_addr + rem_first_page_offset,
					     (void __user *) loc_addr,
					     chunk);
		else
			err = copy_to_user((void __user *) loc_addr,
					   rem_addr + rem_first_page_offset,
					   chunk);
		kunmap(*rem_page);
		if (unlikely(err)) {
			dprintk("Failed to access local user-space %lx-%ld\n",
				loc_addr, chunk);
			err = -EFAULT;
			goto out;
		}

		remaining -= chunk;
		rem_page++;
		rem_first_page_offset = 0;
		loc_addr += chunk;
	}

	return 0;

 out:
	return err;
}

static int
knem_vectmemcpy_pinned_user(const struct knem_region *loc_region, /* no offset for destination, this is a temporary region matching the exact destination */
			    const struct knem_region *rem_region, unsigned long rem_offset,
			    unsigned long length, int write)
{
	const struct knem_cmd_param_iovec * cur_loc_uiovec = &loc_region->uiovecs[0];
	const struct knem_cmd_param_iovec * loc_uiovec_max = cur_loc_uiovec + loc_region->uiovec_nr;
	unsigned long cur_loc_addr = cur_loc_uiovec->base;
	unsigned long cur_loc_len = cur_loc_uiovec->len;

	const struct knem_pinned_iovec * cur_rem_piovec = &rem_region->piovecs[0];
	const struct knem_pinned_iovec * rem_piovec_max = cur_rem_piovec + rem_region->piovec_nr;
	struct page * const * cur_rem_pages;
	unsigned cur_rem_first_page_offset;
	unsigned long cur_rem_len;

	int err;

	while (rem_offset > cur_rem_piovec->len) {
		rem_offset -= cur_rem_piovec->len;
		cur_rem_piovec++;
		if (unlikely(cur_rem_piovec == rem_piovec_max))
			return 0;
	}
	cur_rem_len = cur_rem_piovec->len - rem_offset;
	cur_rem_pages = cur_rem_piovec->pages + ((cur_rem_piovec->first_page_offset + rem_offset) >> PAGE_SHIFT);
	cur_rem_first_page_offset = (cur_rem_piovec->first_page_offset + rem_offset) & (~PAGE_MASK);

	while (1) {
		unsigned long chunk = min(cur_loc_len, cur_rem_len);
		if (unlikely(chunk > length))
			chunk = length;

		err = knem_memcpy_pinned_user(cur_loc_addr,
					      cur_rem_pages, cur_rem_first_page_offset,
					      chunk, write);
		if (unlikely(err < 0))
			return err;

		length -= chunk;
		if (unlikely(!length))
			break;

		if (chunk == cur_rem_len) {
			/* next rem iovec */
			cur_rem_piovec++;
			BUG_ON(cur_rem_piovec == rem_piovec_max);
			cur_rem_pages = cur_rem_piovec->pages;
			cur_rem_first_page_offset = cur_rem_piovec->first_page_offset;
			cur_rem_len = cur_rem_piovec->len;
		} else {
			/* advance in current rem iovec */
			cur_rem_pages += ((cur_rem_first_page_offset + chunk) >> PAGE_SHIFT);
			cur_rem_first_page_offset = (cur_rem_first_page_offset + chunk) & (~PAGE_MASK);
			cur_rem_len -= chunk;
		}

		if (chunk == cur_loc_len) {
			/* next loc iovec */
			cur_loc_uiovec++;
			BUG_ON(cur_loc_uiovec == loc_uiovec_max);
			cur_loc_addr = cur_loc_uiovec->base;
			cur_loc_len = cur_loc_uiovec->len;
		} else {
			/* advance in current loc iovec */
			cur_loc_addr += chunk;
			cur_loc_len -= chunk;
		}
	}

	return 0;
}

static void
knem_do_work_memcpy_to_user(struct knem_context *ctx,
			    struct knem_work *work)
{
	struct knem_region *dst_region = work->dst_region;
	const struct knem_region *src_region = work->src_region;
	unsigned long src_offset = work->src_offset;
	knem_status_t *status = work->status;
	int err = 0;

	BUG_ON(!work->length);
	BUG_ON(work->dst_offset);
	BUG_ON(!dst_region->uiovecs); /* cleared on offload, not possible here */

	if (likely(src_region->piovec_nr == 1 && dst_region->uiovec_nr == 1)) {
		/* optimize the contigous case */
		const struct knem_pinned_iovec *src_piovec = &src_region->piovecs[0];
		struct page * const * src_pages = src_piovec->pages + ((src_piovec->first_page_offset + src_offset) >> PAGE_SHIFT);
		unsigned src_first_page_offset = (src_piovec->first_page_offset + src_offset) & (~PAGE_MASK);
		err = knem_memcpy_pinned_user(dst_region->uiovecs[0].base,
					      src_pages, src_first_page_offset,
					      work->length, 0);
	} else if (likely(src_region->piovec_nr > 0 && dst_region->uiovec_nr > 0)) {
		/* generic vectorial case */
		err = knem_vectmemcpy_pinned_user(dst_region, src_region, src_offset, work->length, 0);
	}

	if (unlikely(err)) {
		dprintk("memcpy_to_user failed (error %d)\n", -err);
		knem_counter_inc(FAILED_MEMCPY_USER);
		*status = KNEM_STATUS_FAILED;
	} else
		*status = KNEM_STATUS_SUCCESS;

	if (unlikely(work->flags & KNEM_FLAG_NOTIFY_FD))
		knem_notify_fd_add(ctx, work->status_index);

	/* no need to set local region as dirty, we used the user-space mapping to write into it */
}

static void
knem_do_work_memcpy_from_user(struct knem_context *ctx,
			      struct knem_work *work)
{
	struct knem_region *dst_region = work->dst_region;
	struct knem_region *src_region = work->src_region;
	unsigned long dst_offset = work->dst_offset;
	knem_status_t *status = work->status;
	int err = 0;

	BUG_ON(!work->length);
	BUG_ON(work->src_offset);
	BUG_ON(!src_region->uiovecs); /* cleared on offload, not possible here */

	if (likely(dst_region->piovec_nr == 1 && src_region->uiovec_nr == 1)) {
		/* optimize the contigous case */
		const struct knem_pinned_iovec *dst_piovec = &dst_region->piovecs[0];
		struct page * const * dst_pages = dst_piovec->pages + ((dst_piovec->first_page_offset + dst_offset) >> PAGE_SHIFT);
		unsigned dst_first_page_offset = (dst_piovec->first_page_offset + dst_offset) & (~PAGE_MASK);
		err = knem_memcpy_pinned_user(src_region->uiovecs[0].base,
					      dst_pages, dst_first_page_offset,
					      work->length, 1);
	} else if (likely(dst_region->piovec_nr > 0 && src_region->uiovec_nr > 0)) {
		/* generic vectorial case */
		err = knem_vectmemcpy_pinned_user(src_region, dst_region, dst_offset, work->length, 1);
	}

	if (unlikely(err)) {
		dprintk("memcpy_from_user failed (error %d)\n", -err);
		knem_counter_inc(FAILED_MEMCPY_USER);
		*status = KNEM_STATUS_FAILED;
	} else
		*status = KNEM_STATUS_SUCCESS;

	if (unlikely(work->flags & KNEM_FLAG_NOTIFY_FD))
		knem_notify_fd_add(ctx, work->status_index);

	dst_region->dirty = 1;
}

/********************************
 * Copying between pinned iovecs
 */

static void
knem_memcpy_pinned(struct page * const * dst_page, unsigned dst_first_page_offset,
		   struct page * const * src_page, unsigned src_first_page_offset,
		   unsigned long remaining)
{
	void *src_addr = knem_kmap_atomic(*src_page, KM_USER0);
	void *dst_addr = knem_kmap_atomic(*dst_page, KM_USER1);

	while (1) {
		unsigned long chunk = remaining;
		if (likely(src_first_page_offset + chunk > PAGE_SIZE))
			chunk = PAGE_SIZE - src_first_page_offset;
		if (likely(dst_first_page_offset + chunk > PAGE_SIZE))
			chunk = PAGE_SIZE - dst_first_page_offset;

		memcpy(dst_addr + dst_first_page_offset,
		       src_addr + src_first_page_offset,
		       chunk);

		remaining -= chunk;
		if (unlikely(!remaining))
			break;

		if (chunk == PAGE_SIZE - src_first_page_offset) {
			knem_kunmap_atomic(src_addr, KM_USER0);
			src_page++;
			src_first_page_offset = 0;
			src_addr = knem_kmap_atomic(*src_page, KM_USER0);
		} else {
			src_first_page_offset += chunk;
		}

		if (chunk == PAGE_SIZE - dst_first_page_offset) {
			knem_kunmap_atomic(dst_addr, KM_USER1);
			dst_page++;
			dst_first_page_offset = 0;
			dst_addr = knem_kmap_atomic(*dst_page, KM_USER1);
		} else {
			dst_first_page_offset += chunk;
		}
	}

	knem_kunmap_atomic(src_addr, KM_USER0);
	knem_kunmap_atomic(dst_addr, KM_USER1);
}

static void
knem_vectmemcpy_pinned(const struct knem_region *dst_region, unsigned long dst_offset,
		       const struct knem_region *src_region, unsigned long src_offset,
		       unsigned long length)
{
	const struct knem_pinned_iovec * cur_dst_piovec = &dst_region->piovecs[0];
	const struct knem_pinned_iovec * dst_piovec_max = cur_dst_piovec + dst_region->piovec_nr;
	struct page * const * cur_dst_pages;
	unsigned cur_dst_first_page_offset;
	unsigned long cur_dst_len;

	const struct knem_pinned_iovec * cur_src_piovec = &src_region->piovecs[0];
	const struct knem_pinned_iovec * src_piovec_max = cur_src_piovec + src_region->piovec_nr;
	struct page * const * cur_src_pages;
	unsigned cur_src_first_page_offset;
	unsigned long cur_src_len;

	while (dst_offset > cur_dst_piovec->len) {
		dst_offset -= cur_dst_piovec->len;
		cur_dst_piovec++;
		if (unlikely(cur_dst_piovec == dst_piovec_max))
			return;
	}
	cur_dst_len = cur_dst_piovec->len - dst_offset;
	cur_dst_pages = cur_dst_piovec->pages + ((cur_dst_piovec->first_page_offset + dst_offset) >> PAGE_SHIFT);
	cur_dst_first_page_offset = (cur_dst_piovec->first_page_offset + dst_offset) & (~PAGE_MASK);

	while (src_offset > cur_src_piovec->len) {
		src_offset -= cur_src_piovec->len;
		cur_src_piovec++;
		if (unlikely(cur_src_piovec == src_piovec_max))
			return;
	}
	cur_src_len = cur_src_piovec->len - src_offset;
	cur_src_pages = cur_src_piovec->pages + ((cur_src_piovec->first_page_offset + src_offset) >> PAGE_SHIFT);
	cur_src_first_page_offset = (cur_src_piovec->first_page_offset + src_offset) & (~PAGE_MASK);

	while (1) {
		unsigned long chunk = min(cur_dst_len, cur_src_len);
		if (unlikely(chunk > length))
			chunk = length;

		knem_memcpy_pinned(cur_dst_pages, cur_dst_first_page_offset,
				   cur_src_pages, cur_src_first_page_offset,
				   chunk);
		length -= chunk;
		if (unlikely(!length))
			break;

		if (chunk == cur_src_len) {
			/* next src iovec */
			cur_src_piovec++;
			BUG_ON(cur_src_piovec == src_piovec_max);
			cur_src_pages = cur_src_piovec->pages;
			cur_src_first_page_offset = cur_src_piovec->first_page_offset;
			cur_src_len = cur_src_piovec->len;
		} else {
			/* advance in current src iovec */
			cur_src_pages += ((cur_src_first_page_offset + chunk) >> PAGE_SHIFT);
			cur_src_first_page_offset = (cur_src_first_page_offset + chunk) & (~PAGE_MASK);
			cur_src_len -= chunk;
		}

		if (chunk == cur_dst_len) {
			/* next dst iovec */
			cur_dst_piovec++;
			BUG_ON(cur_dst_piovec == dst_piovec_max);
			cur_dst_pages = cur_dst_piovec->pages;
			cur_dst_first_page_offset = cur_dst_piovec->first_page_offset;
			cur_dst_len = cur_dst_piovec->len;
		} else {
			/* advance in current dst iovec */
			cur_dst_pages += ((cur_dst_first_page_offset + chunk) >> PAGE_SHIFT);
			cur_dst_first_page_offset = (cur_dst_first_page_offset + chunk) & (~PAGE_MASK);
			cur_dst_len -= chunk;
		}
	}
}

static void
knem_do_work_memcpy_pinned(struct knem_context *ctx,
			   struct knem_work *work)
{
	struct knem_region *dst_region = work->dst_region;
	unsigned long dst_offset = work->dst_offset;
	const struct knem_region *src_region = work->src_region;
	unsigned long src_offset = work->src_offset;
	knem_status_t *status = work->status;

	BUG_ON(!work->length);

	if (likely(src_region->piovec_nr == 1 && dst_region->piovec_nr == 1)) {
		/* optimize the contigous case */
		const struct knem_pinned_iovec *src_piovec = &src_region->piovecs[0];
		const struct knem_pinned_iovec *dst_piovec = &dst_region->piovecs[0];
		struct page * const * src_pages = src_piovec->pages + ((src_piovec->first_page_offset + src_offset) >> PAGE_SHIFT);
		unsigned src_first_page_offset = (src_piovec->first_page_offset + src_offset) & (~PAGE_MASK);
		struct page * const * dst_pages = dst_piovec->pages + ((dst_piovec->first_page_offset + dst_offset) >> PAGE_SHIFT);
		unsigned dst_first_page_offset = (dst_piovec->first_page_offset + dst_offset) & (~PAGE_MASK);
		knem_memcpy_pinned(dst_pages, dst_first_page_offset,
				   src_pages, src_first_page_offset,
				   work->length);
	} else if (likely(src_region->piovec_nr > 0 && dst_region->piovec_nr > 0)) {
		/* generic vectorial case */
		knem_vectmemcpy_pinned(dst_region, dst_offset, src_region, src_offset, work->length);
	}

	*status = KNEM_STATUS_SUCCESS;

	if (unlikely(work->flags & KNEM_FLAG_NOTIFY_FD))
		knem_notify_fd_add(ctx, work->status_index);

	dst_region->dirty = 1;
}

/************************************
 * DMA-copying between pinned iovecs
 */

#ifdef KNEM_HAVE_DMA_ENGINE

static struct page *knem_dmacpy_status_src_page;
static unsigned int knem_dmacpy_status_src_success_page_offset;

static int
knem_dmacpy_init(void)
{
	knem_status_t *status_array;

	knem_dmacpy_status_src_page = alloc_page(GFP_KERNEL);
	if (!knem_dmacpy_status_src_page) {
		dprintk("Failed to allocate the dmacpy status page\n");
		return -ENOMEM;
	}

	status_array = (knem_status_t*)page_address(knem_dmacpy_status_src_page);
	status_array[0] = KNEM_STATUS_SUCCESS;
	knem_dmacpy_status_src_success_page_offset = 0;

	return 0;
}

static void
knem_dmacpy_exit(void)
{
	__free_page(knem_dmacpy_status_src_page);
}

static dma_cookie_t
knem_dmacpy_pinned(struct knem_context *ctx,
		   struct page * const * dst_page, unsigned dst_first_page_offset,
		   struct page * const * src_page, unsigned src_first_page_offset,
		   unsigned long remaining)
{
	struct dma_chan *chan  = ctx->dmacpy_chan;
	dma_cookie_t last_cookie = 0;
	int err;

	while (1) {
		unsigned long chunk = remaining;
		if (likely(src_first_page_offset + chunk > PAGE_SIZE))
			chunk = PAGE_SIZE - src_first_page_offset;
		if (likely(dst_first_page_offset + chunk > PAGE_SIZE))
			chunk = PAGE_SIZE - dst_first_page_offset;

		if (chunk <= knem_dma_chunk_min) {
			/* chunk is small, use a regular copy */
			void *src_addr = knem_kmap_atomic(*src_page, KM_USER0);
			void *dst_addr = knem_kmap_atomic(*dst_page, KM_USER1);
			memcpy(dst_addr + dst_first_page_offset,
			       src_addr + src_first_page_offset,
			       chunk);
			knem_kunmap_atomic(src_addr, KM_USER0);
			knem_kunmap_atomic(dst_addr, KM_USER1);
		} else {
			err = knem_dma_async_memcpy_pg_to_pg(chan,
							     *dst_page, dst_first_page_offset,
							     *src_page, src_first_page_offset,
							     chunk);
			if (err < 0)
				goto failure;
			last_cookie = err;
		}

		remaining -= chunk;
		if (unlikely(!remaining))
			break;

		if (chunk == PAGE_SIZE - src_first_page_offset) {
			src_page++;
			src_first_page_offset = 0;
		} else {
			src_first_page_offset += chunk;
		}

		if (chunk == PAGE_SIZE - dst_first_page_offset) {
			dst_page++;
			dst_first_page_offset = 0;
		} else {
			dst_first_page_offset += chunk;
		}
	}

	return last_cookie;

 failure:
	if (last_cookie) {
		/* complete pending DMA before returning the error */
		knem_dmacpy_partial_cleanup_until(ctx, last_cookie);
	}
	return err;
}

static int
knem_vectdmacpy_pinned(struct knem_context *ctx,
		       const struct knem_region *dst_region, unsigned long dst_offset,
		       const struct knem_region *src_region, unsigned long src_offset,
		       unsigned long length)
{
	const struct knem_pinned_iovec * cur_dst_piovec = &dst_region->piovecs[0];
	const struct knem_pinned_iovec * dst_piovec_max = cur_dst_piovec + dst_region->piovec_nr;
	struct page * const * cur_dst_pages;
	unsigned cur_dst_first_page_offset;
	unsigned long cur_dst_len;

	const struct knem_pinned_iovec * cur_src_piovec = &src_region->piovecs[0];
	const struct knem_pinned_iovec * src_piovec_max = cur_src_piovec + src_region->piovec_nr;
	struct page * const * cur_src_pages;
	unsigned cur_src_first_page_offset;
	unsigned long cur_src_len;

	dma_cookie_t last_cookie = 0;
	int err;

	while (dst_offset > cur_dst_piovec->len) {
		dst_offset -= cur_dst_piovec->len;
		cur_dst_piovec++;
		if (unlikely(cur_dst_piovec == dst_piovec_max))
			return 0;
	}
	cur_dst_len = cur_dst_piovec->len - dst_offset;
	cur_dst_pages = cur_dst_piovec->pages + ((cur_dst_piovec->first_page_offset + dst_offset) >> PAGE_SHIFT);
	cur_dst_first_page_offset = (cur_dst_piovec->first_page_offset + dst_offset) & (~PAGE_MASK);

	while (src_offset > cur_src_piovec->len) {
		src_offset -= cur_src_piovec->len;
		cur_src_piovec++;
		if (unlikely(cur_src_piovec == src_piovec_max))
			return 0;
	}
	cur_src_len = cur_src_piovec->len - src_offset;
	cur_src_pages = cur_src_piovec->pages + ((cur_src_piovec->first_page_offset + src_offset) >> PAGE_SHIFT);
	cur_src_first_page_offset = (cur_src_piovec->first_page_offset + src_offset) & (~PAGE_MASK);

	while (1) {
		unsigned long chunk = min(cur_dst_len, cur_src_len);
		if (unlikely(chunk > length))
			chunk = length;

		err = knem_dmacpy_pinned(ctx,
					 cur_dst_pages, cur_dst_first_page_offset,
					 cur_src_pages, cur_src_first_page_offset,
					 chunk);
		if (unlikely(err < 0))
			goto failure;
		last_cookie = err;

		length -= chunk;
		if (unlikely(!length))
			break;

		if (chunk == cur_src_len) {
			/* next src iovec */
			cur_src_piovec++;
			BUG_ON(cur_src_piovec == src_piovec_max);
			cur_src_pages = cur_src_piovec->pages;
			cur_src_first_page_offset = cur_src_piovec->first_page_offset;
			cur_src_len = cur_src_piovec->len;
		} else {
			/* advance in current src iovec */
			cur_src_pages += ((cur_src_first_page_offset + chunk) >> PAGE_SHIFT);
			cur_src_first_page_offset = (cur_src_first_page_offset + chunk) & (~PAGE_MASK);
			cur_src_len -= chunk;
		}

		if (chunk == cur_dst_len) {
			/* next dst iovec */
			cur_dst_piovec++;
			BUG_ON(cur_dst_piovec == dst_piovec_max);
			cur_dst_pages = cur_dst_piovec->pages;
			cur_dst_first_page_offset = cur_dst_piovec->first_page_offset;
			cur_dst_len = cur_dst_piovec->len;
		} else {
			/* advance in current dst iovec */
			cur_dst_pages += ((cur_dst_first_page_offset + chunk) >> PAGE_SHIFT);
			cur_dst_first_page_offset = (cur_dst_first_page_offset + chunk) & (~PAGE_MASK);
			cur_dst_len -= chunk;
		}
	}

	return last_cookie;

 failure:
	if (last_cookie) {
		/* complete pending DMA before returning the error */
		knem_dmacpy_partial_cleanup_until(ctx, last_cookie);
	}
	return err;
}

static int
knem_do_work_dmacpy_pinned(struct knem_context *ctx,
			   struct knem_work *work)
{
	struct knem_region *dst_region = work->dst_region;
	unsigned long dst_offset = work->dst_offset;
	const struct knem_region *src_region = work->src_region;
	unsigned long src_offset = work->src_offset;
	knem_status_t *status = work->status;
	struct dma_chan *chan  = ctx->dmacpy_chan;
	int ret = 0;
	int err = 0;

	BUG_ON(!work->length);

	if (likely(src_region->piovec_nr == 1 && dst_region->piovec_nr == 1)) {
		/* optimize the contigous case */
		const struct knem_pinned_iovec *src_piovec = &src_region->piovecs[0];
		const struct knem_pinned_iovec *dst_piovec = &dst_region->piovecs[0];
		struct page * const * src_pages = src_piovec->pages + ((src_piovec->first_page_offset + src_offset) >> PAGE_SHIFT);
		unsigned src_first_page_offset = (src_piovec->first_page_offset + src_offset) & (~PAGE_MASK);
		struct page * const * dst_pages = dst_piovec->pages + ((dst_piovec->first_page_offset + dst_offset) >> PAGE_SHIFT);
		unsigned dst_first_page_offset = (dst_piovec->first_page_offset + dst_offset) & (~PAGE_MASK);
		err = knem_dmacpy_pinned(ctx,
					 dst_pages, dst_first_page_offset,
					 src_pages, src_first_page_offset,
					 work->length);
	} else if (likely(src_region->piovec_nr > 0 && dst_region->piovec_nr > 0)) {
		/* generic vectorial case */
		err = knem_vectdmacpy_pinned(ctx, dst_region, dst_offset, src_region, src_offset, work->length);
	}

	if (unlikely(err < 0)) {
		/* got an error, all submitted copies have been waited for */
		dprintk("dmacpy failed (error %d)\n", -err);
		knem_counter_inc(FAILED_DMACPY);
		*status = KNEM_STATUS_FAILED;

		if (unlikely(work->flags & KNEM_FLAG_NOTIFY_FD))
			knem_notify_fd_add(ctx, work->status_index);

	} else if (unlikely(!err)) {
		/* no copy submitted, we are done */
		*status = KNEM_STATUS_SUCCESS;

		if (unlikely(work->flags & KNEM_FLAG_NOTIFY_FD))
			knem_notify_fd_add(ctx, work->status_index);

	} else {
		/* some copies were submitted */
		dma_cookie_t last_cookie = err;

		if (!(work->flags & KNEM_FLAG_ASYNCDMACOMPLETE)) {
			/* synchronous wait mode, wait for completion and set the status directly */
 sync:
			dma_async_issue_pending(chan);
			knem_dmacpy_partial_cleanup_until(ctx, last_cookie);
			*status = KNEM_STATUS_SUCCESS;

			if (unlikely(work->flags & KNEM_FLAG_NOTIFY_FD))
				knem_notify_fd_add(ctx, work->status_index);

		} else {
			/* asynchronous wait mode, queue the status update as well */
			unsigned long status_offset = work->status_index * sizeof(knem_status_t);
			struct page *status_page = ctx->status_pages[status_offset>>PAGE_SHIFT];
			unsigned status_page_offset = status_offset & ~PAGE_MASK;

			err = knem_dma_async_memcpy_pg_to_pg(chan,
							     status_page, status_page_offset,
							     knem_dmacpy_status_src_page, knem_dmacpy_status_src_success_page_offset,
							     sizeof(knem_status_t));
			if (err < 0)
				/* failed to queue the async status update, revert to sync */
				goto sync;

			dma_async_issue_pending(chan);
			work->dmacpy.last_cookie = err;
			ret = 1; /* tell the caller to queue for deferred cleanup */
		}
	}

	dst_region->dirty = 1;

	return ret;
}

static void
knem_dmacpy_partial_cleanup(struct knem_context *ctx)
{
	struct knem_work *work;

	spin_lock(&ctx->dmacpy_cleanup_work_lock);
	if (!list_empty(&ctx->dmacpy_cleanup_work_list)) {
		dma_cookie_t done, used;

		/* see if the first work is done */
		work = list_entry(ctx->dmacpy_cleanup_work_list.next, struct knem_work, list_elt);
		if (dma_async_is_tx_complete(ctx->dmacpy_chan, work->dmacpy.last_cookie, &done, &used) != DMA_IN_PROGRESS) {
			/* cleanup this first work */
			list_del(&work->list_elt);
			spin_unlock(&ctx->dmacpy_cleanup_work_lock);
			knem_free_work(work);
			spin_lock(&ctx->dmacpy_cleanup_work_lock);

			/* see if the next works are in the same done-used interval */
			while (!list_empty(&ctx->dmacpy_cleanup_work_list)) {
				work = list_entry(ctx->dmacpy_cleanup_work_list.next, struct knem_work, list_elt);
				if (dma_async_is_complete(work->dmacpy.last_cookie, done, used) == DMA_IN_PROGRESS) {
					/* some work isn't done yet, reschedule the timer and return */
					mod_timer(&ctx->dmacpy_cleanup_timer,
						  get_jiffies_64() + KNEM_DMACPY_CLEANUP_TIMEOUT);
					spin_unlock(&ctx->dmacpy_cleanup_work_lock);
					return;
				}

				list_del(&work->list_elt);
				spin_unlock(&ctx->dmacpy_cleanup_work_lock);
				knem_free_work(work);
				spin_lock(&ctx->dmacpy_cleanup_work_lock);
			}
			/* we cleaned up all pending works, delete the timer (could have been rescheduled by a copy ioctl) */
			del_timer(&ctx->dmacpy_cleanup_timer);
		}
	}
	spin_unlock(&ctx->dmacpy_cleanup_work_lock);
}

static void
knem_dmacpy_partial_cleanup_until(struct knem_context *ctx, dma_cookie_t cookie)
{
	struct knem_work *work;
	enum dma_status status = DMA_IN_PROGRESS;

	while (status == DMA_IN_PROGRESS) {
		dma_cookie_t done, used;

		status = dma_async_is_tx_complete(ctx->dmacpy_chan, cookie, &done, &used);

		spin_lock(&ctx->dmacpy_cleanup_work_lock);
		/* complete first works if they are in the this done-used interval */
		while (!list_empty(&ctx->dmacpy_cleanup_work_list)) {
			work = list_entry(ctx->dmacpy_cleanup_work_list.next, struct knem_work, list_elt);
			if (dma_async_is_complete(work->dmacpy.last_cookie, done, used) == DMA_IN_PROGRESS
			    && status == DMA_COMPLETE) {
				/* our cookie is done but some work isn't yet, reschedule the timer and return */
				mod_timer(&ctx->dmacpy_cleanup_timer,
					  get_jiffies_64() + KNEM_DMACPY_CLEANUP_TIMEOUT);
				spin_unlock(&ctx->dmacpy_cleanup_work_lock);
				return;
			}

			list_del(&work->list_elt);
			spin_unlock(&ctx->dmacpy_cleanup_work_lock);
			knem_free_work(work);
			spin_lock(&ctx->dmacpy_cleanup_work_lock);
		}
		/* we cleaned up all pending works, delete the timer (could have been rescheduled by a copy ioctl) */
		del_timer(&ctx->dmacpy_cleanup_timer);

		/* release the lock a bit */
		spin_unlock(&ctx->dmacpy_cleanup_work_lock);
	}
}

static void
knem_dmacpy_full_cleanup(struct knem_context *ctx)
{
	struct knem_work *work;

	/* kthread and apps are gone, no need to lock the work list */
	if (!list_empty(&ctx->dmacpy_cleanup_work_list)) {
		dma_cookie_t done, used;

		/* wait until the last work is done */
		work = list_entry(ctx->dmacpy_cleanup_work_list.prev, struct knem_work, list_elt);
		while (dma_async_is_tx_complete(ctx->dmacpy_chan, work->dmacpy.last_cookie, &done, &used) == DMA_IN_PROGRESS)
			cpu_relax();

		/* cleanup all works now */
		while (!list_empty(&ctx->dmacpy_cleanup_work_list)) {
			work = list_entry(ctx->dmacpy_cleanup_work_list.next, struct knem_work, list_elt);
			list_del(&work->list_elt);
			knem_free_work(work);
		}
	}
}

#else /* KNEM_HAVE_DMA_ENGINE */

static inline int knem_dmacpy_init(void) { return 0; }
static inline void knem_dmacpy_exit(void) { /* do nothing */ }

#endif /* !KNEM_HAVE_DMA_ENGINE */

/******************************
 * Common routines for copying
 */

static inline void
knem_submit_work(struct knem_context *ctx, struct knem_work *work,
		 int offload, int async,
		 knem_status_t *current_status, knem_status_t *final_status)
{
	/* actually perform or offload the work */
	if (offload) {
		/* offload the work in the kthread and let it work and free everything */
		spin_lock(&ctx->kthread_work_lock);
		list_add_tail(&work->list_elt, &ctx->kthread_work_list);
		spin_unlock(&ctx->kthread_work_lock);
		wake_up(&ctx->kthread_work_wq);
		knem_counter_inc(PROCESSED_THREAD);
		*current_status = KNEM_STATUS_PENDING;

	} else {
		/* synchronous work, and free everything */
		knem_do_work(ctx, work);
		/* the work already filled the final status */
		if (async) {
			/* asynchronous request was performed synchronously,
			 * current_status is the final status
			 */
			*current_status = *final_status;
		} else {
#ifdef KNEM_DRIVER_DEBUG
			BUG_ON(current_status != final_status);
#endif
		}
	}
}

static int
knem_copy(struct knem_context * ctx,
	  knem_cookie_t src_cookie, unsigned long src_offset,
	  knem_cookie_t dst_cookie, unsigned long dst_offset,
	  unsigned long length,
	  unsigned int flags,
	  knem_status_t *current_status,
	  u32 async_status_index /* only valid if some async flag was given set */)
{
	struct knem_work *work;
	struct knem_region *src_region, *dst_region;
	knem_status_t *final_status = NULL;
	int offload = flags & KNEM_FLAG_MEMCPYTHREAD;
	int async = flags & KNEM_FLAG_ANY_ASYNC_MASK;
	int pollevent = flags & KNEM_FLAG_NOTIFY_FD;
	int err;

	final_status = async ? &ctx->status_array[async_status_index] : current_status;
#ifdef KNEM_DRIVER_DEBUG
	BUG_ON(!current_status);
	BUG_ON(!final_status);
#endif

	knem_counter_inc(SUBMITTED);

#ifdef KNEM_HAVE_DMA_ENGINE
	/* if DMA is not supported, the application shouldn't request it */
	if (!ctx->dmacpy_chan && (flags & KNEM_FLAG_DMA)) {
		dprintk("DMA not supported\n");
		knem_counter_inc(REJECTED_INVALIDFLAGS);
		err = -EINVAL;
		goto out;
	}
#endif

	if (unlikely(pollevent)) {
		spin_lock(&ctx->notify_fd_lock);
		if (ctx->notify_fd_pending + ctx->notify_fd_to_read == ctx->status_index_max) {
			/* always keep an empty slot between write and read */
			spin_unlock(&ctx->notify_fd_lock);
			err = -EBUSY;
			goto out;
		}
		ctx->notify_fd_pending++;
		spin_unlock(&ctx->notify_fd_lock);
	}

	work = kmalloc(sizeof(*work), GFP_KERNEL);
	if (unlikely(!work)) {
		dprintk("Failed to allocate copy work\n");
		knem_counter_inc(REJECTED_NOMEM);
		err = -ENOMEM;
		goto out_with_pollevent;
	}

	src_region = knem_find_region(src_cookie, 0);
	if (IS_ERR(src_region)) {
		knem_counter_inc(REJECTED_FINDREGION);
		err = PTR_ERR(src_region);
		goto out_with_work;
	}
	dst_region = knem_find_region(dst_cookie, 1);
	if (IS_ERR(dst_region)) {
		knem_counter_inc(REJECTED_FINDREGION);
		err = PTR_ERR(dst_region);
		goto out_with_src_region;
	}

	/* now we know that the request is valid, it will be processed (and may fail for other reasons later during the copy) */
	knem_counter_inc(PROCESSED);

	*final_status = KNEM_STATUS_PENDING;

	work->flags = flags;
	work->local_region = NULL; /* no local region is attached to this work */
	if (unlikely(src_offset >= src_region->length || dst_offset >= dst_region->length))
		work->length = 0;
	else
		work->length = min(src_region->length - src_offset, dst_region->length - dst_offset);
	if (work->length > length)
		work->length = length;
	work->dst_region = dst_region;
	work->dst_offset = dst_offset;
	work->src_region = src_region;
	work->src_offset = src_offset;
	work->status = final_status;
	work->status_index = async_status_index; /* ignored in sync mode */

	/* prepare the work depending on its type (pinning, ...) */
#ifdef KNEM_HAVE_DMA_ENGINE
	if (flags & KNEM_FLAG_DMA) {
		/* use DMA engine for copying */
		work->type = KNEM_WORK_DMACPY;
		offload = flags & KNEM_FLAG_DMATHREAD;

		knem_counter_inc(PROCESSED_DMA);
	} else
#endif
	{
		/* fallback to pinned copy */
		work->type = KNEM_WORK_MEMCPY_PINNED;
	}

	if (likely(work->length)) {
		knem_submit_work(ctx, work, offload, async, current_status, final_status);
	} else {
		knem_free_work(work);
		*final_status = KNEM_STATUS_SUCCESS;
	}

	err = 0;
out:
#ifdef KNEM_HAVE_DMA_ENGINE
	/*
	 * Cleanup a bit of completed dmacpy,
	 * and (more important) schedule the timer to defer the cleanup if needed
	 */
	if (ctx->dmacpy_chan)
		knem_dmacpy_partial_cleanup(ctx);
#endif
	return err;

 out_with_src_region:
	knem_put_region(src_region);
 out_with_work:
	kfree(work);
 out_with_pollevent:
	if (unlikely(pollevent)) {
		spin_lock(&ctx->notify_fd_lock);
		ctx->notify_fd_pending--;
		spin_unlock(&ctx->notify_fd_lock);
	}

	goto out;
}

static int
knem_inline_copy(struct knem_context * ctx,
		 const void __user * uiovec_array, unsigned long uiovec_nr,
		 knem_cookie_t remote_cookie, unsigned long remote_offset,
		 unsigned long length,
		 unsigned int flags, int write,
		 knem_status_t *current_status,
		 u32 async_status_index /* only valid if some async flag was given set */)
{
	struct knem_work *work;
	struct knem_region * local_region;
	struct knem_region * remote_region;
	knem_status_t *final_status = NULL;
	int offload = flags & KNEM_FLAG_MEMCPYTHREAD;
	int pinlocal = flags & KNEM_FLAG_PINLOCAL;
	int async = flags & KNEM_FLAG_ANY_ASYNC_MASK;
	int pollevent = flags & KNEM_FLAG_NOTIFY_FD;
	unsigned long i;
	int err;

	final_status = async ? &ctx->status_array[async_status_index] : current_status;
#ifdef KNEM_DRIVER_DEBUG
	BUG_ON(!current_status);
	BUG_ON(!final_status);
#endif

	knem_counter_inc(SUBMITTED);

#ifdef KNEM_HAVE_DMA_ENGINE
	/* if DMA is not supported, the application shouldn't request it */
	if (!ctx->dmacpy_chan && (flags & KNEM_FLAG_DMA)) {
		dprintk("DMA not supported\n");
		knem_counter_inc(REJECTED_INVALIDFLAGS);
		err = -EINVAL;
		goto out;
	}
#endif

	if (unlikely(pollevent)) {
		spin_lock(&ctx->notify_fd_lock);
		if (ctx->notify_fd_pending + ctx->notify_fd_to_read == ctx->status_index_max) {
			/* always keep an empty slot between write and read */
			spin_unlock(&ctx->notify_fd_lock);
			err = -EBUSY;
			goto out;
		}
		ctx->notify_fd_pending++;
		spin_unlock(&ctx->notify_fd_lock);
	}

	work = kmalloc(sizeof(*work) + sizeof(*local_region)
			+ uiovec_nr * sizeof(struct knem_pinned_iovec)
			+ uiovec_nr * sizeof(struct knem_cmd_param_iovec),
			GFP_KERNEL);
	if (unlikely(!work)) {
		dprintk("Failed to allocate an inline work\n");
		knem_counter_inc(REJECTED_NOMEM);
		err = -ENOMEM;
		goto out_with_pollevent;
	}
	local_region = (void *) (work + 1);
	local_region->piovecs = (void *) (local_region + 1); /* piovecs stored right after the region */
	local_region->piovec_nr = 0; /* nothing pinned yet */
	local_region->uiovecs = (void *) (local_region->piovecs + uiovec_nr); /* uiovecs stored after piovecs */
	local_region->uiovec_nr = uiovec_nr; /* will be filled below */

	err = copy_from_user(local_region->uiovecs, uiovec_array,
			     uiovec_nr * sizeof(struct knem_cmd_param_iovec));
	if (unlikely(err)) {
		dprintk("Failed to read inline copy ioctl iovecs from user-space\n");
		knem_counter_inc(REJECTED_READCMD);
		err = -EFAULT;
		goto out_with_work;
	}

	local_region->length = 0;
	for(i=0; i<uiovec_nr; i++)
		local_region->length += local_region->uiovecs[i].len;
	local_region->dirty = 0;
	local_region->protection = write ? PROT_READ : PROT_WRITE;

	remote_region = knem_find_region(remote_cookie, write);
	if (IS_ERR(remote_region)) {
		knem_counter_inc(REJECTED_FINDREGION);
		err = PTR_ERR(remote_region);
		goto out_with_piovecs;
	}

	/* now we know that the request is valid, it will be processed (and may fail for other reasons later during the copy) */
	knem_counter_inc(PROCESSED);

	*final_status = KNEM_STATUS_PENDING;

	work->flags = flags;
	if (write) {
		work->dst_region = remote_region;
		work->dst_offset = remote_offset;
		work->src_region = local_region;
		work->src_offset = 0;
	} else {
		work->src_region = remote_region;
		work->src_offset = remote_offset;
		work->dst_region = local_region;
		work->dst_offset = 0;
	}
	work->local_region = local_region; /* no need to free this region, it's allocated with the work, only need to unpin it */
	if (unlikely(remote_offset >= remote_region->length))
		work->length = 0;
	else
		work->length = min(local_region->length, remote_region->length - remote_offset);
	if (work->length > length)
		work->length = length;
	work->status = final_status;
	work->status_index = async_status_index; /* ignored in sync mode */

	/* memcpy_from_user seems slow, so disable it unless really forced */
	if (write && knem__pinlocalread)
		pinlocal = 1;

	/* prepare the work depending on its type (pinning, ...) */
#ifdef KNEM_HAVE_DMA_ENGINE
	if (flags & KNEM_FLAG_DMA) {
		/* use DMA engine for copying */
		work->type = KNEM_WORK_DMACPY;
		offload = flags & KNEM_FLAG_DMATHREAD;

		/* need to pin on the local side first */
		err = knem_pin_region(local_region, !write);
		if (unlikely(err < 0)) {
			knem_counter_inc(REJECTED_PIN);
			goto out_with_remote_region;
		}

		knem_counter_inc(PROCESSED_DMA);
		knem_counter_inc(PROCESSED_PINLOCAL);
	} else
#endif
	if (!offload && !pinlocal) {
		/* if not offloading, we can memcpy to user-space without pinning on the local side */
		work->type = write ? KNEM_WORK_MEMCPY_FROM_USER : KNEM_WORK_MEMCPY_TO_USER;

		/* no need to pin */

	} else {
		/* fallback to pinned copy */
		work->type = KNEM_WORK_MEMCPY_PINNED;

		/* need to pin on the local side first */
		err = knem_pin_region(local_region, !write);
		if (unlikely(err < 0)) {
			knem_counter_inc(REJECTED_PIN);
			goto out_with_remote_region;
		}

		knem_counter_inc(PROCESSED_PINLOCAL);
	}

	if (offload) {
		/* uiovecs are not accessible anymore once offloaded */
		local_region->uiovecs = NULL;
		local_region->uiovec_nr = 0;
	}

	if (likely(work->length)) {
		knem_submit_work(ctx, work, offload, async, current_status, final_status);
	} else {
		knem_free_work(work);
		*final_status = KNEM_STATUS_SUCCESS;
	}

	err = 0;
out:
#ifdef KNEM_HAVE_DMA_ENGINE
	/*
	 * Cleanup a bit of completed dmacpy,
	 * and (more important) schedule the timer to defer the cleanup if needed
	 */
	if (ctx->dmacpy_chan)
		knem_dmacpy_partial_cleanup(ctx);
#endif
	return err;

 out_with_remote_region:
	knem_put_region(remote_region);
 out_with_piovecs:
	knem_unpin_region(local_region);
 out_with_work:
	kfree(work);
 out_with_pollevent:
	if (unlikely(pollevent)) {
		spin_lock(&ctx->notify_fd_lock);
		ctx->notify_fd_pending--;
		spin_unlock(&ctx->notify_fd_lock);
	}

	goto out;
}

/**********
 * Regions
 */

static int
knem_create_region(struct knem_context * ctx,
		   const void __user * uiovec_array, unsigned long uiovec_nr,
		   unsigned int flags, unsigned protection,
		   knem_cookie_t *cookie)
{
	struct knem_region *region;
	unsigned long cookie_flags;
	unsigned long i;
	int err;

	region = kmalloc(sizeof(*region)
		      + uiovec_nr * sizeof(struct knem_pinned_iovec)
		      + uiovec_nr * sizeof(struct knem_cmd_param_iovec), GFP_KERNEL);
	if (unlikely(!region)) {
		dprintk("Failed to allocate region\n");
		err = -ENOMEM;
		goto out;
	}
	region->single_use = (flags & KNEM_FLAG_SINGLEUSE) != 0 /* single_use is a single bit field */;
	region->any_user = (flags & KNEM_FLAG_ANY_USER_ACCESS) != 0 /* any_user is a single bit field */;
	region->dirty = 0;
	region->protection = protection;

	region->piovecs = (void *) (region + 1); /* piovecs stored right after the region */
	region->piovec_nr = 0; /* nothing pinned yet */
	region->uiovecs = (void *) (region->piovecs + uiovec_nr); /* uiovecs stored after piovecs */
	region->uiovec_nr = uiovec_nr; /* will be filled below */

	err = copy_from_user(region->uiovecs, uiovec_array,
			     uiovec_nr * sizeof(struct knem_cmd_param_iovec));
	if (unlikely(err)) {
		dprintk("Failed to read create region ioctl iovecs from user-space\n");
		err = -EFAULT;
		goto out_with_region;
	}

	region->length = 0;
	for(i=0; i<uiovec_nr; i++)
		region->length += region->uiovecs[i].len;

	err = knem_pin_region(region, protection & PROT_WRITE);
	if (unlikely(err < 0))
		goto out_with_region;

	kref_init(&region->refcount);
	/* uiovecs are not accessible anymore once queued */
	region->uiovecs = NULL;
	region->uiovec_nr = 0;

	err = knem_insert_ctx_region(ctx, region);
	if (unlikely(err < 0))
		goto out_with_region;

	cookie_flags = flags & KNEM_FLAG_SINGLEUSE ? KNEM_COOKIE_FLAG_SINGLEUSE : 0;
	*cookie = KNEM_BUILD_COOKIE(ctx, region, cookie_flags);

	return 0;

 out_with_region:
	knem_free_region(region);
 out:
	return err;
}

static int
knem_destroy_region(struct knem_context * ctx,
		    knem_cookie_t cookie)
{
	struct knem_region *region;
	int err = 0;

	/* dequeue the region so that no new users may arrive */
	region = knem_dequeue_local_region(ctx, cookie);
	if (IS_ERR(region)) {
		err = PTR_ERR(region);
		goto out;
	}
	/* we got the reference on the region that the htbl previously hold */

	/* cleanup things once current users are gone */
	call_rcu(&region->destroy_rcu_head, knem_put_region_rcu);

out:
	return err;
}

/******************
 * Common routines
 */

static void
knem_free_work(struct knem_work *work)
{
	if (work->src_region == work->local_region)
		/* allocated within the work, just unpin it */
		knem_unpin_region(work->src_region);
	else
		/* generic region, just release it */
		knem_put_region(work->src_region);

	if (work->dst_region == work->local_region)
		/* allocated within the work, just unpin it */
		knem_unpin_region(work->dst_region);
	else
		/* generic region, just release it */
		knem_put_region(work->dst_region);

	kfree(work);
}

static void
knem_do_work(struct knem_context *ctx, struct knem_work *work)
{
	switch (work->type) {

	case KNEM_WORK_MEMCPY_PINNED: {
		knem_do_work_memcpy_pinned(ctx, work);
		knem_free_work(work);
		break;
	}

	case KNEM_WORK_MEMCPY_TO_USER: {
		knem_do_work_memcpy_to_user(ctx, work);
		knem_free_work(work);
		break;
	}

	case KNEM_WORK_MEMCPY_FROM_USER: {
		knem_do_work_memcpy_from_user(ctx, work);
		knem_free_work(work);
		break;
	}

#ifdef KNEM_HAVE_DMA_ENGINE
	case KNEM_WORK_DMACPY: {
		int ret = knem_do_work_dmacpy_pinned(ctx, work);
		if (ret) {
			/* the copy was offloaded, we'll cleanup later */
			spin_lock(&ctx->dmacpy_cleanup_work_lock);
			list_add_tail(&work->list_elt, &ctx->dmacpy_cleanup_work_list);
			spin_unlock(&ctx->dmacpy_cleanup_work_lock);
		} else {
			knem_free_work(work);
		}
		break;
	}
#endif /* KNEM_HAVE_DMA_ENGINE */

	default:
		BUG();
	}
}

/******************
 * Kthread routine
 */

static int
knem_kthread_func(void *data)
{
	struct knem_context *ctx = data;
	DECLARE_WAITQUEUE(wait, current);
	int err;

	if (unlikely(knem_debug)) {
		int cpus_strlen = DIV_ROUND_UP(NR_CPUS, 32) * 9;
		char * cpus_str = kmalloc(cpus_strlen, GFP_KERNEL);
		if (cpus_str) {
			knem_cpumask_scnprintf(cpus_str, cpus_strlen, &ctx->kthread_cpumask);
			dprintk("Starting kthread for context %08x, with cpumask %s\n",
				(unsigned) ctx->id, cpus_str);
			kfree(cpus_str);
		}
	}

	/* bind the thread */
	err = knem_set_cpus_allowed_ptr(current, &ctx->kthread_cpumask);
	if (err < 0)
		dprintk("Failed to bind kthread\n");

	set_current_state(TASK_INTERRUPTIBLE);
	while(!kthread_should_stop()) {
		struct knem_work *work;

		add_wait_queue(&ctx->kthread_work_wq, &wait);

		spin_lock(&ctx->kthread_work_lock);
		if (list_empty(&ctx->kthread_work_list)) {
			spin_unlock(&ctx->kthread_work_lock);
			schedule();
			spin_lock(&ctx->kthread_work_lock);
		} else {
			__set_current_state(TASK_RUNNING);
		}

		while (!list_empty(&ctx->kthread_work_list)) {
			work = list_entry(ctx->kthread_work_list.next, struct knem_work, list_elt);
			list_del(&work->list_elt);
			spin_unlock(&ctx->kthread_work_lock);
			knem_do_work(ctx, work);
			spin_lock(&ctx->kthread_work_lock);
		}
		spin_unlock(&ctx->kthread_work_lock);

#ifdef KNEM_HAVE_DMA_ENGINE
		if (ctx->dmacpy_chan)
			knem_dmacpy_partial_cleanup(ctx);
#endif

		remove_wait_queue(&ctx->kthread_work_wq, &wait);
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);

	dprintk("Stopping kthread for context %08x\n",
		(unsigned) ctx->id);
	return 0;
}

#ifdef KNEM_HAVE_DMA_ENGINE
static void
#ifdef HAVE_TIMER_SETUP
knem_dmacpy_cleanup_timer_handler(struct timer_list *t)
#else
knem_dmacpy_cleanup_timer_handler(unsigned long data)
#endif
{
#ifdef HAVE_TIMER_SETUP
	struct knem_context * ctx = from_timer(ctx, t, dmacpy_cleanup_timer);
#else
	struct knem_context * ctx = (void *) data;
#endif

	wake_up(&ctx->kthread_work_wq);
	knem_counter_inc(DMACPY_CLEANUP_TIMEOUT);
}
#endif

/******************
 * File operations
 */

static int
knem_miscdev_open(struct inode * inode, struct file * file)
{
	struct knem_context * ctx;
	int err = 0;

	/* readers do not get a knem context */
	if (!(file->f_mode & FMODE_WRITE)) {
		file->private_data = NULL;
		return 0;
	}

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}
	file->private_data = ctx;
	/* initialize the context */
	ctx->status_array_state = KNEM_STATUS_ARRAY_UNUSED;
	ctx->status_array = NULL;
	ctx->status_index_max = 0;
	ctx->kthread_task = NULL;
	ctx->ignore_flags = knem_ignore_flags;
	ctx->force_flags = knem_force_flags;
	ctx->uid = current_uid();

	knem_ctx_regions_init(ctx);

	INIT_LIST_HEAD(&ctx->kthread_work_list);
	spin_lock_init(&ctx->kthread_work_lock);
	init_waitqueue_head(&ctx->kthread_work_wq);
	/* setup the kthread cpumask to anywhere for now */
	ctx->kthread_cpumask_enforced = 0;
	knem_cpumask_setall(&ctx->kthread_cpumask);

#ifdef KNEM_HAVE_DMA_ENGINE
	/* try to get a dma chan */
	ctx->dmacpy_chan = knem_get_dma_channel();
	if (ctx->dmacpy_chan) {
		INIT_LIST_HEAD(&ctx->dmacpy_cleanup_work_list);
		spin_lock_init(&ctx->dmacpy_cleanup_work_lock);
#ifdef HAVE_TIMER_SETUP
		timer_setup(&ctx->dmacpy_cleanup_timer, knem_dmacpy_cleanup_timer_handler, 0);
#else
		setup_timer(&ctx->dmacpy_cleanup_timer, knem_dmacpy_cleanup_timer_handler, (unsigned long) ctx);
#endif
#if (defined CONFIG_NUMA) && (defined KNEM_HAVE_CPUMASK_OF_NODE)
		{
			int node = dev_to_node(ctx->dmacpy_chan->device->dev);
			int cpu = smp_processor_id();
			if (node != -1 && !cpumask_test_cpu(smp_processor_id(), cpumask_of_node(node)))
				knem_printk_once("knem: got remote chan %s (close to node %d) from processor %d\n",
						 dma_chan_name(ctx->dmacpy_chan), node, cpu);
		}
#endif
	}
#endif

	err = knem_assign_context_id(ctx);
	if (err < 0)
		goto out_with_ctx;

	dprintk("Initialized context %08x, forcing flags 0x%x, ignoring 0x%x, masking region with %08x\n",
		(unsigned) ctx->id, ctx->force_flags, ctx->ignore_flags, (unsigned) ctx->region_id_magic);
	return 0;

 out_with_ctx:
#ifdef KNEM_HAVE_DMA_ENGINE
	if (ctx->dmacpy_chan) {
		del_timer_sync(&ctx->dmacpy_cleanup_timer);
		knem_put_dma_channel(ctx->dmacpy_chan);
	}
#endif
	knem_ctx_regions_destroy(ctx);
	kfree(ctx);
 out:
	return err;
}

/*
 * This work is scheduled after a RCU grace period after the context is made unaccessible to new users.
 * It does the actual destroying of a context.
 * It may sleep when vfree'ing stuff.
 */
static void
knem_ctx_destroy_work(knem_work_struct_data_t data)
{
	struct knem_context *ctx = KNEM_WORK_STRUCT_DATA(data, struct knem_context, destroy_work);
	struct knem_work * work, * nwork;
	knem_context_id_t ctx_id = ctx->id;
	int i;

	/* release remaining regions and destroy the corresponding structures */
	i = knem_ctx_regions_destroy(ctx);
	if (i)
		dprintk("Destroyed %d regions while releasing context %08x\n",
			i, (unsigned) ctx_id);

	/* stop the kthread */
	if (ctx->kthread_task)
		kthread_stop(ctx->kthread_task);

	/* kthread is gone, no need to lock the work list */
	i=0;
	list_for_each_entry_safe(work, nwork, &ctx->kthread_work_list, list_elt) {
		list_del(&work->list_elt);
		knem_free_work(work);
		i++;
	}
	if (i)
		dprintk("Destroyed %d works while releasing context %08x\n",
			i, (unsigned) ctx_id);

#ifdef KNEM_HAVE_DMA_ENGINE
	if (ctx->dmacpy_chan) {
		del_timer_sync(&ctx->dmacpy_cleanup_timer);
		/* cleanup the pending work. don't check whether we got a dma_chan
		 * since the work list has been properly initialized
		 */
		knem_dmacpy_full_cleanup(ctx);
		/* release the channel now that all works are done */
		knem_put_dma_channel(ctx->dmacpy_chan);
	}
#endif

	/* free everything */
	if (ctx->status_array_state != KNEM_STATUS_ARRAY_UNUSED) {
		BUG_ON(ctx->status_array_state != KNEM_STATUS_ARRAY_READY);
		BUG_ON(!ctx->status_array);
		vfree(ctx->status_array);
		kfree(ctx->status_pages);
		vfree(ctx->notify_fd_array);
	}
	kfree(ctx);

	dprintk("Asynchronously destroyed context %08x\n", (unsigned) ctx_id);
}

/*
 * Called after a RCU grace period after the context is made unaccessible to new users.
 * Takes care of scheduling a work to actually destroy the context since
 * we cannot vfree in RCU callback context.
 */
static void
knem_ctx_destroy_rcu(struct rcu_head *rcu_head)
{
	struct knem_context *ctx = container_of(rcu_head, struct knem_context, destroy_rcu_head);
	KNEM_INIT_WORK(&ctx->destroy_work, knem_ctx_destroy_work, ctx);
	schedule_work(&ctx->destroy_work);
}

static int
knem_miscdev_release(struct inode * inode, struct file * file)
{
	struct knem_context * ctx = file->private_data;
	knem_context_id_t ctx_id;

	if (!ctx)
		/* nothing to do */
		return 0;

	ctx_id = ctx->id;
	file->private_data = NULL;

	/* make the context unavailable to other processes */
	knem_release_context_id(ctx);

	/* no new users may acquire the context now */

	/* cleanup things once current users are gone */
	call_rcu(&ctx->destroy_rcu_head, knem_ctx_destroy_rcu);

	dprintk("Scheduled destroying of context %08x\n", (unsigned) ctx_id);
	return 0;
}

static long
knem_miscdev_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct knem_context * ctx = file->private_data;
	int err;

	if (!ctx)
		/* ioctl are not available in reader mode, we need a knem context */
		return -EBADF;

	switch (cmd) {

	case KNEM_CMD_GET_INFO: {
		struct knem_cmd_info info;

		info.abi = KNEM_ABI_VERSION;
		info.features = 0
#ifdef KNEM_HAVE_DMA_ENGINE
				| (knem__dmacpy && ctx->dmacpy_chan ? KNEM_FEATURE_DMA : 0)
#endif
				;
		info.forced_flags = knem_force_flags;
		info.ignored_flags = knem_ignore_flags;
		err = copy_to_user((void __user *) arg, &info,
				   sizeof(info));
		if (unlikely(err)) {
			dprintk("Failed to write get_info ioctl user-space param\n");
			err = -EFAULT;
		}
		break;
	}

	case KNEM_CMD_BIND_OFFLOAD: {
		struct knem_cmd_bind_offload bind_offload;

		err = copy_from_user(&bind_offload, (void __user *) arg, sizeof(bind_offload));
		if (unlikely(err)) {
			dprintk("Failed to read bind-offload ioctl user-space param\n");
			err = -EFAULT;
			goto out;
		}

		if (ctx->status_array_state != KNEM_STATUS_ARRAY_UNUSED) {
			dprintk("Cannot bind offload after kthread startup\n");
			err = -EBUSY;
			goto out;
		}

		switch (bind_offload.flags) {
		case KNEM_BIND_FLAG_CUSTOM:
			if (bind_offload.mask_len < sizeof(cpumask_t)) {
				memset(&ctx->kthread_cpumask, 0, sizeof(cpumask_t));
			} else if (bind_offload.mask_len > sizeof(cpumask_t)) {
				bind_offload.mask_len = sizeof(cpumask_t);
			}
			err = copy_from_user(&ctx->kthread_cpumask, (void __user *)(unsigned long) bind_offload.mask_ptr, bind_offload.mask_len);
			if (unlikely(err)) {
				dprintk("Failed to read bind-offload mask from ioctl user-space param\n");
				err = -EFAULT;
				goto out;
			}
			ctx->kthread_cpumask_enforced = 1;
			break;
		case KNEM_BIND_FLAG_CURRENT:
			ctx->kthread_cpumask = knem_get_cpus_allowed(current);
			ctx->kthread_cpumask_enforced = 1;
			break;
		case KNEM_BIND_FLAG_CURRENT_REVERSED:
			knem_cpumask_complement(&ctx->kthread_cpumask, &knem_get_cpus_allowed(current));
			ctx->kthread_cpumask_enforced = 1;
			break;
		default:
			dprintk("Unknown bind flags %ld\n", (unsigned long) bind_offload.flags);
			err = -EINVAL;
			goto out;
		}

		break;
	}

	case KNEM_CMD_CREATE_REGION: {
		struct knem_cmd_create_region region_param;
		unsigned int flags;

		err = copy_from_user(&region_param, (void __user *) arg, sizeof(region_param));
		if (unlikely(err)) {
			dprintk("Failed to read create_region ioctl user-space param\n");
			err = -EFAULT;
			goto out;
		}

		/* update flags with ignored/forced ones */
		flags = KNEM_FIX_CREATE_FLAGS(ctx, region_param.flags);

		err = knem_create_region(ctx,
					 (void __user *)(unsigned long) region_param.iovec_array,
					 region_param.iovec_nr,
					 flags, region_param.protection,
					 &region_param.cookie);
		if (likely(!err)) {
			err = copy_to_user((void __user *) arg, &region_param, sizeof(region_param));
			BUG_ON(err); /* copy_from_user worked, so this one can't fail */
		}

		break;
	}

	case KNEM_CMD_DESTROY_REGION: {
		knem_cookie_t cookie;

		err = copy_from_user(&cookie, (void __user *) arg, sizeof(cookie));
		if (unlikely(err)) {
			dprintk("Failed to read destroy_region ioctl user-space param\n");
			err = -EFAULT;
			goto out;
		}

		err = knem_destroy_region(ctx, cookie);
		break;
	}

	case KNEM_CMD_COPY_BOUNDED: {
		struct knem_cmd_copy_bounded copy_param;
		knem_status_t current_status = KNEM_STATUS_PENDING;
		unsigned int flags;

		err = copy_from_user(&copy_param, (void __user *) arg, sizeof(copy_param));
		if (unlikely(err)) {
			dprintk("Failed to read copy bounded ioctl user-space param\n");
			err = -EFAULT;
			goto out;
		}

		/* update flags with ignored/forced ones */
		flags = KNEM_FIX_COPY_FLAGS(ctx, copy_param.flags);

		if (flags & KNEM_FLAG_ANY_ASYNC_MASK) {
			if (unlikely(ctx->status_array_state != KNEM_STATUS_ARRAY_READY)) {
				/* not mapped yet */
				dprintk("Cannot post a bounded copy without a mapped status array\n");
				err = -EINVAL;
				goto out;
			}
			if (unlikely(copy_param.async_status_index >= ctx->status_index_max)) {
				/* invalid index */
				dprintk("Invalid status array index in bounded copy ioctl\n");
				err = -EINVAL;
				goto out;
			}
		}

		if (unlikely((flags & KNEM_FLAG_NOTIFY_FD) != 0)) {
			if ((flags & KNEM_FLAG_ANY_THREAD_MASK) == 0) {
				dprintk("NOTIFY_FD flag requires thread offload\n");
				err = -EINVAL;
				goto out;
			}
			if ((flags & KNEM_FLAG_ASYNCDMACOMPLETE) != 0) {
				dprintk("NOTIFY_FD flag incompatible with ASYNCDMACOMPLETE\n");
				err = -EINVAL;
				goto out;
			}
		}

		err = knem_copy(ctx,
				copy_param.src_cookie, copy_param.src_offset,
				copy_param.dst_cookie, copy_param.dst_offset,
				copy_param.length, flags,
				&current_status,
				copy_param.async_status_index);
		if (likely(!err)) {
			copy_param.current_status = current_status;
			err = copy_to_user((void __user *) arg, &copy_param, sizeof(copy_param));
			BUG_ON(err); /* copy_from_user worked, so this one can't fail */
		}

		break;
	}

	case KNEM_CMD_COPY: {
		struct knem_cmd_copy copy_param;
		knem_status_t current_status = KNEM_STATUS_PENDING;
		unsigned int flags;

		err = copy_from_user(&copy_param, (void __user *) arg, sizeof(copy_param));
		if (unlikely(err)) {
			dprintk("Failed to read copy ioctl user-space param\n");
			err = -EFAULT;
			goto out;
		}

		/* update flags with ignored/forced ones */
		flags = KNEM_FIX_COPY_FLAGS(ctx, copy_param.flags);

		if (flags & KNEM_FLAG_ANY_ASYNC_MASK) {
			if (unlikely(ctx->status_array_state != KNEM_STATUS_ARRAY_READY)) {
				/* not mapped yet */
				dprintk("Cannot post a copy without a mapped status array\n");
				err = -EINVAL;
				goto out;
			}
			if (unlikely(copy_param.async_status_index >= ctx->status_index_max)) {
				/* invalid index */
				dprintk("Invalid status array index in copy ioctl\n");
				err = -EINVAL;
				goto out;
			}
		}

		if (unlikely((flags & KNEM_FLAG_NOTIFY_FD) != 0)) {
			if ((flags & KNEM_FLAG_ANY_THREAD_MASK) == 0) {
				dprintk("NOTIFY_FD flag requires thread offload\n");
				err = -EINVAL;
				goto out;
			}
			if ((flags & KNEM_FLAG_ASYNCDMACOMPLETE) != 0) {
				dprintk("NOTIFY_FD flag incompatible with ASYNCDMACOMPLETE\n");
				err = -EINVAL;
				goto out;
			}
		}

		err = knem_copy(ctx,
				copy_param.src_cookie, copy_param.src_offset,
				copy_param.dst_cookie, copy_param.dst_offset,
				(unsigned long) -1 /* no limit */, flags,
				&current_status,
				copy_param.async_status_index);
		if (likely(!err)) {
			copy_param.current_status = current_status;
			err = copy_to_user((void __user *) arg, &copy_param, sizeof(copy_param));
			BUG_ON(err); /* copy_from_user worked, so this one can't fail */
		}

		break;
	}

	case KNEM_CMD_INLINE_COPY_BOUNDED: {
		struct knem_cmd_inline_copy_bounded copy_param;
		knem_status_t current_status = KNEM_STATUS_PENDING;
		unsigned int flags;

		err = copy_from_user(&copy_param, (void __user *) arg, sizeof(copy_param));
		if (unlikely(err)) {
			dprintk("Failed to read bounded inline copy ioctl user-space param\n");
			err = -EFAULT;
			goto out;
		}

		/* update flags with ignored/forced ones */
		flags = KNEM_FIX_COPY_FLAGS(ctx, copy_param.flags);

		if (flags & KNEM_FLAG_ANY_ASYNC_MASK) {
			if (unlikely(ctx->status_array_state != KNEM_STATUS_ARRAY_READY)) {
				/* not mapped yet */
				dprintk("Cannot post an bounded inline copy without a mapped status array\n");
				err = -EINVAL;
				goto out;
			}
			if (unlikely(copy_param.async_status_index >= ctx->status_index_max)) {
				/* invalid index */
				dprintk("Invalid status array index in bounded inline copy ioctl\n");
				err = -EINVAL;
				goto out;
			}
		}

		if (unlikely((flags & KNEM_FLAG_NOTIFY_FD) != 0)) {
			if ((flags & KNEM_FLAG_ANY_THREAD_MASK) == 0) {
				dprintk("NOTIFY_FD flag requires thread offload\n");
				err = -EINVAL;
				goto out;
			}
			if ((flags & KNEM_FLAG_ASYNCDMACOMPLETE) != 0) {
				dprintk("NOTIFY_FD flag incompatible with ASYNCDMACOMPLETE\n");
				err = -EINVAL;
				goto out;
			}
		}

		err = knem_inline_copy(ctx,
				       (void __user *)(unsigned long) copy_param.local_iovec_array, copy_param.local_iovec_nr,
				       copy_param.remote_cookie, copy_param.remote_offset,
				       copy_param.length, flags, copy_param.write,
				       &current_status,
				       copy_param.async_status_index);
		if (likely(!err)) {
			copy_param.current_status = current_status;
			err = copy_to_user((void __user *) arg, &copy_param, sizeof(copy_param));
			BUG_ON(err); /* copy_from_user worked, so this one can't fail */
		}

		break;
	}

	case KNEM_CMD_INLINE_COPY: {
		struct knem_cmd_inline_copy copy_param;
		knem_status_t current_status = KNEM_STATUS_PENDING;
		unsigned int flags;

		err = copy_from_user(&copy_param, (void __user *) arg, sizeof(copy_param));
		if (unlikely(err)) {
			dprintk("Failed to read inline copy ioctl user-space param\n");
			err = -EFAULT;
			goto out;
		}

		/* update flags with ignored/forced ones */
		flags = KNEM_FIX_COPY_FLAGS(ctx, copy_param.flags);

		if (flags & KNEM_FLAG_ANY_ASYNC_MASK) {
			if (unlikely(ctx->status_array_state != KNEM_STATUS_ARRAY_READY)) {
				/* not mapped yet */
				dprintk("Cannot post an inline copy without a mapped status array\n");
				err = -EINVAL;
				goto out;
			}
			if (unlikely(copy_param.async_status_index >= ctx->status_index_max)) {
				/* invalid index */
				dprintk("Invalid status array index in inline copy ioctl\n");
				err = -EINVAL;
				goto out;
			}
		}

		if (unlikely((flags & KNEM_FLAG_NOTIFY_FD) != 0)) {
			if ((flags & KNEM_FLAG_ANY_THREAD_MASK) == 0) {
				dprintk("NOTIFY_FD flag requires thread offload\n");
				err = -EINVAL;
				goto out;
			}
			if ((flags & KNEM_FLAG_ASYNCDMACOMPLETE) != 0) {
				dprintk("NOTIFY_FD flag incompatible with ASYNCDMACOMPLETE\n");
				err = -EINVAL;
				goto out;
			}
		}

		err = knem_inline_copy(ctx,
				       (void __user *)(unsigned long) copy_param.local_iovec_array, copy_param.local_iovec_nr,
				       copy_param.remote_cookie, copy_param.remote_offset,
				       (unsigned long) -1 /* no limit */, flags, copy_param.write,
				       &current_status,
				       copy_param.async_status_index);
		if (likely(!err)) {
			copy_param.current_status = current_status;
			err = copy_to_user((void __user *) arg, &copy_param, sizeof(copy_param));
			BUG_ON(err); /* copy_from_user worked, so this one can't fail */
		}

		break;
	}


	case KNEM_CMD_INIT_SEND: {
		/* old API compatibility wrapper */
		struct knem_cmd_init_send_param send_param;
		unsigned int flags;

		err = copy_from_user(&send_param, (void __user *) arg, sizeof(send_param));
		if (unlikely(err)) {
			dprintk("Failed to read send ioctl user-space param\n");
			err = -EFAULT;
			goto out;
		}

		/* update flags with ignored/forced ones */
		flags = KNEM_FIX_CREATE_FLAGS(ctx, send_param.flags) | KNEM_FLAG_SINGLEUSE;

		err = knem_create_region(ctx,
					 (void __user *)(unsigned long) send_param.send_iovec_array,
					 send_param.send_iovec_nr,
					 flags, PROT_READ,
					 &send_param.send_cookie);
		if (likely(!err)) {
			err = copy_to_user((void __user *) arg, &send_param, sizeof(send_param));
			BUG_ON(err); /* copy_from_user worked, so this one can't fail */
		}

		break;
	}

	case KNEM_CMD_INIT_ASYNC_RECV: {
		/* old API compatibility wrapper */
		struct knem_cmd_init_async_recv_param recv_param;
		knem_status_t current_status = KNEM_STATUS_PENDING;
		unsigned int flags;

		err = copy_from_user(&recv_param, (void __user *) arg, sizeof(recv_param));
		if (unlikely(err)) {
			dprintk("Failed to read async recv ioctl user-space param\n");
			err = -EFAULT;
			goto out;
		}

		/* update flags with ignored/forced ones */
		flags = KNEM_FIX_COPY_FLAGS(ctx, recv_param.flags);

		if (unlikely(ctx->status_array_state != KNEM_STATUS_ARRAY_READY)) {
			/* not mapped yet */
			dprintk("Cannot post a recv without a mapped status array\n");
			err = -EINVAL;
			goto out;
		}
		if (unlikely(recv_param.status_index >= ctx->status_index_max)) {
			/* invalid index */
			dprintk("Invalid status array index in recv ioctl\n");
			err = -EINVAL;
			goto out;
		}

		if (unlikely((flags & KNEM_FLAG_NOTIFY_FD) != 0)) {
			if ((flags & KNEM_FLAG_ASYNCDMACOMPLETE) != 0) {
				dprintk("NOTIFY_FD flag incompatible with ASYNCDMACOMPLETE\n");
				err = -EINVAL;
				goto out;
			}
		}

		err = knem_inline_copy(ctx,
				       (void __user *)(unsigned long) recv_param.recv_iovec_array, recv_param.recv_iovec_nr,
				       recv_param.send_cookie, 0,
				       (unsigned long) -1 /* no limit */, flags, 0 /* read */,
				       &current_status,
				       recv_param.status_index);
		/* if completed synchronously, store the current_status into the async status array */
		if (!err && current_status != KNEM_STATUS_PENDING)
			ctx->status_array[recv_param.status_index] = current_status;
		break;
	}

	case KNEM_CMD_SYNC_RECV: {
		/* old API compatibility wrapper */
		struct knem_cmd_sync_recv_param recv_param;
		knem_status_t current_status = KNEM_STATUS_PENDING;
		unsigned int flags;

		err = copy_from_user(&recv_param, (void __user *) arg, sizeof(recv_param));
		if (unlikely(err)) {
			dprintk("Failed to read sync recv ioctl user-space param\n");
			err = -EFAULT;
			goto out;
		}

		/* update flags with ignored/forced ones */
		flags = KNEM_FIX_COPY_FLAGS(ctx, recv_param.flags);

		if (unlikely((flags & KNEM_FLAG_NOTIFY_FD) != 0)) {
			dprintk("NOTIFY_FD flag not supported for sync receive\n");
			err = -EINVAL;
			goto out;
		}

		/* synchronous may use pinning on send side only, or both */
		err = knem_inline_copy(ctx,
				       (void __user *)(unsigned long) recv_param.recv_iovec_array, recv_param.recv_iovec_nr,
				       recv_param.send_cookie, 0,
				       (unsigned long) -1 /* no limit */, flags & ~KNEM_FLAG_ANY_ASYNC_MASK, 0 /* read */,
				       &current_status,
				       0 /* status_index ignored if no async flags */);
		if (likely(!err)) {
			/* synchronous, so current_status is the final status */
			recv_param.status = current_status;
			err = copy_to_user((void __user *) arg, &recv_param, sizeof(recv_param));
			BUG_ON(err); /* copy_from_user worked, so this one can't fail */
		}

		break;
	}

	default:
		dprintk("Cannot handle unknown ioctl command %d", cmd);
		err = -ENOSYS;
		break;
	}

 out:
	return err;
}

static int
knem_miscdev_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct knem_context * ctx = file->private_data;
	struct task_struct * kthread_task;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long status_index_max = size / sizeof(knem_status_t);
	unsigned long eventbuffersize = status_index_max*sizeof(u32);
	unsigned long i;
	struct page **pages;
	void * buffer, * eventbuffer;
	int err;

	if (!ctx)
		/* mmap not available in reader mode, we need a knem context */
		return -EBADF;

	if (offset != KNEM_STATUS_ARRAY_FILE_OFFSET) {
		dprintk("Cannot map at file offset %lx\n", offset);
		err = -EINVAL;
		goto out;
	}

#if BITS_PER_LONG > 32
	if (status_index_max > (1UL<<32)) {
		dprintk("Cannot map more than 2^32 status slots, the index is on 32bits only\n");
		err = -EINVAL;
		goto out;
	}
#endif

	/* mark the status_array as being under creation.
	 * nobody else can mmap simultaneously,
	 * but other cannot use status_array yet.
	 */
	if (cmpxchg(&ctx->status_array_state, KNEM_STATUS_ARRAY_UNUSED, KNEM_STATUS_ARRAY_CREATING)
	    != KNEM_STATUS_ARRAY_UNUSED) {
		dprintk("Cannot attach another status array\n");
		err = -EBUSY;
		goto out;
	}

	ctx->status_index_max = status_index_max;

	buffer = knem_vmalloc_user(size);
	if (!buffer) {
		dprintk("Failed to allocate status array size %ld\n", size);
		err = -ENOMEM;
		goto out_with_state;
	}
	ctx->status_array = buffer;

	pages = kmalloc((size+PAGE_SIZE-1)>>PAGE_SHIFT, GFP_KERNEL);
	if (!pages) {
		dprintk("Failed to allocate status array pages array size %ld\n",
			(size+PAGE_SIZE-1)>>PAGE_SHIFT);
		err = -ENOMEM;
		goto out_with_buffer;
	}
	ctx->status_pages = pages;

	for(i=0; i<size; i+=PAGE_SIZE)
		pages[i>>PAGE_SHIFT] = vmalloc_to_page(buffer + i);

	err = knem_remap_vmalloc_range(vma, buffer, 0);
	if (err < 0) {
		dprintk("Failed to remap vmalloc'ed status array, got error %d\n", err);
		goto out_with_pages;
	}
	/* the caller will unmap if needed on error return below */

	eventbuffer = vmalloc(eventbuffersize);
	if (!eventbuffer) {
		dprintk("Failed to allocate status event array size %ld\n",
			eventbuffersize);
		err = -ENOMEM;
		goto out_with_remap_user;
	}
	ctx->notify_fd_array = eventbuffer;
	ctx->notify_fd_pending = 0;
	ctx->notify_fd_next_write = 0;
	ctx->notify_fd_to_read = 0;
	spin_lock_init(&ctx->notify_fd_lock);
	init_waitqueue_head(&ctx->notify_fd_wq);

	/* if no ioctl enforced the binding, use the module defaults */
	if (!ctx->kthread_cpumask_enforced) {
		if (knem_binding > 0)
			ctx->kthread_cpumask = knem_get_cpus_allowed(current);
		else if (knem_binding < 0)
			knem_cpumask_complement(&ctx->kthread_cpumask, &knem_get_cpus_allowed(current));
	}

	kthread_task = kthread_run(knem_kthread_func, ctx, "knem-ctx-%x",
				   (unsigned) ctx->id);
	if (IS_ERR(kthread_task)) {
		err = PTR_ERR(kthread_task);
		dprintk("Failed to start context kthread, error %d\n", err);
		goto out_with_eventbuffer;
	}
	ctx->kthread_task = kthread_task;

	/* status_array ready for real */
	ctx->status_array_state = KNEM_STATUS_ARRAY_READY;
	return 0;

 out_with_eventbuffer:
	vfree(ctx->notify_fd_array);
	ctx->notify_fd_array = NULL;
 out_with_remap_user:
        /* nothing to undo */
 out_with_pages:
	kfree(ctx->status_pages);
	ctx->status_pages = NULL;
 out_with_buffer:
	vfree(ctx->status_array);
	ctx->status_array = NULL;
 out_with_state:
	ctx->status_array_state = KNEM_STATUS_ARRAY_UNUSED;
	ctx->status_index_max = 0;
 out:
	return err;
}

static unsigned int
knem_miscdev_poll(struct file *file, struct poll_table_struct *wait)
{
	struct knem_context * ctx = file->private_data;
	return knem_notify_fd_poll(ctx, file, wait);
}

static ssize_t
knem_miscdev_read(struct file* file, char __user * buff, size_t count, loff_t* offp)
{
	struct knem_context * ctx = file->private_data;
	if (ctx)
		return knem_notify_fd_read(ctx, file, buff, count, offp);
	else
		return knem_read_counters(buff, count, offp);
}

static ssize_t
knem_miscdev_write(struct file* file, const char __user * buff, size_t count, loff_t* offp)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (file->private_data)
		return -EBUSY;

	knem_clear_counters();
	return count;
}

static struct file_operations
knem_miscdev_fops = {
	.owner = THIS_MODULE,
	.open = knem_miscdev_open,
	.release = knem_miscdev_release,
	.mmap = knem_miscdev_mmap,
	.poll = knem_miscdev_poll,
	.read = knem_miscdev_read,
	.write = knem_miscdev_write,
	.unlocked_ioctl = knem_miscdev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = knem_miscdev_ioctl,
#endif
};

static struct miscdevice
knem_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "knem",
	.fops = &knem_miscdev_fops,
};

/**************
 * Module core
 */

static int
knem_init(void)
{
	int err;

	knem_init_counters();

	err = knem_setup_flags();
	if (err < 0)
		goto out;

	err = knem_dmacpy_init();
	if (err < 0)
		goto out;

	err = knem_contexts_init();
	if (err < 0)
		goto out_with_dmacpy;

	err = misc_register(&knem_miscdev);
	if (err < 0) {
		dprintk("Failed to register misc device, error %d\n", err);
		goto out_with_contexts;
	}

	printk(KERN_INFO "knem " KNEM_VERSION_STR ": initialized\n");

	return 0;

 out_with_contexts:
	knem_contexts_exit();
 out_with_dmacpy:
	knem_dmacpy_exit();
 out:
	return err;
}
module_init(knem_init);

static void
knem_exit(void)
{
	printk(KERN_INFO "knem " KNEM_VERSION_STR ": terminating\n");

	/* wait for RCU callbacks to be done */
	rcu_barrier();
	/* wait for scheduled works to be done (might have been scheduled in RCU callback) */
	flush_scheduled_work();

	misc_deregister(&knem_miscdev);
	knem_contexts_exit();
	knem_dmacpy_exit();
}
module_exit(knem_exit);

MODULE_LICENSE("GPL");
#ifdef RETPOLINE_MLNX
MODULE_INFO(retpoline, "Y");
#endif
MODULE_AUTHOR("Brice Goglin <Brice.Goglin@inria.fr>");
MODULE_VERSION(PACKAGE_VERSION);
MODULE_DESCRIPTION(PACKAGE_NAME ": kernel-side Nemesis subsystem");

/*
 * Local variables:
 *  tab-width: 8
 *  c-basic-offset: 8
 *  c-indent-level: 8
 * End:
 */
