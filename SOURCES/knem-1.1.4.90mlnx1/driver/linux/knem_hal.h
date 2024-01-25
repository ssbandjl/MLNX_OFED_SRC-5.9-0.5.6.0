/*
 * Copyright © Inria 2009-2014
 * Brice Goglin <Brice.Goglin@inria.fr>
 *
 * This file is distributed under the GNU General Pulic License version 2.
 */

#ifndef __knem_hal_h__
#define __knem_hal_h__

#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/compiler.h>
#include <linux/version.h>

/* DIV_ROUND_UP added in 2.6.19 */
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

#if (defined KNEM_HAVE_REMAP_VMALLOC_RANGE) && (defined KNEM_HAVE_VMALLOC_USER)
/*
 * Either use both official vmalloc_user()/remap_vmalloc_range() or none
 * of them since there were introduced by the same commit, and we can't
 * emulate the former properly (we can't set VM_USERMAP in the area flags
 * while the official remap_vmalloc_range() requires it).
 */

#define knem_vmalloc_user vmalloc_user
#define knem_remap_vmalloc_range remap_vmalloc_range

#else /* !KNEM_HAVE_REMAP_VMALLOC_RANGE || !KNEM_HAVE_VMALLOC_USER */

#include <asm/pgtable.h>

static inline void *
knem_vmalloc_user(unsigned long size)
{
	/* don't pass __GFP_ZERO since cache_grow() would BUG() in <=2.6.18 */
	void * buf = __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL);
	if (buf) {
		/*
		 * We cannot set VM_USERMAP since __find_vm_area() is not exported.
		 * But remap_vmalloc_range() requires it, see below
		 */

		/* memset since we didn't pass __GFP_ZERO above */
		memset(buf, 0, size);
	}
	return buf;
}

static inline int
knem_remap_vmalloc_range(struct vm_area_struct *vma, void *addr, unsigned long pgoff)
{
	unsigned long uaddr = vma->vm_start;
	unsigned long usize = vma->vm_end - vma->vm_start;
	int ret;

	addr += pgoff << PAGE_SHIFT;
	do {
		struct page *page = vmalloc_to_page(addr);
		ret = vm_insert_page(vma, uaddr, page);
		if (ret)
			return ret;

		uaddr += PAGE_SIZE;
		addr += PAGE_SIZE;
		usize -= PAGE_SIZE;
	} while (usize > 0);

	/* Prevent "things" like memory migration? VM_flags need a cleanup... */
	vma->vm_flags |= VM_RESERVED;

	return ret;
}

#endif /* !KNEM_HAVE_REMAP_VMALLOC_RANGE || !KNEM_HAVE_VMALLOC_USER*/

#ifdef KNEM_HAVE_CPUMASK_PR_ARGS
#define knem_cpumask_scnprintf(buf, len, mask) scnprintf(buf, len, "%*pb", cpumask_pr_args(mask))
#elif (defined KNEM_CPUMASK_SCNPRINTF_USES_PTR)
#define knem_cpumask_scnprintf(buf, len, mask) cpumask_scnprintf(buf, len, mask)
#else
#define knem_cpumask_scnprintf(buf, len, mask) cpumask_scnprintf(buf, len, *mask)
#endif

#ifdef KNEM_HAVE_OLD_DMA_ENGINE_API

/* kernel <= 2.6.28 with DMA engine support through NET_DMA */
#ifdef CONFIG_NET_DMA
#define KNEM_HAVE_DMA_ENGINE 1
#include <linux/netdevice.h>
#include <net/netdma.h>
static inline struct dma_chan * knem_get_dma_channel(void) { return get_softnet_dma(); }
static inline void knem_put_dma_channel(struct dma_chan *chan) { dma_chan_put(chan); }
static inline int knem_dma_channel_avail(void) { return __get_cpu_var(softnet_data).net_dma != NULL; }
#endif

#elif defined KNEM_HAVE_DMA_ENGINE_API

/* kernel >= 2.6.29 with nice DMA engine suport */
#if defined CONFIG_DMA_ENGINE || defined CONFIG_DMA_ENGINE_V3
#define KNEM_HAVE_DMA_ENGINE 1
#include <linux/dmaengine.h>
static inline struct dma_chan * knem_get_dma_channel(void)
{
	struct dma_chan *chan;
	dmaengine_get();
	chan = dma_find_channel(DMA_MEMCPY);
	if (chan) {
#ifdef KNEM_HAVE_IS_DMA_COPY_ALIGNED
		if (!is_dma_copy_aligned(chan->device, 1, 1, 1)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
			if (chan->device->copy_align == 6) {
				printk_once("knem: DMA channel reports 64-byte alignment restriction, IGNORED\n"
					    "knem: (this is likely the IOAT DMA channel RAID bug workaround).\n"
					    "knem: Disable DMA with dma=0 module param if IOAT RAID offload is used.\n");
				return chan;
			}
#endif
			printk_once("knem: cannot use DMA channel without 1-byte alignment support.\n");
			dmaengine_put();
			return NULL;
		}
#endif
	}
	return chan;
}
static inline void knem_put_dma_channel(struct dma_chan *chan) { dmaengine_put(); }
static inline int knem_dma_channel_avail(void) { return dma_find_channel(DMA_MEMCPY) != NULL; }
#endif

#else /* !KNEM_HAVE_{,OLD_}DMA_ENGINE_API */

/* kernel <= 2.6.17 with no DMA engine at all */

#endif /* !KNEM_HAVE_{,OLD_}DMA_ENGINE_API */

#ifdef KNEM_HAVE_GET_USER_PAGES_FAST
static inline int
knem_get_user_pages_fast(unsigned long start, int nr_pages, int write, struct page **pages)
{
	int ret;
	int done;
#ifdef KNEM_GUP_FAST_FLAGS
	unsigned int flags = (write ? FOLL_WRITE : 0);
#ifdef FOLL_LONGTERM
	flags |= FOLL_LONGTERM; /* required since 5.3 */
#endif
#else
	int flags = write;
#endif

	done = 0;
	while (nr_pages) {
#define KNEM_GET_USER_PAGES_FAST_BATCH 32
		int chunk = nr_pages > KNEM_GET_USER_PAGES_FAST_BATCH ? KNEM_GET_USER_PAGES_FAST_BATCH : nr_pages;
		ret = get_user_pages_fast(start, chunk, flags, pages);
		if (ret != chunk) {
			ret = done + (ret < 0 ? 0 : ret);
			goto out;
		}
		pages += chunk;
		start += chunk << PAGE_SHIFT;
		done += chunk;
		nr_pages -= chunk;
	}
	ret = done;

 out:
	return ret;
}
#else /* !KNEM_HAVE_GET_USER_PAGES_FAST */
/* If get_user_pages_fast() isn't available, use get_user_pages().
 * That's only for <2.6.27, so just support that version of get_user_pages().
 */
static inline int
knem_get_user_pages_fast(unsigned long start, int nr_pages, int write, struct page **pages)
{
	struct mm_struct *mm = current->mm;
	int ret;

	down_read(&mm->mmap_sem);
	ret = get_user_pages(current, mm, start, nr_pages, write, 0, pages, NULL);
	up_read(&mm->mmap_sem);

	return ret;
}
#endif /* !KNEM_HAVE_GET_USER_PAGES_FAST */

#ifdef KNEM_HAVE_CPUMASK_COMPLEMENT
#define knem_cpumask_complement cpumask_complement
#define knem_cpumask_setall cpumask_setall
#else
#define knem_cpumask_complement(a,b) cpus_complement(*(a), *(b))
#define knem_cpumask_setall(m) cpus_setall(*(m))
#endif

#ifdef KNEM_HAVE_SET_CPUS_ALLOWED_PTR
#define knem_set_cpus_allowed_ptr set_cpus_allowed_ptr
#else
#define knem_set_cpus_allowed_ptr(task, maskp) set_cpus_allowed(task, *maskp)
#endif

#ifdef KNEM_HAVE_TASK_CPUS_MASK
#define knem_get_cpus_allowed(task) ((task)->cpus_mask)
#else
#define knem_get_cpus_allowed(task) ((task)->cpus_allowed)
#endif

/*
 * When IDR is RCU-ready, we use a IDR for ID allocation and lookup.
 * When IDR is not RCU-ready and IDA doesn't exist, we use a IDR for ID allocation.
 * When IDR is not RCU-ready and IDA exists, we use a IDA for ID allocation.
 *
 * This is combined with a hash-table for lookup when IDR is not RCU-ready.
 */
#if (defined KNEM_HAVE_RCU_IDR) || !(defined KNEM_HAVE_IDA)
#define knem_regions_idr idr
#define knem_regions_idr_init idr_init
#define knem_regions_idr_pre_get idr_pre_get
#define knem_regions_idr_get_new idr_get_new
#define knem_regions_idr_remove idr_remove
#define knem_regions_idr_destroy idr_destroy
#else
#define knem_regions_idr ida
#define knem_regions_idr_init ida_init
#define knem_regions_idr_pre_get ida_pre_get
#define knem_regions_idr_get_new(_ida, _ptr, _idp) ida_get_new(_ida, _idp)
#define knem_regions_idr_remove ida_remove
#define knem_regions_idr_destroy ida_destroy
#endif

/* work_struct switch to container_of in 2.6.20 */
#ifdef KNEM_HAVE_WORK_STRUCT_DATA
#define KNEM_INIT_WORK(_work, _func, _data) INIT_WORK(_work, _func, _data)
#define KNEM_WORK_STRUCT_DATA(_data, _type, _field) (_data)
typedef void * knem_work_struct_data_t;
#else
#define KNEM_INIT_WORK(_work, _func, _data) INIT_WORK(_work, _func)
#define KNEM_WORK_STRUCT_DATA(_data, _type, _field) container_of(_data, _type, _field)
typedef struct work_struct * knem_work_struct_data_t;
#endif

/* rcu_access_pointer added in 2.6.34 */
#ifndef rcu_access_pointer
#define rcu_access_pointer(x) (x)
#endif

/* rcu helper added in 2.6.37 */
#ifndef RCU_INIT_POINTER
#define RCU_INIT_POINTER(p, v) p = (typeof(*v) __force __rcu *)(v)
#endif

/* sparse rcu pointer dereferencing check added in 2.6.37 */
#ifndef __rcu
#define __rcu
#endif

/* k[un]map_atomic doesn't want a type since 3.4 */
#ifdef KNEM_HAVE_KMAP_ATOMIC_TYPE
#define knem_kmap_atomic kmap_atomic
#define knem_kunmap_atomic kunmap_atomic
#else
#define knem_kmap_atomic(x,type) kmap_atomic(x)
#define knem_kunmap_atomic(x,type) kunmap_atomic(x)
#endif

/* current_uid() added in 2.6.27 */
#ifdef KNEM_HAVE_CURRENT_UID
#include <linux/cred.h>
#else
#define current_uid() current->uid
#endif

/* dma_async_memcpy_issue_pending removed in 3.9
 * dma_async_issue_pending added in the meantime
 */
#ifndef KNEM_HAVE_DMA_ASYNC_ISSUE_PENDING
#define dma_async_issue_pending dma_async_memcpy_issue_pending
#endif

/* dma_async_memcpy_complete removed in 3.9
 * dma_async_is_tx_complete added in the meantime
 */
#ifndef KNEM_HAVE_DMA_ASYNC_IS_TX_COMPLETE
#define dma_async_is_tx_complete dma_async_memcpy_complete
#endif

/* cred uses kuid_t since 3.5 */
#ifdef KNEM_HAVE_CRED_KUID
#define knem_kuid_t kuid_t
#define knem_uid_eq uid_eq
#else
#define knem_kuid_t uid_t
#define knem_uid_eq(x,y) ((x) == (y))
#endif

/* DMA_SUCCESS renamed into DMA_COMPLETE in 3.13 */
#ifndef KNEM_HAVE_DMA_COMPLETE
#define DMA_COMPLETE DMA_SUCCESS
#endif

/* printk_once added in 2.6.30 */
#ifndef KNEM_HAVE_PRINTK_ONCE
#define knem_printk_once(x...) do {	\
  static int ___once = 0;		\
  if (!___once) {			\
    ___once = 1;			\
    printk(x);				\
  }					\
} while (0)
#else
#define knem_printk_once printk_once
#endif

/* dma_async_memcpy_pg_to_pg removed in 3.18 together with netdma */
#ifdef KNEM_HAVE_DMA_ENGINE
#ifndef KNEM_HAVE_DMA_ASYNC_MEMCPY_PG_TO_PG
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
/* Copyright(c) 2004 - 2006 Intel Corporation. All rights reserved. */
dma_cookie_t
knem_dma_async_memcpy_pg_to_pg(struct dma_chan *chan, struct page *dest_pg,
			       unsigned int dest_off, struct page *src_pg, unsigned int src_off, size_t len)
{
	struct dma_device *dev = chan->device;
	struct dma_async_tx_descriptor *tx;
	dma_cookie_t cookie;
#ifdef KNEM_HAVE_DMAENGINE_GET_UNMAP_DATA
	struct dmaengine_unmap_data *unmap;

	unmap = dmaengine_get_unmap_data(dev->dev, 2, GFP_NOWAIT);
	if (!unmap)
		return -ENOMEM;

	unmap->to_cnt = 1;
	unmap->from_cnt = 1;
	unmap->addr[0] = dma_map_page(dev->dev, src_pg, src_off, len, DMA_TO_DEVICE);
	unmap->addr[1] = dma_map_page(dev->dev, dest_pg, dest_off, len, DMA_FROM_DEVICE);
	unmap->len = len;
	tx = dev->device_prep_dma_memcpy(chan, unmap->addr[1], unmap->addr[0], len, DMA_CTRL_ACK);
	if (!tx) {
		dmaengine_unmap_put(unmap);
		return -ENOMEM;
	}

	dma_set_unmap(tx, unmap);
	cookie = tx->tx_submit(tx);
	dmaengine_unmap_put(unmap);
#else /* !KNEM_HAVE_DMAENGINE_GET_UNMAP_DATA */
	dma_addr_t dma_dest, dma_src;
	unsigned long flags;

	dma_src = dma_map_page(dev->dev, src_pg, src_off, len, DMA_TO_DEVICE);
	dma_dest = dma_map_page(dev->dev, dest_pg, dest_off, len, DMA_FROM_DEVICE);
	flags = DMA_CTRL_ACK;
	tx = dev->device_prep_dma_memcpy(chan, dma_dest, dma_src, len, flags);
        if (!tx) {
		dma_unmap_page(dev->dev, dma_src, len, DMA_TO_DEVICE);
		dma_unmap_page(dev->dev, dma_dest, len, DMA_FROM_DEVICE);
                return -ENOMEM;
        }
	tx->callback = NULL;
	cookie = tx->tx_submit(tx);
#endif
	return cookie;
}
#else /* KNEM_HAVE_DMA_ASYNC_MEMCPY_PG_TO_PG */
#define knem_dma_async_memcpy_pg_to_pg dma_async_memcpy_pg_to_pg
#endif /* KNEM_HAVE_DMA_ASYNC_MEMCPY_PG_TO_PG */
#endif /* KNEM_HAVE_DMA_ENGINE */

#endif /* __knem_hal_h__ */
