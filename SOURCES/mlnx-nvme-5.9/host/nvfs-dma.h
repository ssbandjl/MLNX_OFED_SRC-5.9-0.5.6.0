/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2021 NVIDIA Corporation.
 */

#ifndef NVFS_DMA_H
#define NVFS_DMA_H

static blk_status_t nvme_pci_setup_prps(struct nvme_dev *dev,
                struct request *req, struct nvme_rw_command *cmnd);

static blk_status_t nvme_pci_setup_sgls(struct nvme_dev *dev,
#ifdef HAVE_BIO_SPLIT_TO_LIMITS
                struct request *req, struct nvme_rw_command *cmnd);
#else
                 struct request *req, struct nvme_rw_command *cmnd, int entries);
#endif

static bool nvme_nvfs_unmap_data(struct nvme_dev *dev, struct request *req)
{
        struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
        enum dma_data_direction dma_dir = rq_dma_dir(req);

#ifdef HAVE_BIO_SPLIT_TO_LIMITS
        if (!iod || !iod->sgt.nents)
                return false;

        if (iod->sgt.sgl && !is_pci_p2pdma_page(sg_page(iod->sgt.sgl)) &&
#else
        if (!iod || !iod->nents)
                return false;

        if (iod->sg && !is_pci_p2pdma_page(sg_page(iod->sg)) &&
#endif
                !blk_integrity_rq(req) &&
#if defined(HAVE_BLKDEV_DMA_MAP_BVEC) && defined(HAVE_BLKDEV_REQ_BVEC)
                !iod->dma_len &&
#endif
                nvfs_ops != NULL) {
                int count;
#ifdef HAVE_BIO_SPLIT_TO_LIMITS
                count = nvfs_ops->nvfs_dma_unmap_sg(dev->dev, iod->sgt.sgl, iod->sgt.nents, dma_dir);
#else
                count = nvfs_ops->nvfs_dma_unmap_sg(dev->dev, iod->sg, iod->nents, dma_dir);
#endif
                if (!count)
                        return false;

                nvfs_put_ops();
                return true;
        }

        return false;
}

static blk_status_t nvme_nvfs_map_data(struct nvme_dev *dev, struct request *req,
               struct nvme_command *cmnd, bool *is_nvfs_io)
{
       struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
       struct request_queue *q = req->q;
       enum dma_data_direction dma_dir = rq_dma_dir(req);
       blk_status_t ret = BLK_STS_RESOURCE;
       int nr_mapped;

       nr_mapped = 0;
       *is_nvfs_io = false;

       if (!blk_integrity_rq(req) && nvfs_get_ops()) {
#if defined(HAVE_BLKDEV_DMA_MAP_BVEC) && defined(HAVE_BLKDEV_REQ_BVEC)
                iod->dma_len = 0;
#endif
#ifdef HAVE_BIO_SPLIT_TO_LIMITS
                iod->sgt.sgl = mempool_alloc(dev->iod_mempool, GFP_ATOMIC);
                if (!iod->sgt.sgl) {
#else
                iod->sg = mempool_alloc(dev->iod_mempool, GFP_ATOMIC);
                 if (!iod->sg) {
#endif
                        nvfs_put_ops();
                        return BLK_STS_RESOURCE;
                }
#ifdef HAVE_BIO_SPLIT_TO_LIMITS
               sg_init_table(iod->sgt.sgl, blk_rq_nr_phys_segments(req));
               // associates bio pages to scatterlist
               iod->sgt.orig_nents = nvfs_ops->nvfs_blk_rq_map_sg(q, req, iod->sgt.sgl);
               if (!iod->sgt.orig_nents) {
                       mempool_free(iod->sgt.sgl, dev->iod_mempool);
#else
                sg_init_table(iod->sg, blk_rq_nr_phys_segments(req));
                // associates bio pages to scatterlist
                iod->nents = nvfs_ops->nvfs_blk_rq_map_sg(q, req, iod->sg);
                if (!iod->nents) {
                        mempool_free(iod->sg, dev->iod_mempool);
#endif
                       nvfs_put_ops();
                       return BLK_STS_IOERR; // reset to original ret
               }
               *is_nvfs_io = true;

#ifdef HAVE_BIO_SPLIT_TO_LIMITS
               if (unlikely((iod->sgt.orig_nents == NVFS_IO_ERR))) {
                       pr_err("%s: failed to map sg_nents=:%d\n", __func__, iod->sgt.nents);
                       mempool_free(iod->sgt.sgl, dev->iod_mempool);
#else
                if (unlikely((iod->nents == NVFS_IO_ERR))) {
                        pr_err("%s: failed to map sg_nents=:%d\n", __func__, iod->nents);
                        mempool_free(iod->sg, dev->iod_mempool);
#endif
                       nvfs_put_ops();
                       return BLK_STS_IOERR;
               }

               nr_mapped = nvfs_ops->nvfs_dma_map_sg_attrs(dev->dev,
#ifdef HAVE_BIO_SPLIT_TO_LIMITS
                               iod->sgt.sgl,
                               iod->sgt.orig_nents,
                               dma_dir,
                               DMA_ATTR_NO_WARN);
#else
                                iod->sg,
                                iod->nents,
                                dma_dir,
                                DMA_ATTR_NO_WARN);
#endif

               if (unlikely((nr_mapped == NVFS_IO_ERR))) {
#ifdef HAVE_BIO_SPLIT_TO_LIMITS
                       mempool_free(iod->sgt.sgl, dev->iod_mempool);
                       nvfs_put_ops();
                       pr_err("%s: failed to dma map sglist=:%d\n", __func__, iod->sgt.nents);
#else
                        mempool_free(iod->sg, dev->iod_mempool);
                        nvfs_put_ops();
                        pr_err("%s: failed to dma map sglist=:%d\n", __func__, iod->nents);
#endif
                       return BLK_STS_IOERR;
               }

               if (unlikely(nr_mapped == NVFS_CPU_REQ)) {
#ifdef HAVE_BIO_SPLIT_TO_LIMITS
                       mempool_free(iod->sgt.sgl, dev->iod_mempool);
#else
                        mempool_free(iod->sg, dev->iod_mempool);
#endif
                       nvfs_put_ops();
                       BUG();
               }

#ifdef HAVE_BIO_SPLIT_TO_LIMITS
               iod->sgt.nents = nr_mapped;
# else
                iod->nents = nr_mapped;
#endif
               iod->use_sgl = nvme_pci_use_sgls(dev, req);
               if (iod->use_sgl) { // TBD: not tested on SGL mode supporting drive
#ifdef HAVE_BIO_SPLIT_TO_LIMITS
                        ret = nvme_pci_setup_sgls(dev, req, &cmnd->rw);
#else
                        ret = nvme_pci_setup_sgls(dev, req, &cmnd->rw, nr_mapped);
#endif
               } else {
                       // push dma address to hw registers
                       ret = nvme_pci_setup_prps(dev, req, &cmnd->rw);
               }

               if (ret != BLK_STS_OK) {
                       nvme_nvfs_unmap_data(dev, req);
#ifdef HAVE_BIO_SPLIT_TO_LIMITS
                        mempool_free(iod->sgt.sgl, dev->iod_mempool);
#else
                        mempool_free(iod->sg, dev->iod_mempool);
#endif
               }
               return ret;
       }
       return ret;
}

#endif /* NVFS_DMA_H */
