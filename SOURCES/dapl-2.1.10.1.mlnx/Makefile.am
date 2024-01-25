# $Id: $

ACLOCAL_AMFLAGS = -I m4

OSFLAGS = -DOS_RELEASE=$(shell expr `uname -r | cut -f1 -d.` \* 65536 + `uname -r | cut -f2 -d.`)
# Check for RedHat, needed for ia64 udapl atomic operations (IA64_FETCHADD syntax)
# and built-in atomics for RedHat EL5

if OS_SUSE11
OSFLAGS += -DSUSE_11
endif

if EXT_TYPE_IB
XFLAGS = -DDAT_EXTENSIONS
XPROGRAMS = dapl/openib_common/ib_extensions.c
XHEADERS =
XDAT = dat/include/dat2/dat_ib_extensions.h
XLIBS =
if DEFINE_COUNTERS
XFLAGS += -DDAPL_COUNTERS
endif
if COLL_TYPE_FCA
XFLAGS += -DDAT_IB_COLLECTIVES -DDAT_FCA_PROVIDER
XPROGRAMS += dapl/openib_common/collectives/fca_provider.c
XHEADERS += dapl/openib_common/collectives/ib_collectives.h dapl/openib_common/collectives/fca_provider.h
XLIBS += -lfca
endif
else
XFLAGS =
XPROGRAMS =
XHEADERS =
XDAT =
XLIBS =
endif

if DAPL_USE_IBACM
XLIBS += -lrdmacm
endif

if DEFINE_ATTR_LINK_LAYER
XFLAGS += -DDEFINE_ATTR_LINK_LAYER
endif

if DEBUG
AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DDAPL_DBG -DDAT_CONF="\"$(sysconfdir)/dat.conf\"" 
else
AM_CFLAGS = -g -Wall -D_GNU_SOURCE -DDAT_CONF="\"$(sysconfdir)/dat.conf\""
endif

AM_CFLAGS += -DMPXYD_CONF="\"$(sysconfdir)/mpxyd.conf\""
AM_CFLAGS += -DPACKAGE_DATE=$$(date -u -d@$${SOURCE_DATE_EPOCH:-$$(date ++%s)} +'%Y%m%d')

sysconf_DATA = doc/dat.conf

datlibdir = $(libdir)
if DEFINE_CMA
dapllibofadir = $(libdir)
endif
if DEFINE_SCM
daplliboscmdir = $(libdir)
endif
if DEFINE_UCM
daplliboucmdir = $(libdir)
endif
if DEFINE_MCM
dapllibomcmdir = $(libdir)
endif

datlib_LTLIBRARIES = dat/udat/libdat2.la
if DEFINE_CMA
dapllibofa_LTLIBRARIES = dapl/udapl/libdaplofa.la
endif
if DEFINE_SCM
daplliboscm_LTLIBRARIES = dapl/udapl/libdaploscm.la
endif
if DEFINE_UCM
daplliboucm_LTLIBRARIES = dapl/udapl/libdaploucm.la
endif
if DEFINE_MCM
dapllibomcm_LTLIBRARIES = dapl/udapl/libdaplomcm.la
endif

dat_udat_libdat2_la_CFLAGS = $(AM_CFLAGS) -D_GNU_SOURCE $(OSFLAGS) $(XFLAGS) \
				-I$(srcdir)/dat/include/ -I$(srcdir)/dat/udat/ \
				-I$(srcdir)/dat/udat/linux -I$(srcdir)/dat/common/ 
if DEFINE_CMA
dapl_udapl_libdaplofa_la_CFLAGS = $(AM_CFLAGS) -D_GNU_SOURCE $(OSFLAGS) $(XFLAGS) \
				-DOPENIB -DCQ_WAIT_OBJECT \
				-I$(srcdir)/dat/include/ -I$(srcdir)/dapl/include/ \
				-I$(srcdir)/dapl/common -I$(srcdir)/dapl/udapl/linux \
				-I$(srcdir)/dapl/openib_common \
				-I$(srcdir)/dapl/openib_cma \
				-I$(srcdir)/dapl/openib_cma/linux
endif
if DEFINE_SCM
dapl_udapl_libdaploscm_la_CFLAGS = $(AM_CFLAGS) -D_GNU_SOURCE $(OSFLAGS) $(XFLAGS) \
                                -DOPENIB -DCQ_WAIT_OBJECT \
                                -I$(srcdir)/dat/include/ -I$(srcdir)/dapl/include/ \
                                -I$(srcdir)/dapl/common -I$(srcdir)/dapl/udapl/linux \
				-I$(srcdir)/dapl/openib_common \
                                -I$(srcdir)/dapl/openib_scm \
				-I$(srcdir)/dapl/openib_scm/linux
endif
if DEFINE_UCM
dapl_udapl_libdaploucm_la_CFLAGS = $(AM_CFLAGS) -D_GNU_SOURCE $(OSFLAGS) $(XFLAGS) \
                                -DOPENIB -DCQ_WAIT_OBJECT \
                                -I$(srcdir)/dat/include/ -I$(srcdir)/dapl/include/ \
                                -I$(srcdir)/dapl/common -I$(srcdir)/dapl/udapl/linux \
				-I$(srcdir)/dapl/openib_common \
                                -I$(srcdir)/dapl/openib_ucm \
				-I$(srcdir)/dapl/openib_ucm/linux				
endif
if DEFINE_MCM
dapl_udapl_libdaplomcm_la_CFLAGS = $(AM_CFLAGS) -D_GNU_SOURCE $(OSFLAGS) $(XFLAGS) \
                                -DOPENIB -DCQ_WAIT_OBJECT \
                                -I$(srcdir)/dat/include/ -I$(srcdir)/dapl/include/ \
                                -I$(srcdir)/dapl/common -I$(srcdir)/dapl/udapl/linux \
				-I$(srcdir)/dapl/openib_common \
				-I$(srcdir)/dapl/svc \
                                -I$(srcdir)/dapl/openib_mcm \
				-I$(srcdir)/dapl/openib_mcm/linux				
endif
if HAVE_LD_VERSION_SCRIPT
    dat_version_script = -Wl,--version-script=$(srcdir)/dat/udat/libdat2.map
if DEFINE_CMA
    daplofa_version_script = -Wl,--version-script=$(srcdir)/dapl/udapl/libdaplofa.map
endif
if DEFINE_SCM
    daploscm_version_script = -Wl,--version-script=$(srcdir)/dapl/udapl/libdaploscm.map
endif
if DEFINE_UCM
    daploucm_version_script = -Wl,--version-script=$(srcdir)/dapl/udapl/libdaploucm.map
endif
if DEFINE_MCM
    daplomcm_version_script = -Wl,--version-script=$(srcdir)/dapl/udapl/libdaplomcm.map
endif
else
    dat_version_script = 
if DEFINE_CMA
    daplofa_version_script = 
endif
if DEFINE_SCM
    daploscm_version_script =
endif
if DEFINE_UCM
    daploucm_version_script =
endif
if DEFINE_MCM
    daplopcm_version_script =
endif
endif

#
# uDAT: libdat2.so
#
dat_udat_libdat2_la_SOURCES = dat/udat/udat.c \
			dat/udat/udat_api.c \
			dat/udat/udat_sr_parser.c \
			dat/udat/linux/dat_osd.c \
			dat/common/dat_api.c \
			dat/common/dat_dictionary.c \
			dat/common/dat_strerror.c \
			dat/common/dat_init.c \
			dat/common/dat_dr.c \
			dat/common/dat_sr.c
dat_udat_libdat2_la_LDFLAGS = -version-info 2:0:0 $(dat_version_script) -ldl 

if DEFINE_CMA
#
# uDAPL OpenFabrics rdma_cm version: libdaplofa.so
#
dapl_udapl_libdaplofa_la_SOURCES = dapl/udapl/dapl_init.c \
        dapl/udapl/dapl_evd_create.c               \
        dapl/udapl/dapl_evd_query.c                \
        dapl/udapl/dapl_cno_create.c               \
        dapl/udapl/dapl_cno_modify_agent.c         \
        dapl/udapl/dapl_cno_free.c                 \
        dapl/udapl/dapl_cno_wait.c                 \
        dapl/udapl/dapl_cno_query.c                \
        dapl/udapl/dapl_lmr_create.c               \
        dapl/udapl/dapl_evd_wait.c                 \
        dapl/udapl/dapl_evd_disable.c              \
        dapl/udapl/dapl_evd_enable.c               \
        dapl/udapl/dapl_evd_modify_cno.c           \
        dapl/udapl/dapl_evd_set_unwaitable.c       \
        dapl/udapl/dapl_evd_clear_unwaitable.c     \
        dapl/udapl/linux/dapl_osd.c                \
        dapl/common/dapl_cookie.c                   \
        dapl/common/dapl_cr_accept.c                \
        dapl/common/dapl_cr_query.c                 \
        dapl/common/dapl_cr_reject.c                \
        dapl/common/dapl_cr_util.c                  \
        dapl/common/dapl_cr_callback.c              \
        dapl/common/dapl_cr_handoff.c               \
        dapl/common/dapl_ep_connect.c               \
        dapl/common/dapl_ep_create.c                \
        dapl/common/dapl_ep_disconnect.c            \
        dapl/common/dapl_ep_dup_connect.c           \
        dapl/common/dapl_ep_free.c                  \
        dapl/common/dapl_ep_reset.c                 \
        dapl/common/dapl_ep_get_status.c            \
        dapl/common/dapl_ep_modify.c                \
        dapl/common/dapl_ep_post_rdma_read.c        \
        dapl/common/dapl_ep_post_rdma_write.c       \
        dapl/common/dapl_ep_post_recv.c             \
        dapl/common/dapl_ep_post_send.c             \
        dapl/common/dapl_ep_query.c                 \
        dapl/common/dapl_ep_util.c                  \
        dapl/common/dapl_evd_dequeue.c              \
        dapl/common/dapl_evd_free.c                 \
        dapl/common/dapl_evd_post_se.c              \
        dapl/common/dapl_evd_resize.c               \
        dapl/common/dapl_evd_util.c                 \
        dapl/common/dapl_evd_cq_async_error_callb.c \
        dapl/common/dapl_evd_qp_async_error_callb.c \
        dapl/common/dapl_evd_un_async_error_callb.c \
        dapl/common/dapl_evd_connection_callb.c     \
        dapl/common/dapl_evd_dto_callb.c            \
        dapl/common/dapl_get_consumer_context.c     \
        dapl/common/dapl_get_handle_type.c          \
        dapl/common/dapl_hash.c                     \
        dapl/common/dapl_hca_util.c                 \
        dapl/common/dapl_ia_close.c                 \
        dapl/common/dapl_ia_open.c                  \
        dapl/common/dapl_ia_query.c                 \
        dapl/common/dapl_ia_util.c                  \
        dapl/common/dapl_llist.c                    \
        dapl/common/dapl_lmr_free.c                 \
        dapl/common/dapl_lmr_query.c                \
        dapl/common/dapl_lmr_util.c                 \
        dapl/common/dapl_lmr_sync_rdma_read.c       \
        dapl/common/dapl_lmr_sync_rdma_write.c      \
        dapl/common/dapl_mr_util.c                  \
        dapl/common/dapl_provider.c                 \
        dapl/common/dapl_sp_util.c                  \
        dapl/common/dapl_psp_create.c               \
        dapl/common/dapl_psp_create_any.c           \
        dapl/common/dapl_psp_free.c                 \
        dapl/common/dapl_psp_query.c                \
        dapl/common/dapl_pz_create.c                \
        dapl/common/dapl_pz_free.c                  \
        dapl/common/dapl_pz_query.c                 \
        dapl/common/dapl_pz_util.c                  \
        dapl/common/dapl_rmr_create.c               \
        dapl/common/dapl_rmr_free.c                 \
        dapl/common/dapl_rmr_bind.c                 \
        dapl/common/dapl_rmr_query.c                \
        dapl/common/dapl_rmr_util.c                 \
        dapl/common/dapl_rsp_create.c               \
        dapl/common/dapl_rsp_free.c                 \
        dapl/common/dapl_rsp_query.c                \
        dapl/common/dapl_cno_util.c                 \
        dapl/common/dapl_set_consumer_context.c     \
        dapl/common/dapl_ring_buffer_util.c         \
        dapl/common/dapl_name_service.c             \
        dapl/common/dapl_timer_util.c               \
        dapl/common/dapl_ep_create_with_srq.c       \
        dapl/common/dapl_ep_recv_query.c            \
        dapl/common/dapl_ep_set_watermark.c         \
        dapl/common/dapl_srq_create.c               \
        dapl/common/dapl_srq_free.c                 \
        dapl/common/dapl_srq_query.c                \
        dapl/common/dapl_srq_resize.c               \
        dapl/common/dapl_srq_post_recv.c            \
        dapl/common/dapl_srq_set_lw.c               \
        dapl/common/dapl_srq_util.c                 \
        dapl/common/dapl_debug.c                    \
        dapl/common/dapl_ia_ha.c                    \
        dapl/common/dapl_csp.c                      \
        dapl/common/dapl_ep_post_send_invalidate.c  \
        dapl/common/dapl_ep_post_rdma_read_to_rmr.c \
        dapl/openib_common/mem.c                    \
        dapl/openib_common/cq.c                     \
        dapl/openib_common/qp.c                     \
        dapl/openib_common/util.c                   \
        dapl/openib_common/srq.c                    \
        dapl/openib_cma/cm.c                        \
        dapl/openib_cma/device.c $(XPROGRAMS)

dapl_udapl_libdaplofa_la_LDFLAGS = -version-info 2:0:0 $(daplofa_version_script) \
				   -Wl,-init,dapl_init -Wl,-fini,dapl_fini \
				   -lpthread -libverbs -lrdmacm $(XLIBS)
endif

if DEFINE_SCM				
#
# uDAPL OpenFabrics Socket CM version for IB: libdaplscm.so
#
dapl_udapl_libdaploscm_la_SOURCES = dapl/udapl/dapl_init.c \
        dapl/udapl/dapl_evd_create.c               \
        dapl/udapl/dapl_evd_query.c                \
        dapl/udapl/dapl_cno_create.c               \
        dapl/udapl/dapl_cno_modify_agent.c         \
        dapl/udapl/dapl_cno_free.c                 \
        dapl/udapl/dapl_cno_wait.c                 \
        dapl/udapl/dapl_cno_query.c                \
        dapl/udapl/dapl_lmr_create.c               \
        dapl/udapl/dapl_evd_wait.c                 \
        dapl/udapl/dapl_evd_disable.c              \
        dapl/udapl/dapl_evd_enable.c               \
        dapl/udapl/dapl_evd_modify_cno.c           \
        dapl/udapl/dapl_evd_set_unwaitable.c       \
        dapl/udapl/dapl_evd_clear_unwaitable.c     \
        dapl/udapl/linux/dapl_osd.c                \
        dapl/common/dapl_cookie.c                   \
        dapl/common/dapl_cr_accept.c                \
        dapl/common/dapl_cr_query.c                 \
        dapl/common/dapl_cr_reject.c                \
        dapl/common/dapl_cr_util.c                  \
        dapl/common/dapl_cr_callback.c              \
        dapl/common/dapl_cr_handoff.c               \
        dapl/common/dapl_ep_connect.c               \
        dapl/common/dapl_ep_create.c                \
        dapl/common/dapl_ep_disconnect.c            \
        dapl/common/dapl_ep_dup_connect.c           \
        dapl/common/dapl_ep_free.c                  \
        dapl/common/dapl_ep_reset.c                 \
        dapl/common/dapl_ep_get_status.c            \
        dapl/common/dapl_ep_modify.c                \
        dapl/common/dapl_ep_post_rdma_read.c        \
        dapl/common/dapl_ep_post_rdma_write.c       \
        dapl/common/dapl_ep_post_recv.c             \
        dapl/common/dapl_ep_post_send.c             \
        dapl/common/dapl_ep_query.c                 \
        dapl/common/dapl_ep_util.c                  \
        dapl/common/dapl_evd_dequeue.c              \
        dapl/common/dapl_evd_free.c                 \
        dapl/common/dapl_evd_post_se.c              \
        dapl/common/dapl_evd_resize.c               \
        dapl/common/dapl_evd_util.c                 \
        dapl/common/dapl_evd_cq_async_error_callb.c \
        dapl/common/dapl_evd_qp_async_error_callb.c \
        dapl/common/dapl_evd_un_async_error_callb.c \
        dapl/common/dapl_evd_connection_callb.c     \
        dapl/common/dapl_evd_dto_callb.c            \
        dapl/common/dapl_get_consumer_context.c     \
        dapl/common/dapl_get_handle_type.c          \
        dapl/common/dapl_hash.c                     \
        dapl/common/dapl_hca_util.c                 \
        dapl/common/dapl_ia_close.c                 \
        dapl/common/dapl_ia_open.c                  \
        dapl/common/dapl_ia_query.c                 \
        dapl/common/dapl_ia_util.c                  \
        dapl/common/dapl_llist.c                    \
        dapl/common/dapl_lmr_free.c                 \
        dapl/common/dapl_lmr_query.c                \
        dapl/common/dapl_lmr_util.c                 \
        dapl/common/dapl_lmr_sync_rdma_read.c       \
        dapl/common/dapl_lmr_sync_rdma_write.c      \
        dapl/common/dapl_mr_util.c                  \
        dapl/common/dapl_provider.c                 \
        dapl/common/dapl_sp_util.c                  \
        dapl/common/dapl_psp_create.c               \
        dapl/common/dapl_psp_create_any.c           \
        dapl/common/dapl_psp_free.c                 \
        dapl/common/dapl_psp_query.c                \
        dapl/common/dapl_pz_create.c                \
        dapl/common/dapl_pz_free.c                  \
        dapl/common/dapl_pz_query.c                 \
        dapl/common/dapl_pz_util.c                  \
        dapl/common/dapl_rmr_create.c               \
        dapl/common/dapl_rmr_free.c                 \
        dapl/common/dapl_rmr_bind.c                 \
        dapl/common/dapl_rmr_query.c                \
        dapl/common/dapl_rmr_util.c                 \
        dapl/common/dapl_rsp_create.c               \
        dapl/common/dapl_rsp_free.c                 \
        dapl/common/dapl_rsp_query.c                \
        dapl/common/dapl_cno_util.c                 \
        dapl/common/dapl_set_consumer_context.c     \
        dapl/common/dapl_ring_buffer_util.c         \
        dapl/common/dapl_name_service.c             \
        dapl/common/dapl_timer_util.c               \
        dapl/common/dapl_ep_create_with_srq.c       \
        dapl/common/dapl_ep_recv_query.c            \
        dapl/common/dapl_ep_set_watermark.c         \
        dapl/common/dapl_srq_create.c               \
        dapl/common/dapl_srq_free.c                 \
        dapl/common/dapl_srq_query.c                \
        dapl/common/dapl_srq_resize.c               \
        dapl/common/dapl_srq_post_recv.c            \
        dapl/common/dapl_srq_set_lw.c               \
        dapl/common/dapl_srq_util.c                 \
        dapl/common/dapl_debug.c                    \
        dapl/common/dapl_ia_ha.c                    \
        dapl/common/dapl_csp.c                      \
        dapl/common/dapl_ep_post_send_invalidate.c  \
        dapl/common/dapl_ep_post_rdma_read_to_rmr.c \
        dapl/openib_common/mem.c                    \
        dapl/openib_common/cq.c                     \
        dapl/openib_common/qp.c                     \
        dapl/openib_common/util.c                   \
        dapl/openib_common/srq.c                    \
        dapl/openib_scm/cm.c                        \
        dapl/openib_scm/device.c $(XPROGRAMS)

dapl_udapl_libdaploscm_la_LDFLAGS = -version-info 2:0:0 $(daploscm_version_script) \
                                   -Wl,-init,dapl_init -Wl,-fini,dapl_fini \
                                   -lpthread -libverbs $(XLIBS)
endif

if DEFINE_UCM                      
#
# uDAPL OpenFabrics UD CM version for IB: libdaplucm.so
#
dapl_udapl_libdaploucm_la_SOURCES = dapl/udapl/dapl_init.c \
        dapl/udapl/dapl_evd_create.c               \
        dapl/udapl/dapl_evd_query.c                \
        dapl/udapl/dapl_cno_create.c               \
        dapl/udapl/dapl_cno_modify_agent.c         \
        dapl/udapl/dapl_cno_free.c                 \
        dapl/udapl/dapl_cno_wait.c                 \
        dapl/udapl/dapl_cno_query.c                \
        dapl/udapl/dapl_lmr_create.c               \
        dapl/udapl/dapl_evd_wait.c                 \
        dapl/udapl/dapl_evd_disable.c              \
        dapl/udapl/dapl_evd_enable.c               \
        dapl/udapl/dapl_evd_modify_cno.c           \
        dapl/udapl/dapl_evd_set_unwaitable.c       \
        dapl/udapl/dapl_evd_clear_unwaitable.c     \
        dapl/udapl/linux/dapl_osd.c                \
        dapl/common/dapl_cookie.c                   \
        dapl/common/dapl_cr_accept.c                \
        dapl/common/dapl_cr_query.c                 \
        dapl/common/dapl_cr_reject.c                \
        dapl/common/dapl_cr_util.c                  \
        dapl/common/dapl_cr_callback.c              \
        dapl/common/dapl_cr_handoff.c               \
        dapl/common/dapl_ep_connect.c               \
        dapl/common/dapl_ep_create.c                \
        dapl/common/dapl_ep_disconnect.c            \
        dapl/common/dapl_ep_dup_connect.c           \
        dapl/common/dapl_ep_free.c                  \
        dapl/common/dapl_ep_reset.c                 \
        dapl/common/dapl_ep_get_status.c            \
        dapl/common/dapl_ep_modify.c                \
        dapl/common/dapl_ep_post_rdma_read.c        \
        dapl/common/dapl_ep_post_rdma_write.c       \
        dapl/common/dapl_ep_post_recv.c             \
        dapl/common/dapl_ep_post_send.c             \
        dapl/common/dapl_ep_query.c                 \
        dapl/common/dapl_ep_util.c                  \
        dapl/common/dapl_evd_dequeue.c              \
        dapl/common/dapl_evd_free.c                 \
        dapl/common/dapl_evd_post_se.c              \
        dapl/common/dapl_evd_resize.c               \
        dapl/common/dapl_evd_util.c                 \
        dapl/common/dapl_evd_cq_async_error_callb.c \
        dapl/common/dapl_evd_qp_async_error_callb.c \
        dapl/common/dapl_evd_un_async_error_callb.c \
        dapl/common/dapl_evd_connection_callb.c     \
        dapl/common/dapl_evd_dto_callb.c            \
        dapl/common/dapl_get_consumer_context.c     \
        dapl/common/dapl_get_handle_type.c          \
        dapl/common/dapl_hash.c                     \
        dapl/common/dapl_hca_util.c                 \
        dapl/common/dapl_ia_close.c                 \
        dapl/common/dapl_ia_open.c                  \
        dapl/common/dapl_ia_query.c                 \
        dapl/common/dapl_ia_util.c                  \
        dapl/common/dapl_llist.c                    \
        dapl/common/dapl_lmr_free.c                 \
        dapl/common/dapl_lmr_query.c                \
        dapl/common/dapl_lmr_util.c                 \
        dapl/common/dapl_lmr_sync_rdma_read.c       \
        dapl/common/dapl_lmr_sync_rdma_write.c      \
        dapl/common/dapl_mr_util.c                  \
        dapl/common/dapl_provider.c                 \
        dapl/common/dapl_sp_util.c                  \
        dapl/common/dapl_psp_create.c               \
        dapl/common/dapl_psp_create_any.c           \
        dapl/common/dapl_psp_free.c                 \
        dapl/common/dapl_psp_query.c                \
        dapl/common/dapl_pz_create.c                \
        dapl/common/dapl_pz_free.c                  \
        dapl/common/dapl_pz_query.c                 \
        dapl/common/dapl_pz_util.c                  \
        dapl/common/dapl_rmr_create.c               \
        dapl/common/dapl_rmr_free.c                 \
        dapl/common/dapl_rmr_bind.c                 \
        dapl/common/dapl_rmr_query.c                \
        dapl/common/dapl_rmr_util.c                 \
        dapl/common/dapl_rsp_create.c               \
        dapl/common/dapl_rsp_free.c                 \
        dapl/common/dapl_rsp_query.c                \
        dapl/common/dapl_cno_util.c                 \
        dapl/common/dapl_set_consumer_context.c     \
        dapl/common/dapl_ring_buffer_util.c         \
        dapl/common/dapl_name_service.c             \
        dapl/common/dapl_timer_util.c               \
        dapl/common/dapl_ep_create_with_srq.c       \
        dapl/common/dapl_ep_recv_query.c            \
        dapl/common/dapl_ep_set_watermark.c         \
        dapl/common/dapl_srq_create.c               \
        dapl/common/dapl_srq_free.c                 \
        dapl/common/dapl_srq_query.c                \
        dapl/common/dapl_srq_resize.c               \
        dapl/common/dapl_srq_post_recv.c            \
        dapl/common/dapl_srq_set_lw.c               \
        dapl/common/dapl_srq_util.c                 \
        dapl/common/dapl_debug.c                    \
        dapl/common/dapl_ia_ha.c                    \
        dapl/common/dapl_csp.c                      \
        dapl/common/dapl_ep_post_send_invalidate.c  \
        dapl/common/dapl_ep_post_rdma_read_to_rmr.c \
        dapl/openib_common/mem.c                    \
        dapl/openib_common/cq.c                     \
        dapl/openib_common/qp.c                     \
        dapl/openib_common/util.c                   \
        dapl/openib_common/srq.c                    \
        dapl/openib_ucm/cm.c                        \
        dapl/openib_ucm/device.c $(XPROGRAMS)

dapl_udapl_libdaploucm_la_LDFLAGS = -version-info 2:0:0 $(daploucm_version_script) \
                                   -Wl,-init,dapl_init -Wl,-fini,dapl_fini \
                                   -lpthread -libverbs $(XLIBS)
endif

if DEFINE_MCM                      
#
# uDAPL OpenFabrics MIC Proxy CM for IB: libdaplmcm.so
#    Proxy MIC Infiniband RDMA via SCIF using mpxyd server 
#
dapl_udapl_libdaplomcm_la_SOURCES = dapl/udapl/dapl_init.c \
        dapl/udapl/dapl_evd_create.c               \
        dapl/udapl/dapl_evd_query.c                \
        dapl/udapl/dapl_cno_create.c               \
        dapl/udapl/dapl_cno_modify_agent.c         \
        dapl/udapl/dapl_cno_free.c                 \
        dapl/udapl/dapl_cno_wait.c                 \
        dapl/udapl/dapl_cno_query.c                \
        dapl/udapl/dapl_lmr_create.c               \
        dapl/udapl/dapl_evd_wait.c                 \
        dapl/udapl/dapl_evd_disable.c              \
        dapl/udapl/dapl_evd_enable.c               \
        dapl/udapl/dapl_evd_modify_cno.c           \
        dapl/udapl/dapl_evd_set_unwaitable.c       \
        dapl/udapl/dapl_evd_clear_unwaitable.c     \
        dapl/udapl/linux/dapl_osd.c                \
        dapl/common/dapl_cookie.c                   \
        dapl/common/dapl_cr_accept.c                \
        dapl/common/dapl_cr_query.c                 \
        dapl/common/dapl_cr_reject.c                \
        dapl/common/dapl_cr_util.c                  \
        dapl/common/dapl_cr_callback.c              \
        dapl/common/dapl_cr_handoff.c               \
        dapl/common/dapl_ep_connect.c               \
        dapl/common/dapl_ep_create.c                \
        dapl/common/dapl_ep_disconnect.c            \
        dapl/common/dapl_ep_dup_connect.c           \
        dapl/common/dapl_ep_free.c                  \
        dapl/common/dapl_ep_reset.c                 \
        dapl/common/dapl_ep_get_status.c            \
        dapl/common/dapl_ep_modify.c                \
        dapl/common/dapl_ep_post_rdma_read.c        \
        dapl/common/dapl_ep_post_rdma_write.c       \
        dapl/common/dapl_ep_post_recv.c             \
        dapl/common/dapl_ep_post_send.c             \
        dapl/common/dapl_ep_query.c                 \
        dapl/common/dapl_ep_util.c                  \
        dapl/common/dapl_evd_dequeue.c              \
        dapl/common/dapl_evd_free.c                 \
        dapl/common/dapl_evd_post_se.c              \
        dapl/common/dapl_evd_resize.c               \
        dapl/common/dapl_evd_util.c                 \
        dapl/common/dapl_evd_cq_async_error_callb.c \
        dapl/common/dapl_evd_qp_async_error_callb.c \
        dapl/common/dapl_evd_un_async_error_callb.c \
        dapl/common/dapl_evd_connection_callb.c     \
        dapl/common/dapl_evd_dto_callb.c            \
        dapl/common/dapl_get_consumer_context.c     \
        dapl/common/dapl_get_handle_type.c          \
        dapl/common/dapl_hash.c                     \
        dapl/common/dapl_hca_util.c                 \
        dapl/common/dapl_ia_close.c                 \
        dapl/common/dapl_ia_open.c                  \
        dapl/common/dapl_ia_query.c                 \
        dapl/common/dapl_ia_util.c                  \
        dapl/common/dapl_llist.c                    \
        dapl/common/dapl_lmr_free.c                 \
        dapl/common/dapl_lmr_query.c                \
        dapl/common/dapl_lmr_util.c                 \
        dapl/common/dapl_lmr_sync_rdma_read.c       \
        dapl/common/dapl_lmr_sync_rdma_write.c      \
        dapl/common/dapl_mr_util.c                  \
        dapl/common/dapl_provider.c                 \
        dapl/common/dapl_sp_util.c                  \
        dapl/common/dapl_psp_create.c               \
        dapl/common/dapl_psp_create_any.c           \
        dapl/common/dapl_psp_free.c                 \
        dapl/common/dapl_psp_query.c                \
        dapl/common/dapl_pz_create.c                \
        dapl/common/dapl_pz_free.c                  \
        dapl/common/dapl_pz_query.c                 \
        dapl/common/dapl_pz_util.c                  \
        dapl/common/dapl_rmr_create.c               \
        dapl/common/dapl_rmr_free.c                 \
        dapl/common/dapl_rmr_bind.c                 \
        dapl/common/dapl_rmr_query.c                \
        dapl/common/dapl_rmr_util.c                 \
        dapl/common/dapl_rsp_create.c               \
        dapl/common/dapl_rsp_free.c                 \
        dapl/common/dapl_rsp_query.c                \
        dapl/common/dapl_cno_util.c                 \
        dapl/common/dapl_set_consumer_context.c     \
        dapl/common/dapl_ring_buffer_util.c         \
        dapl/common/dapl_name_service.c             \
        dapl/common/dapl_timer_util.c               \
        dapl/common/dapl_ep_create_with_srq.c       \
        dapl/common/dapl_ep_recv_query.c            \
        dapl/common/dapl_ep_set_watermark.c         \
        dapl/common/dapl_srq_create.c               \
        dapl/common/dapl_srq_free.c                 \
        dapl/common/dapl_srq_query.c                \
        dapl/common/dapl_srq_resize.c               \
        dapl/common/dapl_srq_post_recv.c            \
        dapl/common/dapl_srq_set_lw.c               \
        dapl/common/dapl_srq_util.c                 \
        dapl/common/dapl_debug.c                    \
        dapl/common/dapl_ia_ha.c                    \
        dapl/common/dapl_csp.c                      \
        dapl/common/dapl_ep_post_send_invalidate.c  \
        dapl/common/dapl_ep_post_rdma_read_to_rmr.c \
        dapl/openib_common/mem.c                    \
        dapl/openib_common/cq.c                     \
        dapl/openib_common/qp.c                     \
        dapl/openib_common/util.c                   \
        dapl/openib_common/srq.c                    \
        dapl/openib_mcm/cm.c                        \
        dapl/openib_mcm/mix.c                       \
        dapl/openib_mcm/proxy.c                     \
        dapl/openib_mcm/device.c $(XPROGRAMS)

dapl_udapl_libdaplomcm_la_LDFLAGS = -version-info 2:0:0 $(daplomcm_version_script) \
                                   -Wl,-init,dapl_init -Wl,-fini,dapl_fini \
                                   -lpthread -libverbs -lscif $(XLIBS)
endif

libdatincludedir = $(includedir)/dat2

libdatinclude_HEADERS = dat/include/dat2/dat.h \
			dat/include/dat2/dat_error.h \
			dat/include/dat2/dat_platform_specific.h \
			dat/include/dat2/dat_redirection.h \
			dat/include/dat2/dat_registry.h \
			dat/include/dat2/dat_vendor_specific.h \
			dat/include/dat2/udat_config.h \
			dat/include/dat2/udat.h \
			dat/include/dat2/udat_redirection.h \
			dat/include/dat2/udat_vendor_specific.h $(XDAT)
					
man_MANS = man/dtest.1 man/dapltest.1 man/dat.conf.5 man/dtestsrq.1 man/dtestcm.1 man/dtestx.1 
    	
EXTRA_DIST = dat/common/dat_dictionary.h \
	     dat/common/dat_dr.h \
	     dat/common/dat_init.h \
	     dat/common/dat_sr.h \
	     dat/udat/udat_sr_parser.h \
	     dat/udat/linux/dat_osd.h \
	     dat/include/dat2/dat.h \
	     dat/include/dat2/dat_error.h \
	     dat/include/dat2/dat_platform_specific.h \
	     dat/include/dat2/dat_redirection.h \
	     dat/include/dat2/dat_registry.h \
	     dat/include/dat2/dat_vendor_specific.h \
	     dat/include/dat2/udat_config.h \
	     dat/include/dat2/udat.h \
	     dat/include/dat2/udat_redirection.h \
	     dat/include/dat2/udat_vendor_specific.h \
	     dat/include/dat2/dat_ib_extensions.h \
	     dapl/common/dapl_adapter_util.h \
	     dapl/common/dapl_cno_util.h \
	     dapl/common/dapl_cookie.h \
	     dapl/common/dapl_cr_util.h \
	     dapl/common/dapl_ep_util.h \
	     dapl/common/dapl_evd_util.h \
	     dapl/common/dapl_hash.h \
	     dapl/common/dapl_hca_util.h \
	     dapl/common/dapl_ia_util.h \
	     dapl/common/dapl_init.h \
	     dapl/common/dapl_lmr_util.h \
	     dapl/common/dapl_mr_util.h \
	     dapl/common/dapl_name_service.h \
	     dapl/common/dapl_provider.h \
	     dapl/common/dapl_pz_util.h \
	     dapl/common/dapl_ring_buffer_util.h \
	     dapl/common/dapl_rmr_util.h \
	     dapl/common/dapl_sp_util.h \
	     dapl/common/dapl_srq_util.h \
	     dapl/common/dapl_timer_util.h \
	     dapl/udapl/linux/dapl_osd.h \
	     dapl/include/dapl.h \
	     dapl/include/dapl_debug.h \
	     dapl/include/dapl_ipoib_names.h \
	     dapl/include/dapl_vendor.h \
	     dapl/openib_common/dapl_ib_dto.h \
	     dapl/openib_common/dapl_ib_common.h \
	     dapl/openib_common/dapl_mic_common.h \
	     dapl/openib_common/collectives/ib_collectives.h \
	     dapl/openib_common/collectives/fca_provider.h \
	     dapl/openib_cma/dapl_ib_util.h \
	     dapl/openib_cma/linux/openib_osd.h \
	     dapl/openib_scm/dapl_ib_util.h \
	     dapl/openib_scm/linux/openib_osd.h \
     	     dapl/openib_ucm/dapl_ib_util.h \
	     dapl/openib_ucm/linux/openib_osd.h \
	     dapl/openib_mcm/dapl_ib_util.h \
	     dapl/openib_mcm/linux/openib_osd.h \
	     dapl/svc/mpxyd.h \
	     dat/udat/libdat2.map \
	     dapl/udapl/libdaplofa.map \
	     dapl/udapl/libdaploscm.map \
	     dapl/udapl/libdaploucm.map \
	     dapl/udapl/libdaplomcm.map \
	     README \
	     README.mcm \
	     LICENSE.txt \
	     LICENSE.txt \
	     LICENSE2.txt \
	     LICENSE3.txt \
	     doc/dat.conf \
	     doc/mpxyd.conf \
	     dapl.spec.in \
	     mpxyd.init.in \
	     $(man_MANS) \
	     test/scripts/dtest_suite.sh \
	     test/dapltest/scripts/cl.sh \
	     test/dapltest/scripts/srv.sh \
	     test/dapltest/scripts/regress.sh \
	     test/dapltest/include/dapl_bpool.h \
	     test/dapltest/include/dapl_client_info.h \
	     test/dapltest/include/dapl_common.h \
	     test/dapltest/include/dapl_execute.h \
	     test/dapltest/include/dapl_fft_cmd.h \
	     test/dapltest/include/dapl_fft_util.h \
	     test/dapltest/include/dapl_getopt.h \
	     test/dapltest/include/dapl_global.h \
	     test/dapltest/include/dapl_limit_cmd.h \
	     test/dapltest/include/dapl_mdep.h \
	     test/dapltest/include/dapl_memlist.h \
	     test/dapltest/include/dapl_params.h \
	     test/dapltest/include/dapl_performance_cmd.h \
	     test/dapltest/include/dapl_performance_stats.h \
	     test/dapltest/include/dapl_performance_test.h \
	     test/dapltest/include/dapl_proto.h \
	     test/dapltest/include/dapl_quit_cmd.h \
	     test/dapltest/include/dapl_server_cmd.h \
	     test/dapltest/include/dapl_server_info.h \
	     test/dapltest/include/dapl_tdep.h \
	     test/dapltest/include/dapl_tdep_print.h \
	     test/dapltest/include/dapl_test_data.h \
	     test/dapltest/include/dapl_transaction_cmd.h \
	     test/dapltest/include/dapl_transaction_stats.h \
	     test/dapltest/include/dapl_transaction_test.h \
	     test/dapltest/include/dapl_version.h \
	     test/dapltest/mdep/linux/dapl_mdep_user.h
	 
if DEFINE_MCM
sbin_PROGRAMS = svc/mpxyd
svc_mpxyd_SOURCES = dapl/svc/mpxyd.c \
		dapl/svc/util.c \
		dapl/svc/mix.c \
		dapl/svc/mcm.c \
		dapl/svc/mpxy_out.c \
		dapl/svc/mpxy_in.c
svc_mpxyd_CFLAGS = $(AM_CFLAGS) -lscif -libverbs -lpthread -Idat/include -I$(srcdir)/dapl/openib_common
sysconf_DATA += doc/mpxyd.conf

install-exec-hook:
	install -D -m 755 mpxyd.init $(DESTDIR)$(sysconfdir)/init.d/mpxyd;
	echo %{_sbindir}/mpxyd > mcm-files
	echo %{_sysconfdir}/init.d/mpxyd >> mcm-files
	echo %{_sysconfdir}/mpxyd.conf >> mcm-files
endif

dist-hook: dapl.spec 
	cp dapl.spec $(distdir)/

rpmcheck: dapl.spec dist
	mkdir -p rpmbuild/{SOURCES,BUILD,RPMS,SPECS,BUILDROOT}
	cp $(distdir).tar.gz rpmbuild/SOURCES

srcrpms: rpmcheck
	rpmbuild -bs --define "_topdir ${PWD}/rpmbuild" dapl.spec

rpms: rpmcheck
	rpmbuild -ba --define "_topdir ${PWD}/rpmbuild" dapl.spec

SUBDIRS = . test/dtest test/dapltest
