#!/bin/sh

# Copyright © inria 2009-2010
# Brice Goglin <Brice.Goglin@inria.fr>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

FORCE=0

if test $# -ge 1 && test "$1" = "--force" ; then
  FORCE=1
  shift
fi

if test $# -lt 4 ; then
  echo "Options:"
  echo "  --force	Check again even if the arguments did not change"
  echo "Need 4 command line arguments:"
  echo "  - header checks output file"
  echo "  - kernel build path"
  echo "  - kernel headers path"
  echo "  - kernel release"
  exit -1
fi

CHECKS_NAME="$1"
LINUX_BUILD="$2"
LINUX_HDR="$3"
LINUX_RELEASE="$4"

CONFIG_LINE="Ran with BUILD=\"$LINUX_BUILD\" HDR=\"$LINUX_HDR\" RELEASE=\"$LINUX_RELEASE\""
if test "$FORCE" != 1 && grep "$CONFIG_LINE" "$CHECKS_NAME" >/dev/null 2>&1; then
  # no need to rerun
  exit 0
fi

# create the output file
CHECKS_DATE_PREFIX="This file has been first generated on "
TMP_CHECKS_NAME=${CHECKS_NAME}.tmp
rm -f ${TMP_CHECKS_NAME}

# add the header
echo "#ifndef __knem_checks_h__" >> ${TMP_CHECKS_NAME}
echo "#define __knem_checks_h__ 1" >> ${TMP_CHECKS_NAME}
echo "" >> ${TMP_CHECKS_NAME}

# what command line was used to generate with file
echo "/*" >> ${TMP_CHECKS_NAME}
echo " * ${CHECKS_DATE_PREFIX}"`date` >> ${TMP_CHECKS_NAME}
echo " * ${CONFIG_LINE}" >> ${TMP_CHECKS_NAME}
echo " * It checked kernel headers in ${LINUX_HDR}/include/" >> ${TMP_CHECKS_NAME}
echo " */" >> ${TMP_CHECKS_NAME}
echo "" >> ${TMP_CHECKS_NAME}

# vmalloc_user appeared in 2.6.18 but was broken until 2.6.19
echo -n "  checking (in kernel headers) vmalloc_user() availability... "
if grep "vmalloc_user *(" ${LINUX_HDR}/include/linux/vmalloc.h > /dev/null ; then
  if grep "LINUX_VERSION_CODE 132626" ${LINUX_BUILD}/include/linux/version.h > /dev/null 2>&1 ; then
    echo broken, ignoring
  else
    echo "#define KNEM_HAVE_VMALLOC_USER 1" >> ${TMP_CHECKS_NAME}
    echo yes
  fi
else
  echo no
fi

# remap_vmalloc_range appeared in 2.6.18
echo -n "  checking (in kernel headers) remap_vmalloc_range() availability ... "
if grep "remap_vmalloc_range *(" ${LINUX_HDR}/include/linux/vmalloc.h > /dev/null ; then
  echo "#define KNEM_HAVE_REMAP_VMALLOC_RANGE 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# get_user_pages_fast added in 2.6.27
echo -n "  checking (in kernel headers) get_user_pages_fast() availability ... "
if grep get_user_pages_fast ${LINUX_HDR}/include/linux/mm.h > /dev/null ; then
  echo "#define KNEM_HAVE_GET_USER_PAGES_FAST 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# cpumask_pr_args added in 3.20, and cpumask_scnprintf removed
echo -n "  checking (in kernel headers) cpumask_pr_args() availability ... "
if grep cpumask_pr_args ${LINUX_HDR}/include/linux/cpumask.h > /dev/null ; then
  echo yes
  echo "#define KNEM_HAVE_CPUMASK_PR_ARGS 1" >> ${TMP_CHECKS_NAME}
else
  echo no
  # cpumask_scnprintf uses a cpumask pointer starting in 2.6.29
  echo -n "  checking (in kernel headers) whether cpumask_scnprintf() takes a cpumask pointer ... "
  if sed -ne '/static inline int cpumask_scnprintf(/,/)/p' ${LINUX_HDR}/include/linux/cpumask.h | grep "const struct cpumask *" > /dev/null ; then
    echo "#define KNEM_CPUMASK_SCNPRINTF_USES_PTR 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo no
  fi
fi

# cpumask_of_node added in 2.6.29
echo -n "  checking (in kernel headers) cpumask_of_node() availability ... "
if grep cpumask_of_node ${LINUX_HDR}/include/asm-generic/topology.h > /dev/null ; then
  echo "#define KNEM_HAVE_CPUMASK_OF_NODE 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# cpumask_complement deprecates cpus_complement in 2.6.27, and the latter is removed in 2.6.32
echo -n "  checking (in kernel headers) cpumask_complement() availability ... "
if grep cpumask_complement ${LINUX_HDR}/include/linux/cpumask.h > /dev/null ; then
  echo "#define KNEM_HAVE_CPUMASK_COMPLEMENT 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# set_cpus_allowed_ptr added in 2.6.26, and set_cpus_allowed dropped in 2.6.34
# set_cpus_allowed_ptr backported in redhat 5 kernels but not exported to modules
echo -n "  checking (in kernel headers) set_cpus_allowed_ptr() ... "
if grep set_cpus_allowed_ptr ${LINUX_HDR}/include/linux/sched.h > /dev/null ; then
  if grep "LINUX_VERSION_CODE 132626" ${LINUX_BUILD}/include/linux/version.h > /dev/null 2>&1 ; then
    echo broken, ignoring
  else
    echo "#define KNEM_HAVE_SET_CPUS_ALLOWED_PTR 1" >> ${TMP_CHECKS_NAME}
    echo yes
  fi
else
  echo no
fi

# idr became RCU-ready since 2.6.27
echo -n "  checking (in kernel headers) whether the idr interface is RCU-ready ... "
if grep rcupdate.h ${LINUX_HDR}/include/linux/idr.h > /dev/null ||
   grep radix-tree.h ${LINUX_HDR}/include/linux/idr.h > /dev/null ; then
  echo "#define KNEM_HAVE_RCU_IDR 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# idr_preload added in 3.9
echo -n "  checking (in kernel headers) idr_preload() availability ... "
if grep idr_preload ${LINUX_HDR}/include/linux/idr.h > /dev/null ; then
  echo "#define KNEM_HAVE_IDR_PRELOAD 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# ida added in 2.6.23
echo -n "  checking (in kernel headers) the ida interface ... "
if grep ida_get_new ${LINUX_HDR}/include/linux/idr.h > /dev/null ; then
  echo "#define KNEM_HAVE_IDA 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# work_struct lost its data field in 2.6.20
echo -n "  checking (in kernel headers) whether work_struct contains a data field ... "
if sed -ne '/^struct work_struct {/,/^};/p' ${LINUX_HDR}/include/linux/workqueue.h \
  | grep "void \*data;" > /dev/null ; then
  echo "#define KNEM_HAVE_WORK_STRUCT_DATA 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# k[un]map_atomic doesn't want a type since 3.4
echo -n "  checking (in kernel headers) whether kmap_atomic() needs a type ... "
if grep KM_USER1 ${LINUX_HDR}/include/linux/highmem.h > /dev/null ; then
  echo "#define KNEM_HAVE_KMAP_ATOMIC_TYPE 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# dmaengine API reworked in 2.6.29
echo -n "  checking (in kernel headers) the dmaengine interface ... "
if test -e ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
  if grep dmaengine_get ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
    echo "#define KNEM_HAVE_DMA_ENGINE_API 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo "#define KNEM_HAVE_OLD_DMA_ENGINE_API 1" >> ${TMP_CHECKS_NAME}
    echo "yes, the old one"
  fi
else
  echo no
fi

# is_dma_copy_aligned added in 2.6.32
echo -n "  checking (in kernel headers) is_dma_copy_aligned availability ... "
if test -e ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
  if grep is_dma_copy_aligned ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
    echo "#define KNEM_HAVE_IS_DMA_COPY_ALIGNED 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo no
  fi
else
  echo no
fi

# dma_async_memcpy_issue_pending removed in 3.9
# dma_async_issue_pending added in the meantime
echo -n "  checking (in kernel headers) dma_async_issue_pending() availability ... "
if test -e ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
  if grep dma_async_issue_pending ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
    echo "#define KNEM_HAVE_DMA_ASYNC_ISSUE_PENDING 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo no
  fi
else
  echo no
fi

# dma_async_memcpy_complete removed in 3.9
# dma_async_is_tx_complete added in the meantime
echo -n "  checking (in kernel headers) dma_async_is_tx_complete() availability ... "
if test -e ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
  if grep dma_async_is_tx_complete ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
    echo "#define KNEM_HAVE_DMA_ASYNC_IS_TX_COMPLETE 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo no
  fi
else
  echo no
fi

# DMA_SUCCESS renamed into DMA_COMPLETE in 3.13
echo -n "  checling (in kernel headers) DMA_COMPLETE availability ... "
if test -e ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
  if grep DMA_COMPLETE ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
    echo "#define KNEM_HAVE_DMA_COMPLETE 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo no
  fi
else
  echo no
fi

# dma_async_memcpy_pg_to_pg removed with netdma in 3.18
echo -n "  checking (in kernel headers) dma_async_memcpy_pg_to_pg() availability ... "
if test -e ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
  if grep dma_async_memcpy_pg_to_pg ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
    echo "#define KNEM_HAVE_DMA_ASYNC_MEMCPY_PG_TO_PG 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo no
  fi
else
  echo no
fi

# dmaengine_get_unmap_data added in 3.13
echo -n "  checking (in kernel headers) dmaengine_get_unmap_data() availability ... "
if test -e ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
  if grep dmaengine_get_unmap_data ${LINUX_HDR}/include/linux/dmaengine.h > /dev/null ; then
    echo "#define KNEM_HAVE_DMAENGINE_GET_UNMAP_DATA 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo no
  fi
else
  echo no
fi

# current_uid() added in 2.6.27
echo -n "  checking (in kernel headers) current_uid() availability ... "
if test -e ${LINUX_HDR}/include/linux/cred.h > /dev/null ; then
  if grep current_uid ${LINUX_HDR}/include/linux/cred.h > /dev/null ; then
    echo "#define KNEM_HAVE_CURRENT_UID 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo no
  fi
else
  echo no
fi

# cred uses kuid_t since 3.5
echo -n "  checking (in kernel headers) whether cred uses kuid_t fields ... "
if test -e ${LINUX_HDR}/include/linux/cred.h > /dev/null ; then
  if sed -ne '/^struct cred {/,/^};/p' ${LINUX_HDR}/include/linux/cred.h \
    | grep kuid_t > /dev/null ; then
    echo "#define KNEM_HAVE_CRED_KUID 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo no
  fi
else
  echo no
fi

# printk_once() added in 2.6.30, and moved to the new printk.h in 2.6.37
echo -n "  checking (in kernel headers) printk_once() availability ... "
if grep printk_once ${LINUX_HDR}/include/linux/kernel.h >/dev/null ||
   grep printk_once ${LINUX_HDR}/include/linux/printk.h > /dev/null 2>/dev/null ; then
  echo "#define KNEM_HAVE_PRINTK_ONCE 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# timer_setup() added in v4.14-rc3, setup_timer() removed in 4.14
echo -n "  checking (in kernel headers) timer_setup() availability ... "
if test -e ${LINUX_HDR}/include/linux/timer.h > /dev/null ; then
  if grep timer_setup ${LINUX_HDR}/include/linux/timer.h > /dev/null ; then
    echo "#define HAVE_TIMER_SETUP 1" >> ${TMP_CHECKS_NAME}
    echo yes
  else
    echo no
  fi
else
  echo no
fi

# get_user_pages_fast() replaced the write bool with flags in 5.2
echo -n "  checking (in kernel headers) whether get_user_pages_fast() wants flags ... "
if sed -ne '/^int get_user_pages_fast(/,/);/p' ${LINUX_HDR}/include/linux/mm.h \
  | egrep "unsigned int gup_flags" > /dev/null ; then
  echo "#define KNEM_GUP_FAST_FLAGS 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# task_struct cpus_allowed replaced with cpus_mask in 5.3
echo -n "  checking (in kernel headers) whether task_struct contains a cpus_mask field ... "
if sed -ne '/^struct task_struct {/,/^};/p' ${LINUX_HDR}/include/linux/sched.h \
  | egrep "cpumask_t[ 	]+cpus_mask" > /dev/null ; then
  echo "#define KNEM_HAVE_TASK_CPUS_MASK 1" >> ${TMP_CHECKS_NAME}
  echo yes
else
  echo no
fi

# add the footer
echo "" >> ${TMP_CHECKS_NAME}
echo "#endif /* __knem_checks_h__ */" >> ${TMP_CHECKS_NAME}

# install final file
if diff -q ${CHECKS_NAME} ${TMP_CHECKS_NAME} --ignore-matching-lines="${CHECKS_DATE_PREFIX}" >/dev/null 2>&1; then
  echo "  driver/linux/${CHECKS_NAME} is unchanged"
  rm -f ${TMP_CHECKS_NAME}
else
  echo "  creating driver/linux/${CHECKS_NAME}"
  mv -f ${TMP_CHECKS_NAME} ${CHECKS_NAME}
fi
