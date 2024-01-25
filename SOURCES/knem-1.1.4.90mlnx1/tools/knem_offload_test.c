/*
 * Copyright © inria 2009-2010
 * Brice Goglin <Brice.Goglin@inria.fr>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _GNU_SOURCE 1 /* for sched.h */
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sched.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sched.h>

#include <hwloc.h>
#ifndef HWLOC_BITMAP_H
#define hwloc_bitmap_dup hwloc_cpuset_dup
#define hwloc_bitmap_free hwloc_cpuset_free
#define hwloc_bitmap_andnot hwloc_cpuset_andnot
#define hwloc_bitmap_iszero hwloc_cpuset_iszero
#define hwloc_bitmap_singlify hwloc_cpuset_singlify
#define hwloc_bitmap_asprintf hwloc_cpuset_asprintf
#endif
#include <hwloc/glibc-sched.h>

#include "knem_io.h"

#define DEFAULT_LEN_MB 128

static void
usage(char *argv[])
{
  fprintf(stderr, "%s [options]\n", argv[0]);
  fprintf(stderr, "Iteration configuration:\n");
  fprintf(stderr, " -l <n>\tchange the message length in megabytes [%d]\n", DEFAULT_LEN_MB);
}

static int
bind_knem_kthread(int fd, hwloc_topology_t topology, hwloc_const_cpuset_t hset)
{
  struct knem_cmd_bind_offload bind_offload;
  cpu_set_t gset;
  int err;
  err = hwloc_cpuset_to_glibc_sched_affinity(topology, hset, &gset, sizeof(gset));
  if (err < 0) {
    perror("hwloc_cpuset_to_glibc_sched_affinity");
    return err;
  }

  bind_offload.flags = KNEM_BIND_FLAG_CUSTOM;
  bind_offload.mask_len = sizeof(gset);
  bind_offload.mask_ptr = (uintptr_t) &gset;
  err = ioctl(fd, KNEM_CMD_BIND_OFFLOAD, &bind_offload);
  if (err < 0) {
    perror("ioctl bind-offload");
    return err;
  }

  return 0;
}

static int
one_offload_test(hwloc_topology_t topology, hwloc_cpuset_t hset, unsigned long len_MB)
{
  struct knem_cmd_info info;
  struct knem_cmd_param_iovec siovec, riovec;
  struct knem_cmd_create_region screate, rcreate;
  struct knem_cmd_copy_bounded copy;
  void *sbuf, *rbuf;
  struct timeval tv1, tv2;
  volatile knem_status_t *status_array;
  unsigned long long ns;
  char *str;
  int fd;
  int err;
  char dummy;
  unsigned long long i;
  unsigned long iter = 0;

  hwloc_bitmap_singlify(hset);

  hwloc_bitmap_asprintf(&str, hset);
  printf("Running test with binding %s\n", str);
  free(str);

  sbuf = malloc(len_MB*1048576*2);
  if (!sbuf) {
    perror("malloc");
    goto out;
  }
  rbuf = sbuf+len_MB*1048576;

  fd = open("/dev/knem", O_RDWR);
  if (fd < 0) {
    perror("open");
    goto out_with_buf;
  }

  err = ioctl(fd, KNEM_CMD_GET_INFO, &info);
  if (err < 0) {
    perror("ioctl (get info)");
    goto out_with_fd;
  }

  if (info.abi != KNEM_ABI_VERSION) {
    printf("got driver ABI %lx instead of %lx\n",
           (unsigned long) info.abi, (unsigned long) KNEM_ABI_VERSION);
    goto out_with_fd;
  }

  err = bind_knem_kthread(fd, topology, hset);
  if (err < 0)
    goto out_with_fd;

  status_array = mmap(NULL, 1, PROT_READ|PROT_WRITE, MAP_SHARED, fd, KNEM_STATUS_ARRAY_FILE_OFFSET);
  if (status_array == MAP_FAILED) {
    perror("mmap status_array");
    goto out_with_fd;
  }

  siovec.base = (uintptr_t) sbuf;
  siovec.len = len_MB*1048576;
  screate.iovec_array = (uintptr_t) &siovec;
  screate.iovec_nr = 1;
  screate.flags = 0;
  screate.protection = PROT_READ;
  err = ioctl(fd, KNEM_CMD_CREATE_REGION, &screate);
  if (err < 0) {
    perror("ioctl (create send region)");
    goto out_with_fd;
  }

  riovec.base = (uintptr_t) sbuf + len_MB*1048576;
  riovec.len = len_MB*1048576;
  rcreate.iovec_array = (uintptr_t) &riovec;
  rcreate.iovec_nr = 1;
  rcreate.flags = 0;
  rcreate.protection = PROT_WRITE;
  err = ioctl(fd, KNEM_CMD_CREATE_REGION, &rcreate);
  if (err < 0) {
    perror("ioctl (create recv region)");
    goto out_with_fd;
  }


  gettimeofday(&tv1, NULL);

  memset(sbuf, 0, len_MB*1048576);

  copy.src_cookie = screate.cookie;
  copy.src_offset = 0;
  copy.dst_cookie = rcreate.cookie;
  copy.dst_offset = 0;
  copy.length = len_MB*1048576;
  copy.flags = KNEM_FLAG_MEMCPYTHREAD;
  copy.async_status_index = 0;
  err = ioctl(fd, KNEM_CMD_COPY_BOUNDED, &copy);
  if (err < 0) {
    perror("ioctl (copy)");
    goto out_with_fd;
  }
  if (copy.current_status == KNEM_STATUS_PENDING) {
    while (status_array[copy.async_status_index] == KNEM_STATUS_PENDING)
      iter++;
    if (status_array[copy.async_status_index] != KNEM_STATUS_SUCCESS) {
      fprintf(stderr, "got status %d instead of %d\n", status_array[copy.async_status_index], KNEM_STATUS_SUCCESS);
      goto out_with_fd;
    }
  } else if (copy.current_status != KNEM_STATUS_SUCCESS) {
    fprintf(stderr, "got status %d instead of %d\n", copy.current_status, KNEM_STATUS_SUCCESS);
    goto out_with_fd;
  }

  dummy = 0;
  for(i=0; i<len_MB*1048576; i++)
    dummy += ((char *) rbuf)[i];
  /* make sure dummy doesn't get optimized out */
  if (dummy == 6)
    printf("got lucky\n");

  gettimeofday(&tv2, NULL);

  ns = (tv2.tv_sec-tv1.tv_sec)*1000000000ULL + (tv2.tv_usec-tv1.tv_usec)*1000;
  printf("Copied %ld megabytes in %lld ns => %f GB/s\n", (unsigned long) len_MB, ns, len_MB*1048576/(float) ns);
  printf("Overlapped %lu loops while processing the copy\n", iter);

  close(fd);
  free(sbuf);
  return 0;

 out_with_fd:
  close(fd);
 out_with_buf:
  free(sbuf);
 out:
  return -1;
}

int main(int argc, char *argv[])
{
  hwloc_topology_t topology;
  hwloc_obj_t obj, prev;
  unsigned long len_MB = DEFAULT_LEN_MB;
  int err;
  char c;

  while ((c = getopt(argc, argv, "l:h")) != -1)
    switch (c) {
    case 'l':
      len_MB = atoi(optarg);
      break;
    default:
      fprintf(stderr, "Unknown option -%c\n", c);
      /* fallthru */
    case 'h':
      usage(argv);
      exit(-1);
      break;
    }

  err = hwloc_topology_init(&topology);
  if (err < 0)
    goto out;
  err = hwloc_topology_load(topology);
  if (err < 0)
    goto out_with_topology;

  obj = hwloc_get_obj_by_type(topology, HWLOC_OBJ_PU, 0);
  assert(obj);
  prev = obj;

  err = hwloc_set_cpubind(topology, obj->cpuset, HWLOC_CPUBIND_THREAD);
  assert(!err);

  /* test on the very same PU */
  printf("Inside same PU:\n");
  one_offload_test(topology, obj->cpuset, len_MB);

  /* test on brothers, cousins, ... up to the top of the topology */
  while (obj) {
    char str1[64], str2[64];
    hwloc_cpuset_t cpuset;

    cpuset = hwloc_bitmap_dup(obj->cpuset);
    hwloc_bitmap_andnot(cpuset, cpuset, prev->cpuset);
    if (hwloc_bitmap_iszero(cpuset)) {
      hwloc_bitmap_free(cpuset);
      obj = obj->parent;
      continue;
    }

    hwloc_obj_type_snprintf(str1, sizeof(str1), obj, 1);
    hwloc_obj_type_snprintf(str2, sizeof(str2), prev, 1);
    printf("\nInside same %s but not in same %s:\n", str1, str2);
    one_offload_test(topology, cpuset, len_MB);

    hwloc_bitmap_free(cpuset);

    prev = obj;
    obj = obj->parent;
  }

 out_with_topology:
  hwloc_topology_destroy(topology);
 out:
  return 0;
}
