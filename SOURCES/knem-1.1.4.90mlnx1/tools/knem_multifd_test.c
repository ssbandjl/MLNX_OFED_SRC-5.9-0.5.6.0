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

#include "knem_io.h"

#define LEN 4096

static void
usage(char *argv[])
{
  fprintf(stderr, "%s [options]\n", argv[0]);
  fprintf(stderr, " -A <n>\tchange send/recv buffer relative alignments [%d]\n", 0);
  fprintf(stderr, " -d\tenable DMA engine\n");
  fprintf(stderr, " -F <n>\tadd copy command flags\n");
}

int main(int argc, char * argv[])
{
  knem_cookie_t cookie1, cookie2;
  struct knem_cmd_info info;
  int fd1, fd2, err;
  char *send_buffer, *recv_buffer;
  struct knem_cmd_param_iovec send_iovec[2], recv_iovec[2];
  struct knem_cmd_create_region create;
  struct knem_cmd_inline_copy icopy;
  unsigned long missalign = 0;
  unsigned long flags = 0;
  volatile knem_status_t *sarray1, *sarray2;
  char c;

  while ((c = getopt(argc, argv, "A:dF:h")) != -1)
    switch (c) {
    case 'A':
      missalign = atoi(optarg);
      break;
    case 'F':
      flags |= atoi(optarg);
      break;
    case 'd':
      flags |= KNEM_FLAG_DMA;
      break;
    default:
      fprintf(stderr, "Unknown option -%c\n", c);
      /* fallthru */
    case 'h':
      usage(argv);
      exit(-1);
      break;
    }

  send_buffer = malloc(LEN*2+missalign);
  if (!send_buffer)
    goto out;
  recv_buffer = send_buffer+LEN+missalign;

  send_iovec[0].base = (uintptr_t) send_buffer;
  send_iovec[0].len = LEN/2;
  send_iovec[1].base = (uintptr_t) send_buffer + LEN/2;
  send_iovec[1].len = LEN/2;

  recv_iovec[0].base = (uintptr_t) recv_buffer;
  recv_iovec[0].len = LEN/2;
  recv_iovec[1].base = (uintptr_t) recv_buffer + LEN/2;
  recv_iovec[1].len = LEN/2;

  fd1 = open("/dev/knem", O_RDWR);
  if (fd1 < 0) {
    perror("open1");
    goto out_with_buffer;
  }

  err = ioctl(fd1, KNEM_CMD_GET_INFO, &info);
  if (err < 0) {
    perror("ioctl (get info) 1");
    goto out_with_fd1;
  }

  if (info.abi != KNEM_ABI_VERSION) {
    printf("got driver ABI %lx instead of %lx\n",
	   (unsigned long) info.abi, (unsigned long) KNEM_ABI_VERSION);
    goto out_with_fd1;
  }

  printf("got driver ABI %lx and feature mask %lx\n",
	 (unsigned long) info.abi, (unsigned long) info.features);

  if (flags & KNEM_FLAG_DMA && !(info.features & KNEM_FEATURE_DMA)) {
    fprintf(stderr, "DMA support not available, ignoring it\n");
    flags &= ~KNEM_FLAG_DMA;
  }

  fd2 = open("/dev/knem", O_RDWR);
  if (fd2 < 0) {
    perror("open2");
    goto out_with_fd1;
  }

  err = ioctl(fd2, KNEM_CMD_GET_INFO, &info);
  if (err < 0) {
    perror("ioctl (get info) 2");
    goto out_with_fd;
  }

  if (info.abi != KNEM_ABI_VERSION) {
    printf("got driver ABI %lx instead of %lx\n",
	   (unsigned long) info.abi, (unsigned long) KNEM_ABI_VERSION);
    goto out_with_fd;
  }

  printf("got driver ABI %lx and feature mask %lx\n",
	 (unsigned long) info.abi, (unsigned long) info.features);

  if (flags & KNEM_FLAG_DMA && !(info.features & KNEM_FEATURE_DMA)) {
    fprintf(stderr, "DMA support not available, ignoring it\n");
    flags &= ~KNEM_FLAG_DMA;
  }



  create.iovec_array = (uintptr_t) send_iovec;
  create.iovec_nr = 1;
  create.flags = KNEM_FLAG_SINGLEUSE;
  create.protection = PROT_READ;
  err = ioctl(fd1, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create region) 1");
    goto out_with_fd;
  }
  printf("got lid %llx\n", (unsigned long long) create.cookie);
  cookie1 = create.cookie;

  create.iovec_array = (uintptr_t) (send_iovec+1);
  create.iovec_nr = 1;
  create.flags = KNEM_FLAG_SINGLEUSE;
  create.protection = PROT_READ;
  err = ioctl(fd2, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create region) 2");
    goto out_with_fd;
  }
  printf("got lid %llx\n", (unsigned long long) create.cookie);
  cookie2 = create.cookie;

  icopy.local_iovec_array = (uintptr_t) recv_iovec;
  icopy.local_iovec_nr = 1;
  icopy.remote_cookie = cookie1;
  icopy.remote_offset = 0;
  icopy.write = 0;
  icopy.flags = flags;
  icopy.async_status_index = -1;
  err = ioctl(fd1, KNEM_CMD_INLINE_COPY, &icopy);
  if (err < 0) {
    perror("ioctl (sync icopy) 1");
    goto out_with_fd;
  }
  if (icopy.current_status != KNEM_STATUS_SUCCESS) {
    fprintf(stderr, "got status %d instead of %d\n", icopy.current_status, KNEM_STATUS_SUCCESS);
    goto out_with_fd;
  }
  printf("sync icopy 1 ok\n");

  icopy.local_iovec_array = (uintptr_t) (recv_iovec+1);
  icopy.local_iovec_nr = 1;
  icopy.remote_cookie = cookie2;
  icopy.remote_offset = 0;
  icopy.write = 0;
  icopy.flags = flags;
  icopy.async_status_index = -1;
  err = ioctl(fd2, KNEM_CMD_INLINE_COPY, &icopy);
  if (err < 0) {
    perror("ioctl (sync icopy) 2");
    goto out_with_fd;
  }
  if (icopy.current_status != KNEM_STATUS_SUCCESS) {
    fprintf(stderr, "got status %d instead of %d\n", icopy.current_status, KNEM_STATUS_SUCCESS);
    goto out_with_fd;
  }
  printf("sync icopy 2 ok\n");

  icopy.local_iovec_array = (uintptr_t) (recv_iovec);
  icopy.local_iovec_nr = 1;
  icopy.remote_cookie = cookie2;
  icopy.remote_offset = 0;
  icopy.write = 0;
  icopy.flags = flags;
  icopy.async_status_index = -1;
  err = ioctl(fd2, KNEM_CMD_INLINE_COPY, &icopy);
  assert(err == -1);
  assert(errno == EINVAL);
  printf("sync icopy on completed send properly failed\n");



  create.iovec_array = (uintptr_t) send_iovec;
  create.iovec_nr = 1;
  create.flags = KNEM_FLAG_SINGLEUSE;
  create.protection = PROT_READ;
  err = ioctl(fd1, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create region) 1");
    goto out_with_fd;
  }
  printf("got lid %llx\n", (unsigned long long) create.cookie);
  cookie1 = create.cookie;

  create.iovec_array = (uintptr_t) (send_iovec+1);
  create.iovec_nr = 1;
  create.flags = KNEM_FLAG_SINGLEUSE;
  create.protection = PROT_READ;
  err = ioctl(fd2, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create region) 2");
    goto out_with_fd;
  }
  printf("got lid %llx\n", (unsigned long long) create.cookie);
  cookie2 = create.cookie;

  icopy.flags = flags | KNEM_FLAG_DMATHREAD | KNEM_FLAG_MEMCPYTHREAD;
  err = ioctl(fd1, KNEM_CMD_INLINE_COPY, &icopy);
  assert(err < 0);
  assert(errno == EINVAL);
  printf("async icopy with no mmapped status array properly failed\n");

  sarray1 = mmap(NULL, sizeof(knem_status_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd1, KNEM_STATUS_ARRAY_FILE_OFFSET);
  if (sarray1 == MAP_FAILED) {
    perror("mmap status array 1");
    goto out_with_fd;
  }
  sarray2 = mmap(NULL, sizeof(knem_status_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd2, KNEM_STATUS_ARRAY_FILE_OFFSET);
  if (sarray2 == MAP_FAILED) {
    perror("mmap status array 2");
    goto out_with_fd;
  }

  icopy.local_iovec_array = (uintptr_t) recv_iovec;
  icopy.local_iovec_nr = 1;
  icopy.remote_cookie = cookie1;
  icopy.remote_offset = 0;
  icopy.write = 0;
  icopy.flags = flags | KNEM_FLAG_DMATHREAD | KNEM_FLAG_MEMCPYTHREAD;
  icopy.async_status_index = 0;
  err = ioctl(fd1, KNEM_CMD_INLINE_COPY, &icopy);
  if (err < 0) {
    perror("ioctl (async icopy) 1");
    goto out_with_fd;
  }
  while (*sarray1 == KNEM_STATUS_PENDING);
  if (*sarray1 != KNEM_STATUS_SUCCESS) {
    fprintf(stderr, "got status %d instead of %d\n", *sarray1, KNEM_STATUS_SUCCESS);
    goto out_with_fd;
  }
  printf("async icopy 1 ok\n");

  icopy.local_iovec_array = (uintptr_t) (recv_iovec+1);
  icopy.local_iovec_nr = 1;
  icopy.remote_cookie = cookie2;
  icopy.remote_offset = 0;
  icopy.write = 0;
  icopy.flags = flags | KNEM_FLAG_DMATHREAD | KNEM_FLAG_MEMCPYTHREAD;
  icopy.async_status_index = 0;
  err = ioctl(fd2, KNEM_CMD_INLINE_COPY, &icopy);
  if (err < 0) {
    perror("ioctl (async icopy) 2");
    goto out_with_fd;
  }
  while (*sarray2 == KNEM_STATUS_PENDING);
  if (*sarray2 != KNEM_STATUS_SUCCESS) {
    fprintf(stderr, "got status %d instead of %d\n", *sarray2, KNEM_STATUS_SUCCESS);
    goto out_with_fd;
  }
  printf("async icopy 2 ok\n");

  icopy.local_iovec_array = (uintptr_t) (recv_iovec);
  icopy.local_iovec_nr = 1;
  icopy.remote_cookie = cookie2;
  icopy.remote_offset = 0;
  icopy.write = 0;
  icopy.flags = flags | KNEM_FLAG_DMATHREAD | KNEM_FLAG_MEMCPYTHREAD;
  icopy.async_status_index = 0;
  err = ioctl(fd2, KNEM_CMD_INLINE_COPY, &icopy);
  assert(err == -1);
  assert(errno == EINVAL);
  printf("async icopy on completed send properly failed\n");



  close(fd2);
  close(fd1);
  free(send_buffer);
  return 0;

 out_with_fd:
  close(fd2);
 out_with_fd1:
  close(fd1);
 out_with_buffer:
  free(send_buffer);
 out:
  return 1;
}
