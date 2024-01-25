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
#define NSTATUS 45

static knem_cookie_t
create_region(int fd, int write, struct knem_cmd_param_iovec *iovec, int nr)
{
  int err;
  struct knem_cmd_create_region create;
  create.iovec_array = (uintptr_t) iovec;
  create.iovec_nr = nr;
  create.flags = KNEM_FLAG_SINGLEUSE;
  create.protection = write ? PROT_WRITE : PROT_READ;
  err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create region)");
    exit(1);
  }
  return create.cookie;
}

static void
check_status(knem_status_t status)
{
  if (status == KNEM_STATUS_SUCCESS)
    printf("OK\n");
  else if (status == KNEM_STATUS_FAILED) {
    printf("Failed\n");
    assert(0);
  } else {
    printf("Pending?!\n");
    assert(0);
  }
}

static void
old_sync_recv(int fd, struct knem_cmd_param_iovec *iovec, int nr, knem_cookie_t cookie, unsigned long flags)
{
  int err;
  struct knem_cmd_sync_recv_param srecvcmd;
  srecvcmd.recv_iovec_array = (uintptr_t) iovec;
  srecvcmd.recv_iovec_nr = nr;
  srecvcmd.send_cookie = cookie;
  srecvcmd.flags = flags;
  err = ioctl(fd, KNEM_CMD_SYNC_RECV, &srecvcmd);
  if (err < 0) {
    perror("ioctl (old sync recv)");
    exit(1);
  }
  check_status(srecvcmd.status);
}

static void
old_async_recv(int fd, struct knem_cmd_param_iovec *iovec, int nr, knem_cookie_t cookie, unsigned long flags, volatile knem_status_t *sarray)
{
  int err;
  struct knem_cmd_init_async_recv_param arecvcmd;
  arecvcmd.recv_iovec_array = (uintptr_t) iovec;
  arecvcmd.recv_iovec_nr = nr;
  arecvcmd.send_cookie = cookie;
  arecvcmd.status_index = 23;
  arecvcmd.flags = flags;
  err = ioctl(fd, KNEM_CMD_INIT_ASYNC_RECV, &arecvcmd);
  if (err < 0) {
    perror("ioctl (old async recv)");
    exit(1);
  }
  while (sarray[23] == KNEM_STATUS_PENDING);
  check_status(sarray[23]);
}

static void
inline_copy(int fd, struct knem_cmd_param_iovec *iovec, int nr, knem_cookie_t cookie, unsigned long flags, volatile knem_status_t *sarray, int sindex)
{
  int err;
  struct knem_cmd_inline_copy icopy;
  icopy.local_iovec_array = (uintptr_t) iovec;
  icopy.local_iovec_nr = nr;
  icopy.remote_cookie = cookie;
  icopy.remote_offset = 0;
  icopy.write = 0;
  icopy.async_status_index = sindex;
  icopy.flags = flags;
  err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
  if (err < 0) {
    perror("ioctl (inline copy)");
    exit(1);
  }
  if (icopy.current_status != KNEM_STATUS_PENDING) {
    printf("sync ");
    check_status(icopy.current_status);
  } else {
    printf("async ");
    if (!sarray) {
      fprintf(stderr, "no async array given\n");
      exit(1);
    }
    while (sarray[sindex] == KNEM_STATUS_PENDING);
    check_status(sarray[sindex]);
  }
}

static void
copy(int fd, knem_cookie_t src_cookie, knem_cookie_t dst_cookie, unsigned long flags, volatile knem_status_t *sarray, int sindex)
{
  int err;
  struct knem_cmd_copy_bounded copy;
  copy.src_cookie = src_cookie;
  copy.src_offset = 0;
  copy.dst_cookie = dst_cookie;
  copy.dst_offset = 0;
  copy.length = LEN;
  copy.async_status_index = sindex;
  copy.flags = flags;
  err = ioctl(fd, KNEM_CMD_COPY_BOUNDED, &copy);
  if (err < 0) {
    perror("ioctl (copy)");
    exit(1);
  }
  if (copy.current_status != KNEM_STATUS_PENDING) {
    printf("sync ");
    check_status(copy.current_status);
  } else {
    printf("async ");
    if (!sarray) {
      fprintf(stderr, "no async array given\n");
      exit(1);
    }
    while (sarray[sindex] == KNEM_STATUS_PENDING);
    check_status(sarray[sindex]);
  }
}

int main()
{
  struct knem_cmd_info info;
  int fd, err;
  char *send_buffer, *recv_buffer;
  knem_cookie_t cookie, cookie2;
  struct knem_cmd_param_iovec send_iovec[2], recv_iovec[2];
  volatile knem_status_t *sarray, *sarray2;

  send_buffer = malloc(LEN*2);
  if (!send_buffer)
    goto out;
  recv_buffer = send_buffer+LEN;

  send_iovec[0].base = (uintptr_t) send_buffer;
  send_iovec[0].len = LEN/2;
  send_iovec[1].base = (uintptr_t) send_buffer + LEN/2;
  send_iovec[1].len = LEN/2;

  recv_iovec[0].base = (uintptr_t) recv_buffer;
  recv_iovec[0].len = LEN/2;
  recv_iovec[1].base = (uintptr_t) recv_buffer + LEN/2;
  recv_iovec[1].len = LEN/2;

  fd = open("/dev/knem", O_RDWR);
  if (fd < 0) {
    perror("open");
    goto out_with_buffer;
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
  printf("got driver ABI %lx and feature mask %lx\n",
	 (unsigned long) info.abi, (unsigned long) info.features);

  if (sizeof(size_t) > sizeof(uint32_t)) {
    /* BITS_PER_LONG isn't always defined, so do a runtime check instead to avoid 0x100000001 being truncated on 32bits arch,
     * and use ULL below to avoid warnings about this truncation even if the code isn't executed */
    sarray = mmap(NULL, (size_t)(0x100000001ULL*sizeof(knem_status_t)), PROT_READ|PROT_WRITE, MAP_SHARED, fd, KNEM_STATUS_ARRAY_FILE_OFFSET);
    if (sarray == MAP_FAILED) {
      printf("mapping more than 2^32 slots failed as expected\n");
    } else {
      printf("mapping more than 2^32 slots should fail\n");
      goto out_with_fd;
    }
  }

  sarray = mmap(NULL, NSTATUS*sizeof(knem_status_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, KNEM_STATUS_ARRAY_FILE_OFFSET);
  if (sarray == MAP_FAILED) {
    perror("mmap status array");
    goto out_with_fd;
  }

  sarray2 = mmap(NULL, sizeof(knem_status_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, KNEM_STATUS_ARRAY_FILE_OFFSET);
  if (sarray2 == MAP_FAILED) {
    printf("mmap status array twice failed as expected\n");
  } else {
    printf("mmap status array twice should fail\n");
    goto out_with_fd;
  }

  printf("\n");

  printf("Testing the old Synchronous command...\n");

  printf("OLDSYNC... ");
  cookie = create_region(fd, 0, send_iovec, 2);
  old_sync_recv(fd, recv_iovec, 2, cookie, 0);

  printf("OLDSYNC DMA=sync... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    old_sync_recv(fd, recv_iovec, 2, cookie, KNEM_FLAG_DMA);
  } else {
    printf("ignored\n");
  }

  printf("\n");

  printf("Testing the old Asynchronous command...\n");

  printf("OLDASYNC... ");
  cookie = create_region(fd, 0, send_iovec, 2);
  old_async_recv(fd, recv_iovec, 2, cookie, 0, sarray);

  printf("OLDASYNC THREAD... ");
  cookie = create_region(fd, 0, send_iovec, 2);
  old_async_recv(fd, recv_iovec, 2, cookie, KNEM_FLAG_MEMCPYTHREAD, sarray);

  printf("OLDASYNC DMA=sync... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    old_async_recv(fd, recv_iovec, 2, cookie, KNEM_FLAG_DMA, sarray);
  } else {
    printf("ignored\n");
  }

  printf("OLDASYNC DMA=async... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    old_async_recv(fd, recv_iovec, 2, cookie, KNEM_FLAG_DMA | KNEM_FLAG_ASYNCDMACOMPLETE, sarray);
  } else {
    printf("ignored\n");
  }

  printf("OLDASYNC THREAD DMA=sync... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    old_async_recv(fd, recv_iovec, 2, cookie, KNEM_FLAG_DMA | KNEM_FLAG_DMATHREAD, sarray);
  } else {
    printf("ignored\n");
  }

  printf("OLDASYNC THREAD DMA=async... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    old_async_recv(fd, recv_iovec, 2, cookie, KNEM_FLAG_DMA | KNEM_FLAG_ASYNCDMACOMPLETE | KNEM_FLAG_DMATHREAD, sarray);
  } else {
    printf("ignored\n");
  }

  printf("\n");

  printf("Testing the new Inline Copy command...\n");

  printf("INLINECOPY... ");
  cookie = create_region(fd, 0, send_iovec, 2);
  inline_copy(fd, recv_iovec, 2, cookie, 0, NULL, -1);

  printf("INLINECOPY THREAD... ");
  cookie = create_region(fd, 0, send_iovec, 2);
  inline_copy(fd, recv_iovec, 2, cookie, KNEM_FLAG_MEMCPYTHREAD, sarray, 17);

  printf("INLINECOPY DMA=sync... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    inline_copy(fd, recv_iovec, 2, cookie, KNEM_FLAG_DMA, NULL, -1);
  } else {
    printf("ignored\n");
  }

  printf("INLINECOPY DMA=async... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    inline_copy(fd, recv_iovec, 2, cookie, KNEM_FLAG_DMA | KNEM_FLAG_ASYNCDMACOMPLETE, sarray, 15);
  } else {
    printf("ignored\n");
  }

  printf("INLINECOPY THREAD DMA=sync... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    inline_copy(fd, recv_iovec, 2, cookie, KNEM_FLAG_DMA | KNEM_FLAG_DMATHREAD, sarray, 13);
  } else {
    printf("ignored\n");
  }

  printf("INLINECOPY THREAD DMA=async... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    inline_copy(fd, recv_iovec, 2, cookie, KNEM_FLAG_DMA | KNEM_FLAG_ASYNCDMACOMPLETE | KNEM_FLAG_DMATHREAD, sarray, 37);
  } else {
    printf("ignored\n");
  }

  printf("\n");

  printf("Testing the new Copy command...\n");

  printf("COPY... ");
  cookie = create_region(fd, 0, send_iovec, 2);
  cookie2 = create_region(fd, 1, recv_iovec, 2);
  copy(fd, cookie, cookie2, 0, NULL, -1);

  printf("COPY THREAD... ");
  cookie = create_region(fd, 0, send_iovec, 2);
  cookie2 = create_region(fd, 1, recv_iovec, 2);
  copy(fd, cookie, cookie2, KNEM_FLAG_MEMCPYTHREAD, sarray, 42);

  printf("COPY DMA=sync... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    cookie2 = create_region(fd, 1, recv_iovec, 2);
    copy(fd, cookie, cookie2, KNEM_FLAG_DMA, NULL, -1);
  } else {
    printf("ignored\n");
  }

  printf("COPY DMA=async... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    cookie2 = create_region(fd, 1, recv_iovec, 2);
    copy(fd, cookie, cookie2, KNEM_FLAG_DMA | KNEM_FLAG_ASYNCDMACOMPLETE, sarray, 31);
  } else {
    printf("ignored\n");
  }

  printf("COPY THREAD DMA=sync... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    cookie2 = create_region(fd, 1, recv_iovec, 2);
    copy(fd, cookie, cookie2, KNEM_FLAG_DMA | KNEM_FLAG_DMATHREAD, sarray, 36);
  } else {
    printf("ignored\n");
  }

  printf("COPY THREAD DMA=async... ");
  if (info.features & KNEM_FEATURE_DMA) {
    cookie = create_region(fd, 0, send_iovec, 2);
    cookie2 = create_region(fd, 1, recv_iovec, 2);
    copy(fd, cookie, cookie2, KNEM_FLAG_DMA | KNEM_FLAG_ASYNCDMACOMPLETE | KNEM_FLAG_DMATHREAD, sarray, 40);
  } else {
    printf("ignored\n");
  }

  printf("\n");

  close(fd);
  free(send_buffer);
  return 0;

 out_with_fd:
  close(fd);
 out_with_buffer:
  free(send_buffer);
 out:
  return 1;
}
