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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sched.h>
#include <getopt.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "knem_io.h"

#define ITER 256
#define WARMUP 16
#define MIN 1024
#define MAX (4096*4096+1)
#define MULTIPLIER 2
#define INCREMENT 0
#define PAUSE_MS 100

static void
usage(char *argv[])
{
  fprintf(stderr, "%s [options]\n", argv[0]);
  fprintf(stderr, "Iteration configuration:\n");
  fprintf(stderr, " -S <n>\tchange the start length [%d]\n", MIN);
  fprintf(stderr, " -E <n>\tchange the end length [%d]\n", MAX);
  fprintf(stderr, " -M <n>\tchange the length multiplier [%d]\n", MULTIPLIER);
  fprintf(stderr, " -I <n>\tchange the length increment [%d]\n", INCREMENT);
  fprintf(stderr, " -N <n>\tchange number of iterations [%d]\n", ITER);
  fprintf(stderr, " -W <n>\tchange number of warmup iterations [%d]\n", WARMUP);
  fprintf(stderr, " -P <n>\tpause (in milliseconds) between lengths [%d]\n", PAUSE_MS);
  fprintf(stderr, "Communication configuration:\n");
  fprintf(stderr, " -R\treverse direction\n");
  fprintf(stderr, " -C\tcache regions instead of recreating for each iteration\n");
  fprintf(stderr, " -D\tdisable DMA engine\n");
  fprintf(stderr, " -F <n>\tadd copy command flags\n");
}

static unsigned long long
next_length(unsigned long long length, unsigned long long multiplier, unsigned long long increment)
{
  if (length)
    return length*multiplier+increment;
  else if (increment)
    return increment;
  else
    return 1;
}

static int one_length(int fd, volatile knem_status_t *status_array,
		      unsigned long long length, unsigned long iter, unsigned long warmup,
		      int cache, int reverse,
		      unsigned long flags)
{
  char *send_buffer, *recv_buffer;
  struct knem_cmd_param_iovec send_iovec, recv_iovec;
  struct knem_cmd_create_region create;
  struct knem_cmd_inline_copy copy;
  struct timeval tv1,tv2;
  unsigned long long us;
  unsigned long i;
  int err;

  send_buffer = malloc(length);
  if (!send_buffer) {
    err = -ENOMEM;
    goto out;
  }
  recv_buffer = malloc(length);
  if (!recv_buffer) {
    err = -ENOMEM;
    goto out_with_send_buffer;
  }

  send_iovec.base = (uintptr_t) send_buffer;
  send_iovec.len = length;

  recv_iovec.base = (uintptr_t) recv_buffer;
  recv_iovec.len = length;

  if (cache) {
    create.iovec_array = (uintptr_t) &send_iovec;
    create.iovec_nr = 1;
    create.flags = 0;
    create.protection = reverse ? PROT_WRITE : PROT_READ;
    err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
    if (err < 0) {
      perror("ioctl (create)");
      goto out_with_buffers;
    }
  }

  for(i=0; i<iter+warmup; i++) {
    if (i == warmup)
      gettimeofday(&tv1, NULL);

    if (!cache) {
      create.iovec_array = (uintptr_t) &send_iovec;
      create.iovec_nr = 1;
      create.flags = KNEM_FLAG_SINGLEUSE;
      create.protection = reverse ? PROT_WRITE : PROT_READ;
      err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
      if (err < 0) {
        perror("ioctl (create)");
        goto out_with_buffers;
      }
    }

    copy.local_iovec_array = (uintptr_t) &recv_iovec;
    copy.local_iovec_nr = 1;
    copy.write = reverse;
    copy.async_status_index = 0;
    copy.remote_cookie = create.cookie;
    copy.remote_offset = 0;
    copy.flags = flags;
    err = ioctl(fd, KNEM_CMD_INLINE_COPY, &copy);
    if (err < 0) {
      perror("ioctl (inline copy)");
      goto out_with_buffers;
    }

    if (copy.current_status == KNEM_STATUS_PENDING) {
      while (status_array[copy.async_status_index] == KNEM_STATUS_PENDING)
        sched_yield();
      if (status_array[copy.async_status_index] != KNEM_STATUS_SUCCESS) {
        fprintf(stderr, "got async status %d instead of %d\n", status_array[copy.async_status_index], KNEM_STATUS_SUCCESS);
        goto out_with_buffers;
      }
    } else {
      if (copy.current_status != KNEM_STATUS_SUCCESS) {
        fprintf(stderr, "got sync status %d instead of %d\n", copy.current_status, KNEM_STATUS_SUCCESS);
        goto out_with_buffers;
      }
    }
  }

  gettimeofday(&tv2, NULL);

  if (cache) {
    err = ioctl(fd, KNEM_CMD_DESTROY_REGION, &create.cookie);
    if (err < 0)
      perror("ioctl (destroy)");
  }

  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  printf("% 9lld:\t%.3f us\t%.2f MB/s\t %.2f MiB/s\n",
	 length, ((float) us)/iter,
	 ((float) length)*iter/us,
	 ((float) length)*iter/us/1.048576);

  free(recv_buffer);
  free(send_buffer);
  return 0;

 out_with_buffers:
  free(recv_buffer);
 out_with_send_buffer:
  free(send_buffer);
 out:
  return err;
}

int main(int argc, char * argv[])
{
  unsigned long long length;
  unsigned long long min = MIN;
  unsigned long long max = MAX;
  unsigned long multiplier = MULTIPLIER;
  unsigned long increment = INCREMENT;
  unsigned long pause_ms = PAUSE_MS;
  unsigned long iter = ITER;
  unsigned long warmup = WARMUP;
  unsigned long flags = KNEM_FLAG_DMA;
  int cache = 0;
  int reverse = 0;
  volatile knem_status_t *status_array;
  struct knem_cmd_info info;
  int fd, err;
  int c;

  while ((c = getopt(argc, argv, "S:E:M:I:N:W:P:F:DCRh")) != -1)
    switch (c) {
    case 'S':
      min = atoll(optarg);
      break;
    case 'E':
      max = atoll(optarg);
      break;
    case 'M':
      multiplier = atoll(optarg);
      break;
    case 'I':
      increment = atoll(optarg);
      break;
    case 'N':
      iter = atoi(optarg);
      break;
    case 'W':
      warmup = atoi(optarg);
      break;
    case 'C':
      cache = 1;
      break;
    case 'R':
      reverse = 1;
      break;
    case 'P':
      pause_ms = atoi(optarg);
      break;
    case 'F':
      flags |= atoi(optarg);
      break;
    case 'D':
      flags &= ~KNEM_FLAG_DMA;
      break;
    default:
      fprintf(stderr, "Unknown option -%c\n", c);
      /* fallthru */
    case 'h':
      usage(argv);
      exit(-1);
      break;
    }

  fd = open("/dev/knem", O_RDWR);
  if (fd < 0) {
    perror("open");
    goto out;
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

  status_array = mmap(NULL, 1, PROT_READ|PROT_WRITE, MAP_SHARED, fd, KNEM_STATUS_ARRAY_FILE_OFFSET);
  if (status_array == MAP_FAILED) {
    perror("mmap status_array");
    goto out_with_fd;
  }

  if (flags & KNEM_FLAG_DMA && !(info.features & KNEM_FEATURE_DMA)) {
    fprintf(stderr, "DMA support not available, ignoring it\n");
    flags &= ~KNEM_FLAG_DMA;
  }

  for(length = min;
      length < max;
      length = next_length(length, multiplier, increment)) {
    err = one_length(fd, status_array, length, iter, warmup, cache, reverse, flags);
    if (err < 0)
      goto out_with_fd;
    usleep(pause_ms * 1000);
  }

  close(fd);
  return 0;

 out_with_fd:
  close(fd);
 out:
  return 1;
}
