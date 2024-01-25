/*
 * Copyright © inria 2009-2011
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

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sched.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "knem_io.h"

#define ITER 256
#define WARMUP 16
#define MIN 1024
#define MAX (4096*4096+1)
#define MULTIPLIER 2
#define INCREMENT 0
#define PAUSE_MS 100
#define UNUSED_REGIONS 0
#define MISSALIGN 0
#define MINWORKSET 0

struct rndv_desc {
	knem_cookie_t cookie;
	int ready;
};

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
  fprintf(stderr, " -b <n,m>\tbind sender and receiver on logical processors <n> and <m> [disabled]\n");
  fprintf(stderr, " -k <n,m>\tbind sender and receiver kthreads on logical processors <n> and <m> [disabled]\n");
  fprintf(stderr, " -R\treverse transfer direction\n");
  fprintf(stderr, " -C\tcache regions instead of recreating for each iteration\n");
  fprintf(stderr, " -D\tdisable DMA engine\n");
  fprintf(stderr, " -F <n>\tadd copy command flags\n");
  fprintf(stderr, " -O <n>\tchange the minimal workset size (works around caches) [%d]\n", 0);
  fprintf(stderr, " -A <n>\tchange send/recv buffer relative alignments [%d]\n", MISSALIGN);
  fprintf(stderr, " -U <n>\tadd unused regions to test scalability [%d]\n", UNUSED_REGIONS);
  fprintf(stderr, "Launch configuration:\n");
  fprintf(stderr, " -m <file>\trun as master after creating shared <file>\n");
  fprintf(stderr, " -s <file>\trun as slave of the master that created shared <file>\n");
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

static int one_sender_length(int fd, volatile knem_status_t *status_array,
			     volatile struct rndv_desc *out_desc, volatile struct rndv_desc *in_desc,
			     unsigned long long length, unsigned long long minworkset, unsigned long missalign,
			     unsigned long iter, unsigned long warmup,
			     int cache, int reverse, unsigned long flags)
{
  char *buffer, *send_buffers, *recv_buffers;
  unsigned long long workset, nr_buffers;
  struct knem_cmd_param_iovec send_iovec, recv_iovec;
  struct knem_cmd_create_region create;
  struct knem_cmd_inline_copy icopy;
  struct timeval tv1,tv2;
  unsigned long long us;
  unsigned long i;
  int err;

  if (minworkset) {
    workset = length + minworkset;
    nr_buffers = workset/length;
  } else {
    workset = length;
    nr_buffers = 1;
  }

  buffer = calloc(workset + missalign + workset, 1);
  if (!buffer) {
    err = -ENOMEM;
    goto out;
  }
  send_buffers = buffer;
  recv_buffers = buffer + workset + missalign;

  send_iovec.len = length;
  recv_iovec.len = length;

  if (cache) {
    assert(!minworkset);
    send_iovec.base = (uintptr_t) send_buffers;
    create.iovec_array = (uintptr_t) &send_iovec;
    create.iovec_nr = 1;
    create.flags = 0;
    create.protection = reverse ? PROT_WRITE : PROT_READ;
    err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
    if (err < 0) {
      perror("ioctl (create region)");
      goto out_with_buffers;
    }
  }

  for(i=0; i<iter+warmup; i++) {
    if (i == warmup)
      gettimeofday(&tv1, NULL);

    if (!cache) {
      send_iovec.base = (uintptr_t) send_buffers + length * (i%nr_buffers);
      create.iovec_array = (uintptr_t) &send_iovec;
      create.iovec_nr = 1;
      create.flags = KNEM_FLAG_SINGLEUSE;
      create.protection = reverse ? PROT_WRITE : PROT_READ;
      err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
      if (err < 0) {
	perror("ioctl (create region)");
	goto out_with_buffers;
      }
    }

    out_desc->cookie = create.cookie;
    out_desc->ready = 1;
    while (!in_desc->ready)
      /* yield the processor to the remote process */
      sched_yield();
    in_desc->ready = 0;

    recv_iovec.base = (uintptr_t) recv_buffers + length * (i%nr_buffers);
    icopy.local_iovec_array = (uintptr_t) &recv_iovec;
    icopy.local_iovec_nr = 1;
    icopy.remote_cookie = in_desc->cookie;
    icopy.remote_offset = 0;
    icopy.write = reverse;
    icopy.flags = flags;
    icopy.async_status_index = 0;
    err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
    if (err < 0) {
      perror("ioctl (inline copy)");
      goto out_with_buffers;
    }

    if (icopy.current_status == KNEM_STATUS_PENDING) {
      while (status_array[icopy.async_status_index] == KNEM_STATUS_PENDING)
	/* yield the processor in case the kernel thread is doing the copy on the same processor */
	sched_yield();
      if (status_array[icopy.async_status_index] != KNEM_STATUS_SUCCESS) {
	fprintf(stderr, "got status %d instead of %d\n", status_array[icopy.async_status_index], KNEM_STATUS_SUCCESS);
	goto out_with_buffers;
      }
    } else if (icopy.current_status != KNEM_STATUS_SUCCESS) {
      fprintf(stderr, "got status %d instead of %d\n", icopy.current_status, KNEM_STATUS_SUCCESS);
      goto out_with_buffers;
    }
  }

  gettimeofday(&tv2, NULL);

  /* notify the other side that we are done */
  out_desc->ready = 1;

  if (cache) {
    err = ioctl(fd, KNEM_CMD_DESTROY_REGION, &create.cookie);
    if (err < 0)
      perror("ioctl (destroy)");
  }

  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  printf("% 9lld:\t%.3f us\t%.2f MB/s\t %.2f MiB/s\n",
	 length, ((float) us)/iter/2,
	 ((float) length)*iter*2/us,
	 ((float) length)*iter*2/us/1.048576);

  free(buffer);
  return 0;

 out_with_buffers:
  free(buffer);
 out:
  return err;
}

static int one_receiver_length(int fd, volatile knem_status_t *status_array,
			       volatile struct rndv_desc *out_desc, volatile struct rndv_desc *in_desc,
			       unsigned long long length, unsigned long long minworkset, unsigned long missalign,
			       unsigned long iter, unsigned long warmup,
			       int cache, int reverse, unsigned long flags)
{
  char *buffer, *send_buffers, *recv_buffers;
  unsigned long long workset, nr_buffers;
  struct knem_cmd_param_iovec send_iovec, recv_iovec;
  struct knem_cmd_create_region create;
  struct knem_cmd_inline_copy icopy;
  unsigned long i;
  int err;

  if (minworkset) {
    workset = length + minworkset;
    nr_buffers = workset/length;
  } else {
    workset = length;
    nr_buffers = 1;
  }

  buffer = calloc(workset + missalign + workset, 1);
  if (!buffer) {
    err = -ENOMEM;
    goto out;
  }
  send_buffers = buffer;
  recv_buffers = buffer + workset + missalign;

  send_iovec.len = length;
  recv_iovec.len = length;

  if (cache) {
    assert(!minworkset);
    send_iovec.base = (uintptr_t) send_buffers;
    create.iovec_array = (uintptr_t) &send_iovec;
    create.iovec_nr = 1;
    create.flags = 0;
    create.protection = reverse ? PROT_WRITE : PROT_READ;
    err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
    if (err < 0) {
      perror("ioctl (create region)");
      goto out_with_buffers;
    }
  }

  for(i=0; i<iter+warmup; i++) {
    while (!in_desc->ready)
      /* yield the processor to the remote process */
      sched_yield();
    in_desc->ready = 0;

    recv_iovec.base = (uintptr_t) recv_buffers + length * (i%nr_buffers);
    icopy.local_iovec_array = (uintptr_t) &recv_iovec;
    icopy.local_iovec_nr = 1;
    icopy.remote_cookie = in_desc->cookie;
    icopy.remote_offset = 0;
    icopy.write = reverse;
    icopy.flags = flags;
    icopy.async_status_index = 0;
    err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
    if (err < 0) {
      perror("ioctl (inline copy)");
      goto out_with_buffers;
    }

    if (icopy.current_status == KNEM_STATUS_PENDING) {
      while (status_array[icopy.async_status_index] == KNEM_STATUS_PENDING)
	/* yield the processor in case the kernel thread is doing the copy on the same processor */
	sched_yield();
      if (status_array[icopy.async_status_index] != KNEM_STATUS_SUCCESS) {
	fprintf(stderr, "got status %d instead of %d\n", status_array[icopy.async_status_index], KNEM_STATUS_SUCCESS);
	goto out_with_buffers;
      }
    } else if (icopy.current_status != KNEM_STATUS_SUCCESS) {
      fprintf(stderr, "got status %d instead of %d\n", icopy.current_status, KNEM_STATUS_SUCCESS);
      goto out_with_buffers;
    }

    if (!cache) {
      send_iovec.base = (uintptr_t) send_buffers + length * (i%nr_buffers);
      create.iovec_array = (uintptr_t) &send_iovec;
      create.iovec_nr = 1;
      create.flags = KNEM_FLAG_SINGLEUSE;
      create.protection = reverse ? PROT_WRITE : PROT_READ;
      err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
      if (err < 0) {
	perror("ioctl (create region)");
	goto out_with_buffers;
      }
    }

    out_desc->cookie = create.cookie;
    out_desc->ready = 1;
  }

  /* wait for the other side to be done before exiting */
  while (!in_desc->ready)
    /* yield the processor to the remote process */
    sched_yield();
  in_desc->ready = 0;

  if (cache) {
    err = ioctl(fd, KNEM_CMD_DESTROY_REGION, &create.cookie);
    if (err < 0)
      perror("ioctl (destroy)");
  }

  free(buffer);
  return 0;

 out_with_buffers:
  free(buffer);
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
  unsigned long long minworkset = MINWORKSET;
  unsigned long missalign = MISSALIGN;
  volatile knem_status_t *status_array;
  volatile void *shared_buffer;
  volatile struct rndv_desc *out_desc, *in_desc;
  int reverse = 0;
  int cache = 0;
  int sender;
  int bind = 0;
  int kbind = 0;
  int unused_regions = UNUSED_REGIONS;
  cpu_set_t cpuset;
  int send_cpu = -1, recv_cpu = -1;
  int ksend_cpu = -1, krecv_cpu = -1;
  struct knem_cmd_info info;
  const char *masterfile = NULL;
  const char *slavefile = NULL;
  int fd, err;
  int c;

  while ((c = getopt(argc, argv, "b:k:S:E:M:I:N:W:P:O:A:U:F:DCRm:s:h")) != -1)
    switch (c) {
    case 'b': {
      char *optarg2 = strchr(optarg, ',');
      if (!optarg2) {
	fprintf(stderr, "Invalid binding %s\n", optarg);
	usage(argv);
	exit(-1);
      }
      bind = 1;
      send_cpu = atoi(optarg);
      recv_cpu = atoi(optarg2+1);
      break;
    }
    case 'k': {
      char *optarg2 = strchr(optarg, ',');
      if (!optarg2) {
	fprintf(stderr, "Invalid kthread binding %s\n", optarg);
	usage(argv);
	exit(-1);
      }
      kbind = 1;
      ksend_cpu = atoi(optarg);
      krecv_cpu = atoi(optarg2+1);
      break;
    }
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
    case 'O':
      minworkset = atoll(optarg);
      break;
    case 'A':
      missalign = atoi(optarg);
      break;
    case 'U':
      unused_regions = atoi(optarg);
      break;
    case 'F':
      flags |= atoi(optarg);
      break;
    case 'D':
      flags &= ~KNEM_FLAG_DMA;
      break;
    case 'm':
      masterfile = optarg;
      break;
    case 's':
      slavefile = optarg;
      break;
    default:
      fprintf(stderr, "Unknown option -%c\n", c);
      /* fallthru */
    case 'h':
      usage(argv);
      exit(-1);
      break;
    }

  if (cache && minworkset) {
    fprintf(stderr, "cannot cache region if minimal workset\n");
    goto out;
  }

  /* make sure different sets don't have overlapping cachelines */
  if (minworkset && missalign)
    missalign += 1024;

  if (bind) {
    /* bind on both cpu before allocating stuff */
    CPU_ZERO(&cpuset);
    CPU_SET(send_cpu, &cpuset);
    CPU_SET(recv_cpu, &cpuset);
    err = sched_setaffinity(0, sizeof(cpuset), &cpuset);
    if (err < 0) {
      fprintf(stderr, "failed to bind process on processors #%d and #%d\n", send_cpu, recv_cpu);
      /* fallback */
    }
  }

  if (masterfile) {
    int fd = open(masterfile, O_CREAT|O_EXCL|O_RDWR, S_IRWXU);
    if (fd < 0) {
      perror("open shared buffer file");
      goto out;
    }
    if (ftruncate(fd, 2*sizeof(struct rndv_desc)) < 0) {
      close(fd);
      perror("ftruncate");
      goto out;
    }
    shared_buffer = mmap(NULL, 2*sizeof(struct rndv_desc), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (shared_buffer == MAP_FAILED) {
      perror("mmap shared buffer file");
      goto out;
    }
    memset((void *) shared_buffer, 0, 2*sizeof(struct rndv_desc));

    sender = 1;

  } else if (slavefile) {
    int fd = open(slavefile, O_RDWR, S_IRWXU);
    if (fd < 0) {
      perror("open shared buffer file");
      goto out;
    }
    shared_buffer = mmap(NULL, 2*sizeof(struct rndv_desc), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (shared_buffer == MAP_FAILED) {
      perror("mmap shared buffer file");
      goto out;
    }
    /* the master does the memset */

    sender = 0;

  } else {
    shared_buffer = mmap(NULL, 2*sizeof(struct rndv_desc), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (shared_buffer == MAP_FAILED) {
      perror("mmap shared buffer");
      goto out;
    }
    memset((void *) shared_buffer, 0, 2*sizeof(struct rndv_desc));

    sender = fork();
  }

  if (sender) {
    in_desc = shared_buffer;
    out_desc = in_desc + 1;
  } else {
    out_desc = shared_buffer;
    in_desc = out_desc + 1;
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

  if (flags & KNEM_FLAG_DMA && !(info.features & KNEM_FEATURE_DMA)) {
    fprintf(stderr, "DMA support not available, ignoring it\n");
    flags &= ~KNEM_FLAG_DMA;
  }

  if (bind) {
    CPU_ZERO(&cpuset);
    CPU_SET(sender ? send_cpu : recv_cpu, &cpuset);
    err = sched_setaffinity(0, sizeof(cpuset), &cpuset);
    if (err < 0) {
      fprintf(stderr, "failed to bind process on processor #%d\n", sender ? send_cpu : recv_cpu);
      /* fallback */
    }
  }

  if (kbind) {
    struct knem_cmd_bind_offload bind_offload;
    CPU_ZERO(&cpuset);
    CPU_SET(sender ? ksend_cpu : krecv_cpu, &cpuset);
    bind_offload.flags = KNEM_BIND_FLAG_CUSTOM;
    bind_offload.mask_len = sizeof(cpuset);
    bind_offload.mask_ptr = (uintptr_t) &cpuset;
    err = ioctl(fd, KNEM_CMD_BIND_OFFLOAD, &bind_offload);
    if (err < 0) {
      perror("ioctl bind-offload");
      goto out_with_fd;
    }
  }

  for(; unused_regions>0; unused_regions--) {
    struct knem_cmd_create_region create;
    struct knem_cmd_param_iovec iovec;
    char c;
    iovec.base = (uintptr_t) &c;
    iovec.len = 0;
    create.iovec_array = (uintptr_t) &iovec;
    create.iovec_nr = 1;
    create.flags = 0;
    create.protection = 0;
    err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
    if (err < 0) {
      perror("ioctl (create unused region)");
      goto out_with_fd;
    }
  }

  status_array = mmap(NULL, 1, PROT_READ|PROT_WRITE, MAP_SHARED, fd, KNEM_STATUS_ARRAY_FILE_OFFSET);
  if (status_array == MAP_FAILED) {
    perror("mmap status_array");
    goto out_with_fd;
  }

  if (sender) {
    /* sender, father */

    for(length = min;
	length < max;
	length = next_length(length, multiplier, increment)) {
      usleep(pause_ms * 1000);
      err = one_sender_length(fd, status_array, out_desc, in_desc, length, minworkset, missalign, iter, warmup, cache, reverse, flags);
      if (err < 0)
	goto out_with_fd;
    }
    waitpid(sender, NULL, 0);

  } else {
    /* receiver, child */

    for(length = min;
	length < max;
	length = next_length(length, multiplier, increment)) {
      err = one_receiver_length(fd, status_array, out_desc, in_desc, length, minworkset, missalign, iter, warmup, cache, reverse, flags);
      if (err < 0)
	goto out_with_fd;
    }
  }

  close(fd);
  return 0;

 out_with_fd:
  close(fd);
 out:
  return 1;
}
