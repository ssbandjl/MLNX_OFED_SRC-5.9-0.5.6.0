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

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sched.h>
#include <errno.h>
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

struct rndv_desc {
	knem_cookie_t cookie;
	int ready;
};

/* rank 0 writes to rank X>0 in desc[(X-1)*2]
 * rank X>0 writes to rank 0 in desc[(X-1)*2+1]
 */
#define outdesc(myrank, hisrank, shmbuf) ((shmbuf) + (!myrank ? (hisrank-1)*2 : (myrank-1)*2+1))
#define indesc(myrank, hisrank, shmbuf) ((shmbuf) + (!hisrank ? (myrank-1)*2 : (hisrank-1)*2+1))

static void
usage(char *argv[], int nprocs)
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
  fprintf(stderr, " -p <n>\tchange the number of processes [%d]\n", nprocs);
  fprintf(stderr, " -b <n,m,...>\tbind ranks on logical processors <n,m,...> [0,1,...]\n");
  fprintf(stderr, " -R\ttransfer from slaves to master instead from master to slaves\n");
  fprintf(stderr, " -s\tsplit the buffer among all slaves instead of sending it entirely multiple times\n");
  fprintf(stderr, " -m\tprocess all transfers in the master instead of in the slaves\n");
  fprintf(stderr, " -c\tcreate one (identical) region per slave instead of sharing one when slave-initiated\n");
  fprintf(stderr, " -C\tcache region instead of recreating for each iteration\n");
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

/***********
 * Topology
 */

#ifdef KNEM_HAVE_HWLOC
#include "hwloc.h"
static hwloc_topology_t topology = NULL;
#else /* KNEM_HAVE_HWLOC */
static void * topology = NULL;
#endif /* KNEM_HAVE_HWLOC */

static void
hwloc_init(void)
{
#ifdef KNEM_HAVE_HWLOC
  int err;
  err = hwloc_topology_init(&topology);
  if (err < 0)
    goto hwloc_failed;
  err = hwloc_topology_load(topology);
  if (err < 0) {
    hwloc_topology_destroy(topology);
    goto hwloc_failed;
  }
  return;

 hwloc_failed:
#endif
  topology = NULL;
}

static void
hwloc_exit(void)
{
#ifdef KNEM_HAVE_HWLOC
  if (topology)
    hwloc_topology_destroy(topology);
#endif
}

static int
hwloc_get_nprocs(void)
{
#ifdef KNEM_HAVE_HWLOC
  if (topology) {
    int nprocs = hwloc_get_nbobjs_by_type(topology, HWLOC_OBJ_CORE);
    if (nprocs > 0)
      return nprocs;
  }
#endif
  return sysconf(_SC_NPROCESSORS_ONLN);
}

static int
hwloc_get_rank_bindcpu(int rank)
{
#ifdef KNEM_HAVE_HWLOC
  hwloc_obj_t core, pu;
  if (!topology)
    goto hwloc_failed;
  core = hwloc_get_obj_by_type(topology, HWLOC_OBJ_CORE, rank);
  if (!core)
    goto hwloc_failed;
  pu = hwloc_get_next_obj_inside_cpuset_by_type(topology, core->cpuset, HWLOC_OBJ_PU, NULL);
  if (!pu)
    goto hwloc_failed;
  return pu->os_index;

 hwloc_failed:
#endif
  return rank;
}

/*********************************
 * Slave-initiated communications
 *
 * The target (master) creates a region,
 * passes its cookie to the data transfer initiators (slaves),
 * and destroy the region when the slaves are done
 */

static int one_master_target_length(int fd,
				    int nprocs, volatile struct rndv_desc *shmbuf,
				    unsigned long long length, unsigned long iter, unsigned long warmup,
				    int cache, int sharedregion, int reverse, int split)
{
  char *buffer;
  struct knem_cmd_param_iovec iovec;
  int nregions = sharedregion ? 1 : nprocs-1; /* create one sharedregion, or one per slave */
  struct knem_cmd_create_region *create;
  struct timeval tv1,tv2;
  unsigned long long us;
  unsigned long i;
  int j;
  int err;

  buffer = malloc(length);
  if (!buffer) {
    err = -ENOMEM;
    goto out;
  }

  create = malloc(nregions * sizeof(*create));
  if (!create) {
    free(buffer);
    err = -ENOMEM;
    goto out;
  }

  if (cache) {
    for(j=0; j<nregions; j++) {
      if (split && !sharedregion) {
	iovec.base = (uintptr_t) buffer + length/(nprocs-1) * j;
	iovec.len = length/(nprocs-1) + (j == nregions-1 ? length%(nprocs-1) : 0);
      } else {
	iovec.base = (uintptr_t) buffer;
	iovec.len = length;
      }
      create[j].iovec_array = (uintptr_t) &iovec;
      create[j].iovec_nr = 1;
      create[j].flags = 0;
      create[j].protection = reverse ? PROT_WRITE : PROT_READ;
      err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create[j]);
      if (err < 0) {
	perror("ioctl (create region)");
	goto out_with_buffer;
      }
    }
  }

  for(i=0; i<iter+warmup; i++) {
    if (i == warmup)
      gettimeofday(&tv1, NULL);

    if (cache) {
      /* use existing region(s) and tell the slaves that we're ready */
      for(j=1; j<nprocs; j++) {
	volatile struct rndv_desc *out_desc = outdesc(0, j, shmbuf);
	out_desc->cookie = create[sharedregion ? 0 : j-1].cookie;
	out_desc->ready = 1;
      }
    } else if (nregions == 1) {
      /* create a single region and tell the slaves that we're ready */
      iovec.base = (uintptr_t) buffer;
      iovec.len = length;
      create[0].iovec_array = (uintptr_t) &iovec;
      create[0].iovec_nr = 1;
      create[0].flags = 0; /* cannot use KNEM_FLAG_SINGLEUSE since multiple slaves will access it once */
      create[0].protection = reverse ? PROT_WRITE : PROT_READ;
      err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create[0]);
      if (err < 0) {
	perror("ioctl (create region)");
	goto out_with_buffer;
      }
      for(j=1; j<nprocs; j++) {
	volatile struct rndv_desc *out_desc = outdesc(0, j, shmbuf);
	out_desc->cookie = create[0].cookie;
	out_desc->ready = 1;
      }
    } else {
      /* for each slave, create a region and tell it we're ready */
      for(j=0; j<nregions; j++) {
	volatile struct rndv_desc *out_desc = outdesc(0, j+1, shmbuf);
	if (split && !sharedregion) {
	  iovec.base = (uintptr_t) buffer + length/(nprocs-1) * j;
	  iovec.len = length/(nprocs-1) + (j == nregions-1 ? length%(nprocs-1) : 0);
	} else {
	  iovec.base = (uintptr_t) buffer;
	  iovec.len = length;
	}
	create[j].iovec_array = (uintptr_t) &iovec;
	create[j].iovec_nr = 1;
	create[j].flags = KNEM_FLAG_SINGLEUSE;
	create[j].protection = reverse ? PROT_WRITE : PROT_READ;
	err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create[j]);
	if (err < 0) {
	  perror("ioctl (create region)");
	  goto out_with_buffer;
        }
	out_desc->cookie = create[j].cookie;
	out_desc->ready = 1;
      }
    }

    /* wait for the slaves to be ready */
    for(j=1; j<nprocs; j++) {
      volatile struct rndv_desc *in_desc = indesc(0, j, shmbuf);
      while (!in_desc->ready)
        sched_yield();
      in_desc->ready = 0;
    }

    if (!cache && nregions == 1) {
      err = ioctl(fd, KNEM_CMD_DESTROY_REGION, &create[0].cookie);
      if (err < 0)
	perror("ioctl (destroy)");
    }
  }

  gettimeofday(&tv2, NULL);

  /* notify the slaves that we're done */
  for(j=1; j<nprocs; j++) {
    volatile struct rndv_desc *out_desc = outdesc(0, j, shmbuf);
    out_desc->ready = 1;
  }

  if (cache) {
    for(j=0; j<nregions; j++) {
      err = ioctl(fd, KNEM_CMD_DESTROY_REGION, &create[j].cookie);
      if (err < 0)
	perror("ioctl (destroy)");
    }
  }

  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  if (split)
    printf("% 9lld %s/among %d procs:\t%.3f us\t%.2f MB/s\t %.2f MiB/s\n",
	   length, reverse ? "from" : "to", nprocs-1,
	   ((float) us)/iter,
	   ((float) length)*iter/us,
	   ((float) length)*iter/us/1.048576);
  else
    printf("% 9lld %s %d procs:\t%.3f us\t%.2f MB/s\t %.2f MiB/s\n",
	   length, reverse ? "from" : "to", nprocs-1,
	   ((float) us)/iter,
	   ((float) length)*iter*(nprocs-1)/us,
	   ((float) length)*iter*(nprocs-1)/us/1.048576);

  free(create);
  free(buffer);
  return 0;

 out_with_buffer:
  free(create);
  free(buffer);
 out:
  return err;
}

static int one_slave_initiator_length(int fd, volatile knem_status_t *status_array,
				      int rank, int nprocs, volatile struct rndv_desc *shmbuf,
				      unsigned long long length, unsigned long iter, unsigned long warmup,
				      int sharedregion, int reverse, int split, unsigned long flags)
{
  volatile struct rndv_desc *in_desc = indesc(rank, 0, shmbuf);
  volatile struct rndv_desc *out_desc = outdesc(rank, 0, shmbuf);
  char *buffer;
  struct knem_cmd_param_iovec iovec;
  struct knem_cmd_inline_copy icopy;
  unsigned long i;
  unsigned long offset;
  int err;

  buffer = malloc(length);
  if (!buffer) {
    err = -1;
    goto out;
  }

  iovec.base = (uintptr_t) buffer;
  if (split) {
    iovec.len = length/(nprocs-1) + (rank == nprocs-1 ? length%(nprocs-1) : 0);
    if (sharedregion) {
      offset = length/(nprocs-1) * (rank-1);
    } else {
      offset = 0;
    }
  } else {
    iovec.len = length;
    offset = 0;
  }

  for(i=0; i<iter+warmup; i++) {
    /* wait for the master to be ready */
    while (!in_desc->ready)
      sched_yield();
    in_desc->ready = 0;

    icopy.local_iovec_array = (uintptr_t) &iovec;
    icopy.local_iovec_nr = 1;
    icopy.remote_cookie = in_desc->cookie;
    icopy.remote_offset = offset;
    icopy.write = reverse;
    icopy.flags = flags;
    icopy.async_status_index = 0;
    err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
    if (err < 0) {
      perror("ioctl (inline copy)");
      goto out_with_buffer;
    }

    if (icopy.current_status == KNEM_STATUS_PENDING) {
      while (status_array[icopy.async_status_index] == KNEM_STATUS_PENDING)
	sched_yield();
      if (status_array[icopy.async_status_index] != KNEM_STATUS_SUCCESS) {
	fprintf(stderr, "got status %d instead of %d\n", status_array[icopy.async_status_index], KNEM_STATUS_SUCCESS);
	goto out_with_buffer;
      }
    } else if (icopy.current_status != KNEM_STATUS_SUCCESS) {
      fprintf(stderr, "got status %d instead of %d\n", icopy.current_status, KNEM_STATUS_SUCCESS);
      goto out_with_buffer;
    }

    /* tell the master that we are ready */
    out_desc->ready = 1;
  }

  /* wait for the other side to be done before exiting */
  while (!in_desc->ready)
    sched_yield();
  in_desc->ready = 0;

  free(buffer);
  return 0;

 out_with_buffer:
  free(buffer);
 out:
  return err;
}

/**********************************
 * Master-initiated communications
 *
 * The targets (slaves) create regions,
 * pass their cookie to the data transfer initiator (master),
 * and destroy the regions when the master is done
 */

static int one_master_initiator_length(int fd, volatile knem_status_t *status_array,
				       int nprocs, volatile struct rndv_desc *shmbuf,
				       unsigned long long length, unsigned long iter, unsigned long warmup,
				       int reverse, int split, int flags)
{
  char *buffer;
  struct knem_cmd_param_iovec *iovec;
  struct knem_cmd_inline_copy *icopy;
  struct timeval tv1,tv2;
  unsigned long long us;
  unsigned long i;
  int j;
  int err;

  icopy = malloc((nprocs-1)*sizeof(*icopy));
  if (!icopy) {
    err = -ENOMEM;
    goto out;
  }

  iovec = malloc((nprocs-1)*sizeof(*iovec));
  if (!iovec) {
    err = -ENOMEM;
    goto out_with_icopy;
  }

  buffer = malloc(length);
  if (!buffer) {
    err = -ENOMEM;
    goto out_with_iovec;
  }

  for(i=0; i<iter+warmup; i++) {
    if (i == warmup)
      gettimeofday(&tv1, NULL);

    /* wait for the slaves to be ready */
    for(j=1; j<nprocs; j++) {
      volatile struct rndv_desc *in_desc = indesc(0, j, shmbuf);
      while (!in_desc->ready)
        sched_yield();

      /* submit all data transfers */
      if (split) {
	iovec[j-1].base = (uintptr_t) buffer + length/(nprocs-1) * (j-1);
	iovec[j-1].len = length/(nprocs-1) + (j == nprocs-1 ? length%(nprocs-1) : 0);
      } else {
	iovec[j-1].base = (uintptr_t) buffer;
	iovec[j-1].len = length;
      }
      icopy[j-1].local_iovec_array = (uintptr_t) &iovec[j-1];
      icopy[j-1].local_iovec_nr = 1;
      icopy[j-1].remote_cookie = in_desc->cookie;
      icopy[j-1].remote_offset = 0;
      icopy[j-1].write = !reverse;
      icopy[j-1].flags = flags;
      icopy[j-1].async_status_index = j-1;
      err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy[j-1]);
      if (err < 0) {
        perror("ioctl (inline copy)");
        goto out_with_buffer;
      }

      in_desc->ready = 0;
    }

    /* wait for all data transfers to be done */
    for(j=1; j<nprocs; j++) {
      if (icopy[j-1].current_status == KNEM_STATUS_PENDING) {
	while (status_array[icopy[j-1].async_status_index] == KNEM_STATUS_PENDING)
	  sched_yield();
	if (status_array[icopy[j-1].async_status_index] != KNEM_STATUS_SUCCESS) {
	  fprintf(stderr, "got status %d instead of %d\n", status_array[icopy[j-1].async_status_index], KNEM_STATUS_SUCCESS);
	  goto out_with_buffer;
	}
      } else if (icopy[j-1].current_status != KNEM_STATUS_SUCCESS) {
	fprintf(stderr, "got status %d instead of %d\n", icopy[j-1].current_status, KNEM_STATUS_SUCCESS);
	goto out_with_buffer;
      }
    }

    /* the slaves that we're ready */
    for(j=1; j<nprocs; j++) {
      volatile struct rndv_desc *out_desc = outdesc(0, j, shmbuf);
      out_desc->ready = 1;
    }
  }

  gettimeofday(&tv2, NULL);

  /* wait for the slaves to be done before exiting */
  for(j=1; j<nprocs; j++) {
    volatile struct rndv_desc *in_desc = indesc(0, j, shmbuf);
    while (!in_desc->ready)
      sched_yield();
    in_desc->ready = 0;
  }

  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  if (split)
    printf("% 9lld %s/among %d procs:\t%.3f us\t%.2f MB/s\t %.2f MiB/s\n",
	   length, reverse ? "from" : "to", nprocs-1,
	   ((float) us)/iter,
	   ((float) length)*iter/us,
	   ((float) length)*iter/us/1.048576);
  else
    printf("% 9lld %s %d procs:\t%.3f us\t%.2f MB/s\t %.2f MiB/s\n",
	   length, reverse ? "from" : "to", nprocs-1,
	   ((float) us)/iter,
	   ((float) length)*iter*(nprocs-1)/us,
	   ((float) length)*iter*(nprocs-1)/us/1.048576);

  free(buffer);
  free(iovec);
  free(icopy);
  return 0;

 out_with_buffer:
  free(buffer);
 out_with_iovec:
  free(iovec);
 out_with_icopy:
  free(icopy);
 out:
  return err;
}

static int one_slave_target_length(int fd,
				   int rank, int nprocs, volatile struct rndv_desc *shmbuf,
				   unsigned long long length, unsigned long iter, unsigned long warmup,
				   int cache, int reverse, int split)
{
  volatile struct rndv_desc *in_desc = indesc(rank, 0, shmbuf);
  volatile struct rndv_desc *out_desc = outdesc(rank, 0, shmbuf);
  char *buffer;
  struct knem_cmd_param_iovec iovec;
  struct knem_cmd_create_region create;
  unsigned long i;
  int err;

  buffer = malloc(length);
  if (!buffer) {
    err = -ENOMEM;
    goto out;
  }

  iovec.base = (uintptr_t) buffer;
  if (split)
    iovec.len = length/(nprocs-1) + (rank == nprocs-1 ? length%(nprocs-1) : 0);
  else
    iovec.len = length;

  if (cache) {
    create.iovec_array = (uintptr_t) &iovec;
    create.iovec_nr = 1;
    create.flags = 0;
    create.protection = reverse ? PROT_READ : PROT_WRITE;
    err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
    if (err < 0) {
      perror("ioctl (create region)");
      goto out_with_buffer;
    }
  }

  for(i=0; i<iter+warmup; i++) {

    if (!cache) {
      create.iovec_array = (uintptr_t) &iovec;
      create.iovec_nr = 1;
      create.flags = KNEM_FLAG_SINGLEUSE;
      create.protection = reverse ? PROT_READ : PROT_WRITE;
      err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
      if (err < 0) {
	perror("ioctl (create region)");
	goto out_with_buffer;
      }
    }

    /* tell the master that we are ready */
    out_desc->cookie = create.cookie;
    out_desc->ready = 1;

    /* wait for the master to be ready */
    while (!in_desc->ready)
      sched_yield();
    in_desc->ready = 0;
  }

  /* notify the master that we're done */
  out_desc->ready = 1;

  if (cache) {
    err = ioctl(fd, KNEM_CMD_DESTROY_REGION, &create.cookie);
    if (err < 0)
      perror("ioctl (destroy)");
  }

  free(buffer);
  return 0;

 out_with_buffer:
  free(buffer);
 out:
  return err;
}

/************
 * Main
 */

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
  char *binding = NULL;
  volatile knem_status_t *status_array;
  volatile void *shared_buffer;
  int reverse = 0;
  int cache = 0;
  int sharedregion = 1;
  cpu_set_t cpuset;
  struct knem_cmd_info info;
  int fd, err = 0;
  int c;
  int rank, i, bindcpu;
  int nprocs = 0;
  int split = 0;
  int master_initiator = 0;
  pid_t *pids;

  hwloc_init();
  nprocs = hwloc_get_nprocs();

  while ((c = getopt(argc, argv, "p:b:S:E:M:I:N:W:P:F:smDCcRh")) != -1)
    switch (c) {
    case 'p':
      nprocs = atoi(optarg);
      break;
    case 'b':
      binding = strdup(optarg);
      break;
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
    case 'c':
      sharedregion = 0;
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
    case 's':
      split = 1;
      break;
    case 'm':
      master_initiator = 1;
      break;
    default:
      fprintf(stderr, "Unknown option -%c\n", c);
      /* fallthru */
    case 'h':
      usage(argv, nprocs);
      exit(-1);
      break;
    }

  if (nprocs == 1) {
    fprintf(stderr, "nothing to do with a single process\n");
    err = 0;
    goto out;
  }

  pids = malloc((nprocs-1) * sizeof(*pids));
  if (!pids) {
    fprintf(stderr, "malloc pids\n");
    err = 1;
    goto out;
  }

  shared_buffer = mmap(NULL, 2*(nprocs-1)*sizeof(struct rndv_desc), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  if (shared_buffer == MAP_FAILED) {
    perror("mmap shared buffer");
    err = 1;
    goto out_with_pids;
  }
  memset((void *) shared_buffer, 0, 2*(nprocs-1)*sizeof(struct rndv_desc));

  rank = 0; /* father is rank 0 */
  for(i=0; i<nprocs-1; i++) {
    err = fork();
    if (err < 0) {
      perror("fork");
      nprocs = i+1;
      goto out_with_fork;
    }
    if (!err) {
      rank = i+1;
      break;
    }
    pids[i] = err;
  }

  bindcpu = -1;
  if (binding) {
    char *tmp = binding;
    for(i=0; i<rank; i++) {
      tmp = strchr(tmp, ',');
      if (!tmp)
	/* no such slot, do not bind */
	break;
      tmp++;
    }
    if (tmp && *tmp != ',' && *tmp != '\0')
      bindcpu = atoi(tmp);
  } else {
    bindcpu = hwloc_get_rank_bindcpu(rank);
  }
  if (bindcpu != -1) {
    CPU_ZERO(&cpuset);
    CPU_SET(bindcpu, &cpuset);
    err = sched_setaffinity(0, sizeof(cpuset), &cpuset);
    if (err < 0) {
      fprintf(stderr, "rank %d: failed to bind process on processor #%d\n", rank, bindcpu);
      /* fallback */
    }
  }

  fd = open("/dev/knem", O_RDWR);
  if (fd < 0) {
    perror("open");
    goto out_with_fork;
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
    fprintf(stderr, "rank %d: DMA support not available, ignoring it\n", rank);
    flags &= ~KNEM_FLAG_DMA;
  }

  status_array = mmap(NULL, nprocs-1, PROT_READ|PROT_WRITE, MAP_SHARED, fd, KNEM_STATUS_ARRAY_FILE_OFFSET);
  if (status_array == MAP_FAILED) {
    perror("mmap status_array");
    goto out_with_fd;
  }

  if (!rank) {
    printf("aggregate throughput moving %s %s master (rank 0) %s slaves (ranks 1-%d)\n",
	   split ? "buffer chunks" : "entire buffer",
	   reverse ? "to" : "from",
	   reverse ? "from" : "to",
           nprocs-1);
    printf("processing data transfers in %s\n", master_initiator ? "master process" : "slave processes");
  }

  for(length = min;
      length < max;
      length = next_length(length, multiplier, increment)) {
    usleep(pause_ms * 1000);
    if (master_initiator) {
      if (!rank)
	err = one_master_initiator_length(fd, status_array, nprocs, shared_buffer, length, iter, warmup, reverse, split, flags);
      else
	err = one_slave_target_length(fd, rank, nprocs, shared_buffer, length, iter, warmup, cache, reverse, split);
    } else {
      if (!rank)
	err = one_master_target_length(fd, nprocs, shared_buffer, length, iter, warmup, cache, sharedregion, reverse, split);
      else
	err = one_slave_initiator_length(fd, status_array, rank, nprocs, shared_buffer, length, iter, warmup, sharedregion, reverse, split, flags);
    }
    if (err < 0)
      goto out_with_fd;
  }

  err = 0;

 out_with_fd:
  close(fd);
 out_with_fork:
  if (!rank) {
    for(i=0; i<nprocs-1; i++) {
      kill(pids[i], SIGKILL);
      waitpid(pids[i], NULL, 0);
    }
  }
 out_with_pids:
  free(pids);
 out:
  free(binding);
  hwloc_exit();
  return err;
}
