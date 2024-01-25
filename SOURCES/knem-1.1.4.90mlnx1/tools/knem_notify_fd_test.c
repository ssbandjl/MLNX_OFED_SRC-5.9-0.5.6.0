/*
 * Copyright © inria 2009-2013
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
#include <poll.h>

#include "knem_io.h"

#define LEN 128*1024
#define NSTATUS 4096

static int fd;
static volatile knem_status_t *sarray;
static uint32_t events[NSTATUS*3];

static int submit(int nr, int first, knem_cookie_t cookie1, knem_cookie_t cookie2, int testmore)
{
  struct knem_cmd_copy copy;
  int err, i;

  printf("submitting %d copies (%d-%d)\n", NSTATUS, first, first+nr-1);

  copy.src_cookie = cookie1;
  copy.src_offset = 0;
  copy.dst_cookie = cookie2;
  copy.dst_offset = 0;
  copy.flags = KNEM_FLAG_MEMCPYTHREAD | KNEM_FLAG_NOTIFY_FD;
  for(i=first; i<first+nr; i++) {
    copy.async_status_index = NSTATUS-(i%NSTATUS)-1;
    err = ioctl(fd, KNEM_CMD_COPY, &copy);
    if (err < 0) {
      perror("ioctl (copy)");
      return err;
    }
  }

  if (testmore) {
    /* too many notityfd events, this one will be rejected */
    printf("submitting one impossible copy\n");
    err = ioctl(fd, KNEM_CMD_COPY, &copy);
    assert(err == -1);
    assert(errno == EBUSY);
  }

  return nr;
}

static void check_events(int nr, int first)
{
  int i;
  for(i=first; i<first+nr; i++) {
    if (events[i] != (uint32_t) NSTATUS-(i%NSTATUS)-1) {
      printf("event#%d contains %u instead of %u\n",
	     i, (unsigned) events[i], (unsigned) NSTATUS-(i%NSTATUS)-1);
      assert(0);
    }
    if (sarray[NSTATUS-(i%NSTATUS)-1] != KNEM_STATUS_SUCCESS) {
      printf("status#%u contains %d instead of %d\n",
	     (unsigned) NSTATUS-(i%NSTATUS)-1, (int) sarray[NSTATUS-(i%NSTATUS)-1], KNEM_STATUS_SUCCESS);
      assert(0);
    }
  }
}

static int get_blocking(int nr, int first)
{
  int err;

  err = fcntl(fd, F_GETFL) & O_NONBLOCK;
  assert(!err);

  err = read(fd, events+first, sizeof(uint32_t)*nr);
  assert(err >= 0);
  err /= sizeof(uint32_t);
  assert(err == nr);
  printf("got %d events (%d-%d)\n", err, first, first+err-1);
  check_events(err, first);
  return err;
}

static int get_nonblocking(int nr, int first)
{
  int err;

  err = fcntl(fd, F_GETFL) & O_NONBLOCK;
  assert(err == O_NONBLOCK);

  err = read(fd, events+first, sizeof(uint32_t)*nr);
  if (err < 0) {
    assert(errno == EAGAIN);
    printf("got 0 events\n");
    return 0;
  }

  err /= sizeof(uint32_t);
  assert(err <= nr);
  printf("got %d events (%d-%d)\n", err, first, first+err-1);
  check_events(err, first);
  return err;
}

static void poll_blocking(void)
{
  struct pollfd p;
  int err;
  p.fd = fd;
  p.events = POLLIN;
  err = poll(&p, 1, -1);
  assert(err == 1);
  assert(p.revents & POLLIN);
}

int main()
{
  struct knem_cmd_info info;
  int err;
  char *send_buffer, *recv_buffer;
  knem_cookie_t cookie1, cookie2;
  struct knem_cmd_param_iovec send_iovec, recv_iovec;
  struct knem_cmd_create_region create;
  int got, submitted, goal;

  send_buffer = malloc(LEN*2);
  if (!send_buffer)
    goto out;
  recv_buffer = send_buffer+LEN;

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

  sarray = mmap(NULL, NSTATUS*sizeof(knem_status_t), PROT_READ|PROT_WRITE, MAP_SHARED, fd, KNEM_STATUS_ARRAY_FILE_OFFSET);
  if (sarray == MAP_FAILED) {
    perror("mmap status array");
    goto out_with_fd;
  }

  create.iovec_nr = 1;
  create.flags = 0;
  create.protection = PROT_WRITE | PROT_READ;

  send_iovec.base = (uintptr_t) send_buffer;
  send_iovec.len = LEN;
  create.iovec_array = (uintptr_t) &send_iovec;
  err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create region)");
    exit(1);
  }
  cookie1 = create.cookie;

  recv_iovec.base = (uintptr_t) recv_buffer;
  recv_iovec.len = LEN;
  create.iovec_array = (uintptr_t) &recv_iovec;
  err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create region)");
    exit(1);
  }
  cookie2 = create.cookie;

  submitted = 0;
  got = 0;

  /* submit NSTATUS copies */
  err = submit(NSTATUS, submitted, cookie1, cookie2, 1);
  assert(err == NSTATUS);
  submitted += err;

  /* (blocking) read 1/2 of the events */
  printf("(blocking) reading %d events\n", NSTATUS/4);
  got += get_blocking(NSTATUS/4, got);
  assert(got == NSTATUS/4); /* we got NSTATUS/4 now */

  /* switch to non-blocking reads */
  err = fcntl(fd, F_SETFL, O_NONBLOCK);
  assert(!err);

  /* (non-blocking) try to read 1/4 of the events */
  printf("(non-blocking) reading %d events\n", NSTATUS/4);
  got += get_nonblocking(NSTATUS/4, got);

  /* poll + read until we get 3/4 */
  goal = NSTATUS*3/4;
  while (got < goal) {
    printf("polling for new events\n");
    poll_blocking();
    printf("(non-blocking) reading %d events\n", goal-got);
    got += get_nonblocking(goal-got, got);
  }
  assert(got == NSTATUS*3/4); /* we got NSTATUS*3/4 now */

  /* submit NSTATUS*3/4 additional copies, reusing the just released status slots */
  err = submit(NSTATUS*3/4, submitted, cookie1, cookie2, 0);
  assert(err == NSTATUS*3/4);
  submitted += err;
  assert(submitted == NSTATUS*7/4); /* we have submitted NSTATUS*7/4 now */

  /* sleep a bit and read, until we get to NSTATUS */
  goal = NSTATUS;
  while (got < goal) {
    printf("sleeping 1s\n");
    sleep(1);
    printf("(non-blocking) reading %d events\n", goal-got);
    got += get_nonblocking(goal-got, got);
  }
  assert(got == NSTATUS); /* we got NSTATUS now */
  
  /* submit NSTATUS*1/4 additional copies, reusing the just released status slots */
  err = submit(NSTATUS/4, submitted, cookie1, cookie2, 0);
  assert(err == NSTATUS/4);
  submitted += err;
  assert(submitted == NSTATUS*2); /* we have submitted NSTATUS*2 now */

  /* poll + read until we get 3/2*NSTATUS */
  goal = NSTATUS*3/2;
  while (got < goal) {
    printf("polling for new events\n");
    poll_blocking();
    printf("(non-blocking) reading %d events\n", goal-got);
    got += get_nonblocking(goal-got, got);
  }
  assert(got == NSTATUS*3/2); /* we got NSTATUS*3/2 now */

  /* submit NSTATUS*1/2 additional copies, reusing the just released status slots */
  err = submit(NSTATUS/2, submitted, cookie1, cookie2, 0);
  assert(err == NSTATUS/2);
  submitted += err;
  assert(submitted == NSTATUS*5/2); /* we have submitted NSTATUS*5/2 now */

  goal = NSTATUS*5/2;
  /* (non-blocking) read the remaining events */
  printf("(non-blocking) reading %d events\n", goal-got);
  got += get_nonblocking(goal-got, got);
  /* switch back to blocking reads */
  err = fcntl(fd, F_SETFL, 0);
  assert(!err);
  /* (blocking) read the remaining events */
  printf("(blocking) reading %d events\n", goal-got);
  got += get_blocking(goal-got, got);
  assert(got == NSTATUS*5/2); /* we got NSTATUS*5/2 now */

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
