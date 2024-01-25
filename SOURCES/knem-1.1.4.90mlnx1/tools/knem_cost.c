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
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "knem_io.h"

#define CONTEXTS 1000
#define REGIONS	100000
#define LOOKUPS 100000

static void
usage(char *argv[])
{
  fprintf(stderr, "%s [options]\n", argv[0]);
  fprintf(stderr, " -C <n>\tcreate <n> contexts [%d]\n", CONTEXTS);
  fprintf(stderr, " -R <n>\tcreate <n> regions in the last context [%d]\n", REGIONS);
  fprintf(stderr, " -L <n>\tlookup <n> times [%d]\n", LOOKUPS);
}

int main(int argc, char * argv[])
{
  int nr_contexts = CONTEXTS;
  int nr_cookies = REGIONS;
  int nr_lookups = LOOKUPS;
  knem_cookie_t *cookies;
  int *fds;
  char buffer[1];
  struct knem_cmd_param_iovec iovec = { .base = (uintptr_t) buffer, .len = 1 };
  struct knem_cmd_create_region create;
  struct knem_cmd_inline_copy icopy;
  struct timeval tv1, tv2;
  unsigned long long us, ns;
  char c;
  int i;
  int err;

  while ((c = getopt(argc, argv, "C:R:L:h")) != -1)
    switch (c) {
    case 'C':
      nr_contexts = atoi(optarg);
      break;
    case 'R':
      nr_cookies = atoi(optarg);
      break;
    case 'L':
      nr_lookups = atoi(optarg);
      break;
    default:
      fprintf(stderr, "Unknown option -%c\n", c);
      /* fallthru */
    case 'h':
      usage(argv);
      exit(-1);
      break;
    }

  create.iovec_array = (uintptr_t) &iovec;
  create.iovec_nr = 1;
  create.flags = 0;
  create.protection = PROT_READ;

  icopy.local_iovec_array = (uintptr_t) &iovec;
  icopy.local_iovec_nr = 1;
  icopy.remote_offset = 0;
  icopy.write = 0;
  icopy.flags = 0;
  icopy.async_status_index = -1;

  fds = malloc(nr_contexts * sizeof(*fds));
  if (!fds)
    goto out;

  cookies = malloc(nr_cookies * sizeof(*cookies));
  if (!cookies)
    goto out_with_fds;

  /* open many contexts */

  gettimeofday(&tv1, NULL);
  for(i=0; i<nr_contexts; i++) {
    fds[i] = open("/dev/knem", O_RDWR);
    if (fds[i] < 0) {
      perror("open");
      exit(-1);
    }
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/nr_contexts;
  printf("open %d contexts in %lld us => %lld ns\n", nr_contexts, us, ns);

  /* create many regions in last context */

  gettimeofday(&tv1, NULL);
  for(i=0; i<nr_cookies; i++) {
    err = ioctl(fds[nr_contexts-1], KNEM_CMD_CREATE_REGION, &create);
    assert(!err);
    cookies[i] = create.cookie;
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/nr_cookies;
  printf("created %d regions in last context in %lld us => %lld ns\n", nr_cookies, us, ns);

  /* submit many copies with invalid context id */

  icopy.remote_cookie = 0;

  gettimeofday(&tv1, NULL);
  for(i=0; i<nr_lookups; i++) {
    err = ioctl(fds[nr_contexts-1], KNEM_CMD_INLINE_COPY, &icopy);
    assert(err < 0 && errno == EINVAL);
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/nr_lookups;
  printf("%d failed lookups in %lld us => %lld ns\n", nr_lookups, us, ns);

  /* open and close a new region to get an invalid cookie with valid context id */
  err = ioctl(fds[nr_contexts-1], KNEM_CMD_CREATE_REGION, &create);
  assert(!err);
  err = ioctl(fds[nr_contexts-1], KNEM_CMD_DESTROY_REGION, &create.cookie);
  assert(!err);

  /* submit many copies with invalid cookie but valid context id */

  icopy.remote_cookie = create.cookie;
  gettimeofday(&tv1, NULL);
  for(i=0; i<nr_lookups; i++) {
    err = ioctl(fds[nr_contexts-1], KNEM_CMD_INLINE_COPY, &icopy);
    assert(err < 0 && errno == EINVAL);
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/nr_lookups;
  printf("%d failed lookups in last context in %lld us => %lld ns\n", nr_lookups, us, ns);

  /* submit many copies with valid cookie */

  icopy.remote_cookie = cookies[nr_cookies-1];
  gettimeofday(&tv1, NULL);
  for(i=0; i<nr_lookups; i++) {
    err = ioctl(fds[nr_contexts-1], KNEM_CMD_INLINE_COPY, &icopy);
    assert(!err && icopy.current_status == KNEM_STATUS_SUCCESS);
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/nr_lookups;
  printf("%d 1-byte copies in last region of last context in %lld us => %lld ns\n", nr_lookups, us, ns);

  /* close all regions */

  gettimeofday(&tv1, NULL);
  for(i=0; i<nr_cookies; i++) {
    err = ioctl(fds[nr_contexts-1], KNEM_CMD_DESTROY_REGION, &cookies[i]);
    assert(!err);
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/nr_cookies;
  printf("closed %d regions in last context in %lld us => %lld ns\n", nr_cookies, us, ns);

  /* close all contexts */

  gettimeofday(&tv1, NULL);
  for(i=0; i<nr_contexts; i++) {
    err = close(fds[i]);
    assert(!err);
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/nr_contexts;
  printf("closed %d contexts in %lld us => %lld ns\n", nr_contexts, us, ns);

  free(cookies);
 out_with_fds:
  free(fds);
 out:
  return 0;
}
