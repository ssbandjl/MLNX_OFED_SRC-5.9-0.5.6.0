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

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "knem_io.h"

#define TOTAL_PAGES 65536
#define BIG_PAGES 256

static void
usage(char *argv[])
{
  fprintf(stderr, "%s [options]\n", argv[0]);
  fprintf(stderr, " -P <n>\ttotal number of pages to operate on [%d]\n", TOTAL_PAGES);
  fprintf(stderr, " -B <n>\tnumber of pages for large regions [%d]\n", BIG_PAGES);
}

int main(int argc, char * argv[])
{
  char *buffer;
  unsigned long pagesize = getpagesize();
  unsigned long total_pages = TOTAL_PAGES;
  unsigned long big_pages = BIG_PAGES;
  knem_cookie_t *cookies;
  struct knem_cmd_param_iovec iovec;
  struct knem_cmd_create_region create;
  struct timeval tv1, tv2;
  unsigned long long us, ns;
  unsigned long long createsmallns, createbigns, destroysmallns, destroybigns;
  unsigned long long createbasens, createpagens, destroybasens, destroypagens;
  char c;
  int fd;
  unsigned long i;
  int err;

  while ((c = getopt(argc, argv, "P:B:h")) != -1)
    switch (c) {
    case 'P':
      total_pages = atoi(optarg);
      break;
    case 'B':
      big_pages = atoi(optarg);
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
    exit(-1);
  }

  buffer = memalign(pagesize, pagesize*total_pages);
  memset(buffer, 0, pagesize*total_pages);
  cookies = malloc(total_pages * sizeof(knem_cookie_t));

  gettimeofday(&tv1, NULL);
  for(i=0; i<total_pages; i++) {
    iovec.base = (uintptr_t) buffer + pagesize*i;
    iovec.len = pagesize;
    create.iovec_array = (uintptr_t) &iovec;
    create.iovec_nr = 1;
    create.flags = 0;
    create.protection = PROT_READ;
    err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
    assert(!err);
    cookies[i] = create.cookie;
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/total_pages;
  printf("created %ld 1-page regions %lld us => %lld ns\n", total_pages, us, ns);
  createsmallns = ns;


  gettimeofday(&tv1, NULL);
  for(i=0; i<total_pages; i++) {
    err = ioctl(fd, KNEM_CMD_DESTROY_REGION, &cookies[i]);
    assert(!err);
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/total_pages;
  printf("destroyed %ld 1-page regions %lld us => %lld ns\n", total_pages, us, ns);
  destroysmallns = ns;


  gettimeofday(&tv1, NULL);
  for(i=0; i<total_pages/big_pages; i++) {
    iovec.base = (uintptr_t) buffer + pagesize*i*big_pages;
    iovec.len = pagesize*big_pages;
    create.iovec_array = (uintptr_t) &iovec;
    create.iovec_nr = 1;
    create.flags = 0;
    create.protection = PROT_READ;
    err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
    assert(!err);
    cookies[i] = create.cookie;
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/(total_pages/big_pages);
  printf("created %ld %ld-pages regions %lld us => %lld ns\n", total_pages/big_pages, big_pages, us, ns);
  createbigns = ns;


  gettimeofday(&tv1, NULL);
  for(i=0; i<total_pages/big_pages; i++) {
    err = ioctl(fd, KNEM_CMD_DESTROY_REGION, &cookies[i]);
    assert(!err);
  }
  gettimeofday(&tv2, NULL);
  us = (tv2.tv_sec-tv1.tv_sec)*1000000 + (tv2.tv_usec-tv1.tv_usec);
  ns = us*1000/(total_pages/big_pages);
  printf("destroyed %ld %ld-pages regions %lld us => %lld ns\n", total_pages/big_pages, big_pages, us, ns);
  destroybigns = ns;

  if (destroybigns < destroysmallns)
    destroysmallns = destroybigns;


  createpagens = (createbigns-createsmallns)/(big_pages-1);
  createbasens = createsmallns-createpagens;
  destroypagens = (destroybigns-destroysmallns)/(big_pages-1);
  destroybasens = destroysmallns-destroypagens;
  printf("create  = %lld base + %lld per page\n", createbasens, createpagens);
  printf("destroy = %lld base + %lld per page\n", destroybasens, destroypagens);

  close(fd);
  free(buffer);
  free(cookies);
  return 0;
}
