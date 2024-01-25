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
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "knem_io.h"

#define LEN 8388608

#define SENDER_IGNORED_CHAR 'a'
#define SENDER_CHAR 'b'
#define RECEIVER_IGNORED_CHAR 'c'
#define RECEIVER_CHAR 'c'

static void
usage(char *argv[])
{
  fprintf(stderr, "%s [options]\n", argv[0]);
  fprintf(stderr, " -A <n>\tchange send/recv buffer relative alignments [%d]\n", 0);
  fprintf(stderr, " -d\tenable DMA engine\n");
  fprintf(stderr, " -F <n>\tadd copy command flags\n");
  fprintf(stderr, " -R\twrite from the source instead of reading from the destination\n");
}

int main(int argc, char * argv[])
{
  struct knem_cmd_info info;
  int fd, err;
  char *send_buffer, *recv_buffer;
  struct knem_cmd_param_iovec send_iovec[5], recv_iovec[5];
  struct knem_cmd_create_region create;
  struct knem_cmd_inline_copy copy;
  unsigned long missalign = 0;
  unsigned long flags = 0;
  int reverse = 0;
  int tmplen, totallen;
  int i,j,k;
  int last_copied;
  char c;

  while ((c = getopt(argc, argv, "A:dRF:h")) != -1)
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
    case 'R':
      reverse = 1;
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

  send_iovec[0].base = (uintptr_t) send_buffer + 53;
  send_iovec[0].len = 7; /* total = 7 */
  send_iovec[1].base = (uintptr_t) send_buffer + 100;
  send_iovec[1].len = 253; /* total = 260 */
  send_iovec[2].base = (uintptr_t) send_buffer + 1000;
  send_iovec[2].len = 14567; /* total = 14827 */
  send_iovec[3].base = (uintptr_t) send_buffer + 20000;
  send_iovec[3].len = 123456; /* total = 138283 */
  send_iovec[4].base = (uintptr_t) send_buffer + 1000000;
  send_iovec[4].len = 3333333; /* total = 3471616 */
  tmplen = 0;
  for(i=0; i<5; i++)
    tmplen += send_iovec[i].len;
  totallen = tmplen;

  recv_iovec[0].base = (uintptr_t) recv_buffer + 10;
  recv_iovec[0].len = 3333333; /* total = 3333333 */
  recv_iovec[1].base = (uintptr_t) recv_buffer + 3500000;
  recv_iovec[1].len = 12345; /* total = 3345678 */
  recv_iovec[2].base = (uintptr_t) recv_buffer + 3600000;
  recv_iovec[2].len = 253; /* total = 3345931 */
  recv_iovec[3].base = (uintptr_t) recv_buffer + 3700000;
  recv_iovec[3].len = 86523; /* total = 3432454 */
  recv_iovec[4].base = (uintptr_t) recv_buffer + 3800000;
  recv_iovec[4].len = 7; /* total = 3432461 */
  tmplen = 0;
  for(i=0; i<5; i++)
    tmplen += recv_iovec[i].len;
  totallen = tmplen < totallen ? tmplen : totallen;

  /* the last 39155 bytes of recv_iovec won't be touched */

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

  if (flags & KNEM_FLAG_DMA && !(info.features & KNEM_FEATURE_DMA)) {
    fprintf(stderr, "DMA support not available, ignoring it\n");
    flags &= ~KNEM_FLAG_DMA;
  }

  memset(send_buffer, SENDER_IGNORED_CHAR, LEN);
  for(i=0; i<5; i++)
    memset((void *)(uintptr_t) send_iovec[i].base, SENDER_CHAR, send_iovec[i].len);
  memset(recv_buffer, RECEIVER_IGNORED_CHAR, LEN);
  for(i=0; i<5; i++)
    memset((void *)(uintptr_t) recv_iovec[i].base, RECEIVER_CHAR, recv_iovec[i].len);

  create.iovec_array = reverse ? (uintptr_t) recv_iovec : (uintptr_t) send_iovec;
  create.iovec_nr = 5;
  create.flags = KNEM_FLAG_SINGLEUSE;
  create.protection = reverse ? PROT_WRITE : PROT_READ;
  err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create)");
    goto out_with_fd;
  }
  printf("got cookie %llx\n", (unsigned long long) create.cookie);

  printf("copying with flags %lx write %d\n", flags, reverse);
  copy.local_iovec_array = reverse ? (uintptr_t) send_iovec : (uintptr_t) recv_iovec;
  copy.local_iovec_nr = 5;
  copy.write = reverse;
  copy.remote_cookie = create.cookie;
  copy.remote_offset = 0;
  copy.flags = flags;
  err = ioctl(fd, KNEM_CMD_INLINE_COPY, &copy);
  if (err < 0) {
    perror("ioctl (inline copy)");
    goto out_with_fd;
  }

  if (copy.current_status != KNEM_STATUS_SUCCESS) {
    fprintf(stderr, "got status %d instead of %d\n", copy.current_status, KNEM_STATUS_SUCCESS);
    goto out_with_fd;
  }

  /* check that the receiver contains either unchanged or the sender char */

  for(i=0; i<LEN; i++)
    if (recv_buffer[i] != RECEIVER_CHAR && recv_buffer[i] != RECEIVER_IGNORED_CHAR && recv_buffer[i] != SENDER_CHAR)
      printf("invalid char at offset %d, got %c\n", i, recv_buffer[i]);

  last_copied = -1;
  k=0;
  for(j=0; j<5; j++) {
    char * buffer = (void *)(uintptr_t) recv_iovec[j].base;
    for(i=0; i<(int)recv_iovec[j].len; i++, k++) {
      if (buffer[i] != RECEIVER_CHAR && buffer[i] != SENDER_CHAR)
	printf("invalid char at offset %d segment %d, got %c\n", i, j, buffer[i]);
      if (buffer[i] == SENDER_CHAR) {
	if (last_copied != k-1)
	  printf("got a modified char at %d while the last one was at %d\n", k, last_copied-1);
	last_copied = k;
      }
    }
  }
  printf("last properly copied at %d\n", last_copied);
  if (last_copied+1 != totallen) {
    printf("should have been %d\n", totallen-1);
    goto out_with_fd;
  } else
    printf("looks good\n");

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
