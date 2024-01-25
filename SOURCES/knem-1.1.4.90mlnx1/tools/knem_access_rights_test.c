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

#include "knem_io.h"

int main(int argc, char *argv[])
{
  struct knem_cmd_info info;
  int fd, err;
  char buffer[1];
  knem_cookie_t cookie_rw, cookie_w, cookie_r_anyuser;
  struct knem_cmd_param_iovec iovec;
  struct knem_cmd_create_region create;
  struct knem_cmd_inline_copy icopy;
  int uid = 0;

  if (argc > 1)
    uid = atoi(argv[1]);

  iovec.base = (uintptr_t) buffer;
  iovec.len = 1;

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
  printf("got driver ABI %lx and feature mask %lx\n",
	 (unsigned long) info.abi, (unsigned long) info.features);

  create.iovec_array = (uintptr_t) &iovec;
  create.iovec_nr = 1;

  create.flags = 0;
  create.protection = PROT_READ | PROT_WRITE;
  err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create region rw)");
    exit(1);
  }
  cookie_rw = create.cookie;

  create.flags = 0;
  create.protection = PROT_WRITE;
  err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create region w)");
    exit(1);
  }
  cookie_w = create.cookie;

  create.flags = KNEM_FLAG_ANY_USER_ACCESS;
  create.protection = PROT_READ;
  err = ioctl(fd, KNEM_CMD_CREATE_REGION, &create);
  if (err < 0) {
    perror("ioctl (create region w anyuser)");
    exit(1);
  }
  cookie_r_anyuser = create.cookie;

  icopy.local_iovec_array = (uintptr_t) &iovec;
  icopy.local_iovec_nr = 1;
  icopy.remote_offset = 0;

  /* read from cookie_rw must succeed */
  icopy.remote_cookie = cookie_rw;
  icopy.write = 0;
  icopy.flags = 0;
  err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
  assert(!err);
  assert(icopy.current_status == KNEM_STATUS_SUCCESS);
  printf("read from RW succeeded\n");

  /* write to cookie_rw must succeed */
  icopy.remote_cookie = cookie_rw;
  icopy.write = 1;
  icopy.flags = 0;
  err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
  assert(!err);
  assert(icopy.current_status == KNEM_STATUS_SUCCESS);
  printf("write to RW succeeded\n");

  /* read from cookie_w must fail */
  icopy.remote_cookie = cookie_w;
  icopy.write = 0;
  icopy.flags = 0;
  err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
  assert(err < 0);
  assert(errno == EACCES);
  printf("read from W failed as expected\n");

  /* write to cookie_w must succeed */
  icopy.remote_cookie = cookie_w;
  icopy.write = 1;
  icopy.flags = 0;
  err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
  assert(!err);
  assert(icopy.current_status == KNEM_STATUS_SUCCESS);
  printf("write to W succeeded\n");

  /* read from cookie_r_anyuser must succeed */
  icopy.remote_cookie = cookie_r_anyuser;
  icopy.write = 0;
  icopy.flags = 0;
  err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
  assert(!err);
  assert(icopy.current_status == KNEM_STATUS_SUCCESS);
  printf("read from R succeeded\n");

  /* write to cookie_r_anyuser must fail */
  icopy.remote_cookie = cookie_r_anyuser;
  icopy.write = 1;
  icopy.flags = 0;
  err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
  assert(err < 0);
  assert(errno == EACCES);
  printf("write to R failed as expected\n");

  /* try to switch to another user */
  if (uid != 0 && setuid(uid) == 0) {

    /* read from cookie_rw must now fail */
    icopy.remote_cookie = cookie_rw;
    icopy.write = 0;
    icopy.flags = 0;
    err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
    assert(err < 0);
    assert(errno == EPERM);
    printf("read from RW as a different user succeeded\n");

    /* write to cookie_w must now fail */
    icopy.remote_cookie = cookie_w;
    icopy.write = 1;
    icopy.flags = 0;
    err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
    assert(err < 0);
    assert(errno == EPERM);
    printf("write to W as a different user failed as expected\n");

    /* read from cookie_r_anyuser must still succeed */
    icopy.remote_cookie = cookie_r_anyuser;
    icopy.write = 0;
    icopy.flags = 0;
    err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
    assert(!err);
    assert(icopy.current_status == KNEM_STATUS_SUCCESS);
    printf("read from R as a different user still succeeded\n");

    /* write to cookie_r_anyuser must still fail */
    icopy.remote_cookie = cookie_r_anyuser;
    icopy.write = 1;
    icopy.flags = 0;
    err = ioctl(fd, KNEM_CMD_INLINE_COPY, &icopy);
    assert(err < 0);
    assert(errno == EACCES);
    printf("write to R as a different user still failed as expected\n");

  } else {
    printf("run as root with an uid as parameter to test access from different users.\n");
  }

  close(fd);
  return 0;

 out_with_fd:
  close(fd);
 out:
  return 1;
}
