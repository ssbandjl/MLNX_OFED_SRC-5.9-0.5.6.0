# Copyright © inria 2009-2013
# Brice Goglin <Brice.Goglin@inria.fr>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

AM_CFLAGS = -Wall -Wextra

AM_CPPFLAGS = -imacros $(top_builddir)/common/knem_config.h -I$(top_srcdir)/common

bin_PROGRAMS = knem_loopback knem_pingpong knem_collectives knem_access_rights_test knem_multifd_test knem_status_test knem_notify_fd_test knem_vect_test knem_cost knem_region_cost

knem_collectives_CFLAGS = $(HWLOC_CFLAGS)
knem_collectives_LDADD = $(HWLOC_LIBS)

if KNEM_HAVE_HWLOC
  bin_PROGRAMS += knem_offload_test
  knem_offload_test_CFLAGS = $(HWLOC_CFLAGS)
  knem_offload_test_LDADD = $(HWLOC_LIBS)
endif

nodist_sbin_SCRIPTS = knem_local_install

dist_sysconf_DATA = 10-knem.rules

SUBDIRS = check
