# Copyright © inria 2009-2010
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

# the main module object file
MODULEFILE = knem.ko
# the header checks file that must be generated prior to building the module
HDRCHECKFILE = knem_checks.h
# the script generating the header checks file
CHECKSCRIPT = $(srcdir)/check_kernel_headers.sh

# It seems that LDFLAGS get a value that is supposed to be a command
# for gcc, but gets passed to ld directly in the kernel build system.
LD_LDFLAGS = $(shell echo "$(LDFLAGS)" | sed -e 's/-Wl,//g')

moduledir = $(libdir)/modules/$(LINUX_RELEASE)
module_DATA = $(MODULEFILE)

EXTRA_DIST = knem_main.c knem_hal.h $(CHECKSCRIPT) Kbuild.in

# make the driver build .PHONY so as to let Kbuild handle dependencies properly
.PHONY: $(MODULEFILE)

# Kbuild may fail during make install as a different user since it tries to create
# some files in .tmp_versions even when there is nothing to do. This is especially
# a problem when doing make install as root over NFS without root squash.
# Ignore these errors when the current user is not the one that ran configure.
# So make install as root does not fail, and we still do not ignore build failures
# as the normal user.
$(MODULEFILE): $(HDRCHECKFILE)
	+LDFLAGS="$(LD_LDFLAGS)" $(MAKE) -C $(LINUX_BUILD) M=$(abs_builddir) $(KBUILD_ARGS) CONFIG_CC_STACKPROTECTOR_STRONG= CONFIG_CTF= $(MAKE_PARAMS) V=$(V) || test x`id -u` != x`stat -c %u Kbuild`

$(HDRCHECKFILE):
	$(CHECKSCRIPT) $(HDRCHECKFILE) "$(LINUX_BUILD)" "$(LINUX_HDR)" "$(LINUX_RELEASE)"

clean-local:
	+$(MAKE) -C $(LINUX_BUILD) M=$(abs_builddir) $(KBUILD_ARGS) clean

distclean-local:
	$(RM) $(HDRCHECKFILE)
