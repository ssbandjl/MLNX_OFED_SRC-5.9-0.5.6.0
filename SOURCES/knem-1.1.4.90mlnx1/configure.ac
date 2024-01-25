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

AC_INIT(knem,
	1.1.4.90mlnx1,
	knem-devel@lists.gforge.inria.fr,
	knem,
	http://gitlab.inria.fr/knem/knem)
AC_CONFIG_SRCDIR(common/knem_io.h)
AC_PREREQ(2.61)
AC_CANONICAL_SYSTEM
AC_PREFIX_DEFAULT(/opt/knem)
AC_PRESERVE_HELP_ORDER
AM_INIT_AUTOMAKE([1.10 -Wall foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

######################
# usual config checks

AC_PROG_CPP
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_MKDIR_P
AC_PROG_INSTALL

#####################
# build flags config

AC_SUBST(CPPFLAGS)
AC_SUBST(CFLAGS)

########################
# Kernel related config

AC_ARG_VAR(KCC, [Compiler for building the kernel module])
AC_ARG_VAR(KARCH, [Architecture name to pass when building the kernel module])
AC_ARG_VAR(KBUILD_ARGS, [Arguments to pass when building the kernel module])

if test -n "$KCC" ; then
    KCC_BASE=`echo $KCC | cut -d' ' -f1`
else
    KCC_BASE=`echo $CC | cut -d' ' -f1`
fi
AC_MSG_CHECKING(which compiler to use for kernel modules)
AC_MSG_RESULT($KCC)
AC_CHECK_PROGS(_KCC_BASE_UNUSED, $KCC_BASE)

test -z "$KCC" || KBUILD_ARGS="$KBUILD_ARGS CC=\"$KCC\""
test -z "$KARCH" || KBUILD_ARGS="$KBUILD_ARGS ARCH=\"$KARCH\""
AC_SUBST(KBUILD_ARGS)

linux_release_set=false
linux_build_set=false
AC_ARG_WITH(linux-release,
    [AS_HELP_STRING([--with-linux-release=<version>], [release number of the target kernel])],
    LINUX_RELEASE="$withval"; linux_release_set=true,
    LINUX_RELEASE=`uname -r`)
AC_ARG_WITH(linux,
	[AS_HELP_STRING([--with-linux=<dir>], [location of the Linux kernel source])],
	linux_build_set=true ; LINUX_SRC="$withval"; LINUX_BUILD="$withval"; AC_MSG_NOTICE(overriding kernel source and build dirs with $withval))
AC_ARG_WITH(linux-build,
	[AS_HELP_STRING([--with-linux-build=<dir>], [location of the Linux kernel build tree])],
	linux_build_set=true ; LINUX_BUILD="$withval"; AC_MSG_NOTICE(overriding kernel build dir with $withval))
test -z $LINUX_SRC && LINUX_SRC=/lib/modules/$LINUX_RELEASE/source
test -z $LINUX_BUILD && LINUX_BUILD=/lib/modules/$LINUX_RELEASE/build

# GCC earlier than 4.6.0 will build modules which require 'mcount',
# and this symbol will not be available in the kernel if the kernel was
# compiled with GCC 4.6.0 and above.
# therefore, to prevent unknown symbol issues we disable function tracing.
#
MAKE_PARAMS=
CC=${CROSS_COMPILE}gcc
CPP="$CC -E"
CPP_MAJOR=`$CPP -dumpversion 2>&1 | cut -d'.' -f1`
CPP_MINOR=`$CPP -dumpversion 2>&1 | cut -d'.' -f2`
CPP_PATCH=`$CPP -dumpversion 2>&1 | cut -d'.' -f3`
CPP_VERS=`expr 0$CPP_MAJOR \* 1000000 + 0$CPP_MINOR \* 1000 + 0$CPP_PATCH`
compile_h=`/bin/ls -1 $LINUX_BUILD/include/*/compile.h 2> /dev/null | head -1`
if [[ "X$compile_h" != "X" ]]; then
    KERNEL_GCC_MAJOR=`grep LINUX_COMPILER $compile_h | sed -r -e 's/.*gcc version ([[0-9\.\-]]*) .*/\1/g' | cut -d'.' -f1`
    KERNEL_GCC_MINOR=`grep LINUX_COMPILER $compile_h | sed -r -e 's/.*gcc version ([[0-9\.\-]]*) .*/\1/g' | cut -d'.' -f2`
    KERNEL_GCC_PATCH=`grep LINUX_COMPILER $compile_h | sed -r -e 's/.*gcc version ([[0-9\.\-]]*) .*/\1/g' | cut -d'.' -f3`
    KERNEL_GCC_VER=`expr 0$KERNEL_GCC_MAJOR \* 1000000 + 0$KERNEL_GCC_MINOR \* 1000 + 0$KERNEL_GCC_PATCH`
    if [[ $CPP_VERS -lt 4006000 ]]  && [[ $KERNEL_GCC_VER -ge 4006000 ]]; then
        echo "Warning: The kernel was compiled with GCC newer than 4.6.0, while the current GCC is older than 4.6.0, Disabling function tracing to prevent unknown symbol issues..."
        MAKE_PARAMS="$MAKE_PARAMS CONFIG_FUNCTION_TRACER= CONFIG_HAVE_FENTRY= "
    fi
    if [[ $CPP_VERS -ge 4006000 ]]  && [[ $KERNEL_GCC_VER -lt 4006000 ]]; then
        echo "Warning: The kernel was compiled with GCC older than 4.6.0, while the current GCC is newer than 4.6.0, Disabling function tracing to prevent unknown symbol issues..."
        MAKE_PARAMS="$MAKE_PARAMS CONFIG_FUNCTION_TRACER= CONFIG_HAVE_FENTRY= "
    fi
fi

if (echo $LINUX_RELEASE | grep -qE 'uek'); then
MAKE_PARAMS="$MAKE_PARAMS ctf-dir=`pwd`/.ctf"
fi

AC_SUBST(MAKE_PARAMS)

# Find where the headers are (to avoid grepping at both places).
# Do not check for autoconf.h or version.h since these are in
# both the source and the build directory.
AC_MSG_CHECKING(kernel.h kernel header)
LINUX_HDR=
if test -f ${LINUX_SRC}/include/linux/kernel.h ; then
  LINUX_HDR=$LINUX_SRC
else if test -f ${LINUX_BUILD}/include/linux/kernel.h ; then
  LINUX_HDR=$LINUX_BUILD
fi fi
if test -z "${LINUX_HDR}" ; then
  AC_MSG_RESULT([not found])
else
  AC_MSG_RESULT([found in ${LINUX_HDR}])
fi

# Find where the autoconf header is (to avoid grepping at both places).
# The one in the build dir is preferred since this is where the configured
# tree should be
AC_MSG_CHECKING(autoconf.h kernel header)
LINUX_AUTOCONF_DIR=
if test -f ${LINUX_BUILD}/include/generated/autoconf.h -o -f ${LINUX_BUILD}/include/linux/autoconf.h ; then
  LINUX_AUTOCONF_DIR=${LINUX_BUILD}
else if test -f ${LINUX_SRC}/include/generated/autoconf.h -o -f ${LINUX_SRC}/include/linux/autoconf.h ; then
  LINUX_AUTOCONF_DIR=${LINUX_SRC}
fi fi
if test -z "${LINUX_AUTOCONF_DIR}" ; then
  AC_MSG_RESULT([not found])
else
  AC_MSG_RESULT([found in ${LINUX_AUTOCONF_DIR}])
fi

# Find where the kbuild Makefile is
AC_MSG_CHECKING(kernel Makefile)
if test -f ${LINUX_BUILD}/Makefile ; then
  AC_MSG_RESULT([found in ${LINUX_BUILD}])
else
  AC_MSG_RESULT([not found])
fi

# Error out if we fail to find everything
if test -z "${LINUX_HDR}" -o -z "${LINUX_AUTOCONF_DIR}" -o ! -f ${LINUX_BUILD}/Makefile  ; then
  AC_MSG_NOTICE([looked for kernel headers and build system using:])
  AC_MSG_NOTICE([  kernel headers in ${LINUX_SRC}])
  AC_MSG_NOTICE([  kernel build in ${LINUX_BUILD}])
  AC_MSG_NOTICE([might need --with-linux-release, --with-linux, or --with-linux-build])
  AC_MSG_ERROR([could not find kernel headers and build system])
fi

# Check the kernel release
LINUX_REAL_RELEASE=$(make kernelrelease -C ${LINUX_BUILD} M=dummy | grep -e '^[[0-9]]\+\.[[0-9]]\+')
AC_MSG_NOTICE(found Linux kernel release $LINUX_REAL_RELEASE in build tree)

# The kernel module gets installed in $prefix/modules/$LINUX_RELEASE
# and usually gets loaded from $prefix/modules/`uname -r`,
# so we must make sure that those release string match.
#
# If the user forces the Linux release, this will be the value used when
# installing the module.
#
# Else, Linux release tries to be inferred from the Linux build tree (if this
# one has been forced. Else `uname -r` is used). See the comments below.
warn_about_kernelrelease=false
if $linux_release_set ; then
  if test x$LINUX_RELEASE != "x$LINUX_REAL_RELEASE" ; then
    # Here, the user forces the Linux release but this value conflicts with
    # the one inferred from the build tree. We keep the user value because the
    # autodetected one can be buggy (see the comment below).
    # Nonetheless, we issue a warning related to this conflict.
    AC_MSG_WARN(kernel build reports $LINUX_REAL_RELEASE instead of $LINUX_RELEASE)
    AC_MSG_WARN(installing in $LINUX_RELEASE as requested)
  fi
else
  if $linux_build_set ; then
    # Here, Linux release has not been specified but the build tree has
    # been. So, the only usable value is the one inferred from the build
    # tree. Most of the time, this value will match the `uname -r` value
    # when running this kernel. So things work well.
    #
    # But sometimes, some kernel headers have a buggy 'make kernelrelease'
    # whose output differs from their `uname -r` output. Such
    # case will lead to not finding the kernel module at load time.
    #
    # Whatever, we have no choice here to keep the 'make kernelrelease'
    # value. But, we inform the user at the end of the configure with an
    # emphasized message about this possible issue as well as with the
    # associated workaround: force the Linux release to match `uname -r`.
    AC_MSG_NOTICE(installing in $LINUX_REAL_RELEASE as detected in the build tree)
    LINUX_RELEASE="$LINUX_REAL_RELEASE"
    warn_about_kernelrelease=true
  fi
fi

AC_SUBST(LINUX_RELEASE)
AC_SUBST(LINUX_SRC)
AC_SUBST(LINUX_BUILD)
AC_SUBST(LINUX_HDR)

# Check whether ccflags-y is supported
AC_MSG_CHECKING(kernel build supports ccflags-y)
if test -d ${LINUX_BUILD}/scripts/ && grep ccflags-y -r ${LINUX_BUILD}/scripts/ >/dev/null ; then
    AC_MSG_RESULT(yes)
    LINUX_KBUILD_CCFLAGS_Y=ccflags-y
else
    AC_MSG_RESULT([no, reverting to EXTRA_CFLAGS])
    LINUX_KBUILD_CCFLAGS_Y=EXTRA_CFLAGS
fi
AC_SUBST(LINUX_KBUILD_CCFLAGS_Y)

# Check kernel headers early
AC_MSG_NOTICE([checking kernel headers ...])
mkdir -p driver/linux
${srcdir}/driver/linux/check_kernel_headers.sh --force ./driver/linux/knem_checks.h "$LINUX_BUILD" "$LINUX_HDR" "$LINUX_RELEASE"

if test ! "$srcdir" -ef "." ; then
  # Symlink kernel sources into the build tree if needed
  AC_MSG_NOTICE([creating symlinks to kernel sources in driver/linux/ ...])
  mkdir -p driver/linux
  AC_CONFIG_LINKS(driver/linux/knem_main.c:driver/linux/knem_main.c)
  AC_CONFIG_LINKS(driver/linux/knem_hal.h:driver/linux/knem_hal.h)
fi

######################
# Misc config options

AC_ARG_ENABLE(debug,
	[AS_HELP_STRING([--enable-debug], [enable debugging features in the driver])],
	enable_debug=$enableval, enable_debug=optional)
AC_MSG_CHECKING(if debug is enabled in the driver)
if test x$enable_debug = xyes; then
  AC_DEFINE(KNEM_DRIVER_DEBUG, [1], [Define to enable debug features in the driver])
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

AC_ARG_ENABLE(hwloc,
	[AS_HELP_STRING([--disable-hwloc], [disable hwloc in the user-space tools])],
	enable_hwloc=$enableval, enable_hwloc=yes)
if test x$enable_hwloc = xyes; then
  PKG_CHECK_MODULES(HWLOC, hwloc >= 1.0, :, enable_hwloc=no)
  if test x$enable_hwloc = xyes; then
    # use pkg-config result to check that headers and libs are usable
    # (in case it's a cross compilation environment)
    knem_cflags_save="$CFLAGS"
    knem_libs_save="$LIBS"
    CFLAGS="$CFLAGS $HWLOC_CFLAGS"
    LIBS="$LIBS $HWLOC_LIBS"
    AC_CHECK_FUNC(hwloc_topology_init, :, enable_hwloc=no)
    CFLAGS="$knem_cflags_save"
    LIBS="$knem_libs_save"
    if test x$enable_hwloc = xno; then
      # clear pkg-config result if hwloc isn't actually usable
      HWLOC_CFLAGS=
      HWLOC_LIBS=
    fi
  fi
fi
AM_CONDITIONAL(KNEM_HAVE_HWLOC, test x$enable_hwloc = xyes)
if test x$enable_hwloc = xyes; then
  AC_DEFINE(KNEM_HAVE_HWLOC, 1, [Define to enable hwloc in user-space tools])
fi

AC_SUBST(CONFIG_STATUS_DEPENDENCIES,
	'$(top_srcdir)/driver/linux/Kbuild.in $(top_srcdir)/driver/linux/check_kernel_headers.sh')

AC_CONFIG_COMMANDS(chmoding-check_wrapper, chmod ugo+x tools/check/wrapper)
AC_MSG_NOTICE(creating symlinks to wrapper in tools/check/ ...)
TEST_LIST='status.sh accessrights.sh multifd.sh notify_fd.sh cost.sh regioncost.sh offload.sh vect1.sh vect2.sh vect3.sh vect4.sh vect5.sh vect6.sh loopback1.sh loopback2.sh pingpong1.sh pingpong2.sh pingpong3.sh collectives1.sh collectives2.sh collectives3.sh collectives4.sh'
AC_SUBST(TEST_LIST)
mkdir -p tools/check/
for i in $TEST_LIST ; do
  ln -sf wrapper tools/check/$i
done

AC_CONFIG_HEADER(common/knem_config.h)
AC_OUTPUT(driver/linux/Makefile driver/linux/Kbuild tools/Makefile tools/knem_local_install tools/check/Makefile tools/check/wrapper doc/Makefile Makefile knem.pc)

cat <<EOF

Driver Configuration Summary
****************************
Linux kernel headers:	 $LINUX_HDR
Linux kernel build tree: $LINUX_BUILD
Linux kernel release:	 $LINUX_RELEASE
EOF

if $warn_about_kernelrelease ; then
cat <<EOF

WARNING
*******
You specified a Linux build tree (through --with-linux or --with-linux-build)
without having specified a Linux release (with --with-linux-release).
The above Linux kernel release was inferred from the build tree. It may be
wrong, preventing from finding the right kernel module at loading time.
If this happen, add --with-linux-release to your configure line so that the
release string matches the \`uname -r\` value of this kernel.
EOF
fi
