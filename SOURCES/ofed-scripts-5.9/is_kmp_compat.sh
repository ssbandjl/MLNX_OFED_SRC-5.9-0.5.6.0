#!/bin/bash
# Copyright (c) 2015 Mellanox Technologies. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a
#    copy of which is available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/gpl-license.php.
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.
#
#
# Author: Alaa Hleihel - alaa@mellanox.com
#
#########################################################################
#
# Check if any of the modules inside the given kmp rpm has an
# issue to be loaded with the given kernel version.
#
# output:
#       - When the rpm is compatible with the kerne: RC=0 and no output to screen
#       - When the rpm is NOT compatible with the kernel: RC!=0 and errors/warnings
#         will be printed to STDERR
#########################################################################

kver=
rpmPaths=
tmphome=

RPM="rpm --nodigest --nosignature"

usage()
{
	cat <<EOF
Usage:
    ${0##*/} --path <rpm paths> --kernel <version> [options]

Options:
    --path <rpm paths>        Comma separated list of paths to RPM files
    --tmp <path>              Change path to temp working dir (default: /tmp)
    -h, --help                Show help message

Output:
    - When the rpm is compatible with the kernel: RC=0 and no output to screen
    - When the rpm is NOT compatible with the kernel: RC!=0 and errors/warnings
      will be printed to STDERR
EOF
}

while [ ! -z "$1" ]
do
	case "$1" in
		--path)
		rpmPaths="$2"
		shift
		;;
		--kernel)
		kver="$2"
		shift
		;;
		--tmp)
		tmphome="$2"
		shift
		;;
		-h | *help)
		usage
		exit 0
		;;
		*)
		echo "-E- Unsupported option: $1" >&2
		exit 1
		;;
	esac
	shift
done

# Some input verification
if [ -z "$kver" ]; then
	echo "--kernel flag is needed" >&2
	exit 1
fi
if [ ! -e "/lib/modules/$kver" ]; then
	echo "-E- $kver is not installed to /lib/modules/" >&2
	exit 1
fi
if [ -z "$rpmPaths" ]; then
	echo "--path flag is needed" >&2
	exit 1
fi

# Get tmp dir
if [ -z "$tmphome" ]; then
	tmphome="/tmp"
fi
tmpdir=$(mktemp -d $tmphome/kmp_check.XXXXXXX)
if [ ! -d "$tmpdir" ]; then
	echo "-E- Faield to create tmp dir!" >&2
	exit 1
fi
trap "/bin/rm -rf $tmpdir" EXIT

# Prepare tmp dir with the modules
cd $tmpdir
echo "$rpmPaths" | tr ',' '\n' | \
while read fff
do
	if [ ! -e "$fff" ]; then
		echo "-E- $fff does not exist!" >&2
		exit 1
	fi
	$RPM -i --nodeps --notriggers --noscripts --root $tmpdir "$fff"
done
cd lib/modules
test -d $kver || ln -s * $kver
cd $kver
ln -s /lib/modules/$kver/kernel kernel

cd $tmpdir
/bin/rm -rf System.map symvers >/dev/null 2>&1
symsArg=
if (depmod --help 2>&1 | grep -qw symvers); then
	if [ -e /boot/symvers-$kver.gz ]; then
		zcat /boot/symvers-$kver.gz 2>/dev/null >> $tmpdir/symvers
	elif [ -e /lib/modules/$kver/symvers.gz ]; then
		zcat /lib/modules/$kver/symvers.gz 2>/dev/null >> $tmpdir/symvers
	else
		cat /lib/modules/$kver/*/Module.symvers 2>/dev/null >> $tmpdir/symvers
	fi
	if [ ! -s $tmpdir/symvers ]; then
		echo "-E- Faield to get symvers list .." >&2
		exit 1
	fi
	symsArg="-E $tmpdir/symvers"
else
	if [ -e /boot/System.map-$kver ]; then
		cat /boot/System.map-$kver >> $tmpdir/System.map
	else
		cat /lib/modules/$kver/*/System.map 2>/dev/null >> $tmpdir/System.map
	fi
	if [ ! -s $tmpdir/System.map ]; then
		echo "-E- Faield to get System.map .." >&2
		exit 1
	fi
	symsArg="-F $tmpdir/System.map"
fi

mkdir -p $tmpdir/etc/depmod.d
echo "search updates extra built-in weak-updates" > $tmpdir/etc/depmod.d/dist.conf

# $tmpdir/etc/depmod.d/ can have conf files from the RPMs as well
res=$(depmod -b $tmpdir -ae $symsArg -C $tmpdir/etc/depmod.d/ $kver 2>&1)
if [ $? -ne 0 ]; then
	echo "-E- depmod failed!" >&2
	exit 1
fi

rpm_mods() {
	# Always called in a subshell, so no need to restore IFS
	IFS=","
	for rpm in $rpmPaths; do
		rpm -qlp "$rpm"
	done | grep '\.ko' | sed -e 's/.*\///g'
}

# Get only warnings/errors related to the modules coming from the given rpm
modregex=
for mod in $(rpm_mods)
do
	if [ -z "$modregex" ]; then
		modregex="$mod"
	else
		modregex="$modregex|$mod"
	fi
done
echo "$res" | grep -E "(needs unknown|disagrees about version of) symbol" | grep -E "$modregex" 1>&2
if [ $? -eq 0 ]; then
	exit 1
fi

exit 0
