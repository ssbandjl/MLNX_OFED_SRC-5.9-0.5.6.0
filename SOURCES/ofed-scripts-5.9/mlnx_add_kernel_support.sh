#!/bin/bash
# Copyright (c) 2012 Mellanox Technologies. All rights reserved.
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

VERSION="7.2"

export LANG="C"

skip_repo=0
distro=
deb=0
BINDIR=RPMS
SRCDIR=SRPMS
missing_pkgs=0

os_release_field() {
	grep "^$1=" /etc/os-release | cut -d= -f2- | tr -d '"' | tr '[:upper:]' '[:lower:]'
}

get_distro() {
        . /etc/os-release
        case "$ID:$VERSION_ID" in
        # The RPM-based uos has an lower-case, as oppoed to the deb based:
        uos:*) ID="uos20-1020";;
        esac
        echo "$ID" | tr '[:upper:]' '[:lower:]'
}

debian_version() {
	if [ ! -r /etc/debian_version ]; then
		echo 0.0 # Should not happen
		return
	fi
	debian_version=`</etc/debian_version`
	if ! echo "$debian_version" | grep -q '^[1-9]'; then
		echo 0 # sid (unstable)
		return
	fi
	echo "$debian_version"
}

if [ -r /etc/os-release ]; then
	distro_id=`get_distro`
	case "$distro_id" in
	debian | ubuntu | uos)
		deb=1
		BINDIR=DEBS
		SRCDIR=SOURCES
		distro_version_id=`os_release_field VERSION_ID`
		if [ "$distro_id" = "debian" ]; then
			distro_version_id=`debian_version`
		fi
		distro="$distro_id$distro_version_id"
		;;
	esac
fi

usage()
{
	kmp_msg="[--kmp]                                                 Enable KMP format if supported."
	distro_msg="[--distro]                                              Set Distro name for the running OS (e.g: rhel6.5, sles11sp3). Default: Use auto-detection."
	if [ $deb -eq 1 ]; then
		kmp_msg=
		distro_msg=
	fi
cat << EOF

	Usage: `basename $0` -m|--mlnx_ofed <path to MLNX_OFED/mlnx-en directory> [--make-iso|--make-tgz]

		[--make-iso]                    			Create MLNX_OFED/mlnx-en ISO image.
		[--make-tgz]                    			Create MLNX_OFED/mlnx-en tarball. (Default)
		[-t|--tmpdir <temp work dir>]                           Temp work directory (Default: /tmp)
		$kmp_msg
		[-k | --kernel]	<kernel version>			Kernel version to use.
		[-s | --kernel-sources] <path to the kernel sources>	Path to kernel headers.
		[--ofed-sources] <path to tgz>				Path to OFED sources tgz package.
		[-v|--verbose]
		[-n|--name]						Name of the package to be created.
		[-y|--yes]						Answer "yes" to all questions
		[--force]						Force removing packages that depends on MLNX_OFED/mlnx-en
		[--skip-repo]						Do not create a repository from MLNX_OFED/mlnx-en rpms.
		[--without-<package>]					Do not build/install given package (or module).
		$distro_msg

EOF
}

# COLOR SETTINGS
TT_COLOR="yes"
SETCOLOR_SUCCESS="echo -en \\033[1;34m"
SETCOLOR_FAILURE="echo -en \\033[1;31m"
SETCOLOR_WARNING="echo -en \\033[1;35m"
SETCOLOR_NORMAL="echo -en \\033[0;39m"


# Print message with "ERROR:" prefix
err_echo()
{
	[ "$TT_COLOR" = "yes" ] && $SETCOLOR_FAILURE
	echo -n "ERROR: $@"
	[ "$TT_COLOR" = "yes" ] && $SETCOLOR_NORMAL
	echo
	return 0
}

# Print message with "WARNING:" prefix
warn_echo()
{
	[ "$TT_COLOR" = "yes" ] && $SETCOLOR_WARNING
	echo -n "WARNING: $@"
	[ "$TT_COLOR" = "yes" ] && $SETCOLOR_NORMAL
	echo
	return 0
}

# Print message (bold)
pass_echo()
{
	[ "$TT_COLOR" = "yes" ] && $SETCOLOR_SUCCESS
	echo -n "$@"
	[ "$TT_COLOR" = "yes" ] && $SETCOLOR_NORMAL
	echo
	return 0
}

trap_handler()
{
        err_echo "Killed by user."
        exit 1

}

# Get user's trap (Ctrl-C or kill signals)
trap 'trap_handler' 2 9 15

ex()
{
	if [ $verbose -eq 1 ]; then
		echo Running $@
	fi
	eval "$@" >> $LOG 2>&1
	if [ $? -ne 0 ]; then
		echo
		err_echo Failed executing \"$@\"
		err_echo See $LOG
		# cleanup
		exit 1
	fi
}

cleanup()
{
	/bin/rm -rf $tmpdir > /dev/null 2>&1
	/bin/rm -rf $tmpdir_logs > /dev/null 2>&1
}

# Returns "0" if $1 is integer and "1" otherwise
is_integer()
{
        printf "%s\n" $1 |grep -E "^[+-]?[0-9]+$" > /dev/null
        return $?
}

# Check disk space requirments $1 - required size $2 - directory to check
check_space_req()
{
        local space_req=$1
        local dir=$2

        shift 2

        while [ ! -d $dir ]
        do
                dir=${dir%*/*}
        done

        local avail_space=`/bin/df $dir | tail -1 | awk '{print$4}' | tr -d '[:space:]'`

        if ! is_integer $avail_space; then
                # Wrong avail_space found
                return 0
        fi

        if [ $avail_space -lt $space_req ]; then
                echo
                err_echo "Not enough disk space in the ${dir} directory. Required ${space_req}KB"
                echo
                exit 1
        fi

        return 0
}

function remove_double_slash()
{
	local path=$1
	shift
	local go=1
	while [ $go -eq 1 ]
	do
		case $path in
		*//*)
		path=$(echo $path | sed -e 's@//@/@g')
		;;
		*)
		go=0
		;;
		esac
	done
	path=$(echo $path | sed -e 's@/$@@g')
	echo $path
}

if [ $UID -ne 0 ]; then
	echo You must be root to run `basename $0`
	exit 1
fi

if [ -z "$1" ]; then
	usage
	exit 1
fi

mlnx_iso=
kernel=
kernel_sources=
dflt_kernel=`uname -r`
dflt_kernel_sources="/lib/modules/${dflt_kernel}/build/"
arch=`uname -m`
if [ $deb -eq 0 ]; then
	build_arch=`rpm --eval '%{_target_cpu}'`
else
	build_arch=`dpkg --print-architecture`
fi
if [ "X$ARCH" != "X" -a "X$ARCH" != "X$arch" ]; then
	echo "Detected cross compiling (local: $arch, target: $ARCH)"
	echo
	arch=$ARCH
	binArch=$(echo $ARCH | sed -e 's/aarch64/arm64/g')
fi
verbose=0
make_iso=0
make_tgz=1
mofed_type="TGZ"
name=
yes=0
force=
disabled_pkgs=
# pass distro to install.pl only if it was provided by the user
distro1=
ofed_tgz=

TMP=${TMP:-"/tmp"}
mlnx_tmp=mlnx_iso.$$
tmpdir=${TMP}/$mlnx_tmp
tmpdir_logs=${TMP}/${mlnx_tmp}_logs

KMP="--disable-kmp"
KMP_BUMP_VER=
META_BUILD_NUM=
TS=

while [ ! -z "$1" ]
do
	case "$1" in
		-h | --help)
		usage
		shift
		exit 0
		;;
		-m | --mlnx_ofed)
		mlnx_ofed_dir="$2"
		shift 2
		;;
		-k | --kernel)
		kernel=$2
		shift 2
		;;
		-s | --kernel-sources)
		kernel_sources=$2
		shift 2
		;;
		-t | --tmpdir)
		tmpdir=$2/$mlnx_tmp
		TMP=$2
		tmpdir_logs=${TMP}/${mlnx_tmp}_logs
		shift 2
		;;
		--kmp)
		KMP=
		TS=$(date "+%Y%m%d%H%M")
		KMP_BUMP_VER="--bump-kmp-version $TS"
		shift
		;;
		--kmp-same-name)
		KMP=
		shift
		;;
		-v | --verbose)
		verbose=1
		shift
		;;
		--make-iso)
		make_iso=1
		make_tgz=0
		mofed_type="ISO"
		shift
		;;
		--make-tgz)
		make_tgz=1
		make_iso=0
		mofed_type="TGZ"
		shift
		;;
		-n | --name)
		name=$2
		shift 2
		;;
		-y | --yes)
		yes=1
		shift
		;;
		--force)
		force="--force"
		shift
		;;
		--version)
		echo "Version: $VERSION"
		exit 0
		;;
		--without-* | --enable-gds)
		disabled_pkgs="$disabled_pkgs $1"
		shift
		;;
		--distro)
		distro=`echo $2 | tr '[:upper:]' '[:lower:]'`
		distro1="--distro $distro"
		shift 2
		;;
		--ofed-sources)
		ofed_tgz=$2
		shift 2
		;;
		--skip-repo)
		skip_repo=1
		shift
		;;
		*)
		usage
		shift
		exit 1
		;;
	esac
done

if [ $deb -eq 1 ]; then
	KMP=--without-dkms
fi

# remove // from path
TMP=$(remove_double_slash $TMP)
tmpdir=$(remove_double_slash $tmpdir)
tmpdir_logs=$(remove_double_slash $tmpdir_logs)

LOG=${tmpdir_logs}/mlnx_ofed_iso.$$.log

if [ -z "$kernel_sources" ]; then
	if [ -z "$kernel" ]; then
		kernel=$dflt_kernel
		kernel_sources=$dflt_kernel_sources
	else
		kernel_sources="/lib/modules/${kernel}/build"
	fi
fi

mkiso=""
mkiso_commands="genisoimage mkisofs"
if [ $make_iso -eq 1 ]; then
    for p in $mkiso_commands; do
        if command -v -p "$p" >/dev/null 2>&1; then
	    mkiso="$p"
	    break
	fi
    done
    if [ "$mkiso" = "" ]; then
        err_echo "Cannot create iso, no ISO generator found. Tried:: $mkiso_commands. Aborting."
        exit 1
    fi
fi

if [ ! -e "$mlnx_ofed_dir/create_mlnx_ofed_installers.pl" ]; then
	if [ $skip_repo -eq 0 ]; then
		warn_echo "create_mlnx_ofed_installers.pl is missing, cannot build a repository."
		skip_repo=1
	fi
fi

if [ -z "$kernel" ]; then
	kernel=$dflt_kernel
fi

if [ -z "$mlnx_ofed_dir" ]; then
	err_echo "Path to MLNX_OFED/mlnx-en directory is not defined."
	usage
	exit 1
fi

ofed_dir=`dirname $0`
INSTALLER=mlnxofedinstall
PACKAGE=MLNX_OFED_LINUX
if [ -e "$mlnx_ofed_dir/install" ]; then
	INSTALLER=install
	PACKAGE=mlnx-en
fi

# About 600MB is required
check_space_req 614400 `dirname $tmpdir`

mkdir -p $tmpdir
mkdir -p $tmpdir_logs

# Set distro
if [ $deb -eq 0 ]; then
	distro_rpm=`rpm -qf /etc/issue 2> /dev/null | grep -v "is not owned by any package" | head -1`
	if [ "X${distro_rpm}" == "X" ]; then
		distro_rpm=`rpm -qf /etc/os-release 2> /dev/null | grep -v "is not owned by any package" | head -1`
	fi
	if [ "X${distro_rpm}" == "X" ]; then
		distro_rpm="unsupported"
	fi
fi
if [ "X$distro" == "X" -a $deb -eq 0 ]; then
	if [ $verbose -eq 1 ]; then
		echo "Distro was not provided, trying to auto-detect the current distro..."
	fi
	distro_install_pl=`$ofed_dir/$INSTALLER --print-distro`
	if [ $? -eq 0 ]; then
		distro=`echo "$distro_install_pl" | sed -r -e 's/([0-9])u/\1./g'`
	else
		err_echo "Linux Distribution ($distro_rpm) is not supported"
		exit 1
	fi
	if [ $verbose -eq 1 ]; then
		echo "Auto-detected $distro distro."
	fi
else
	if [ $verbose -eq 1 ]; then
		echo "Using provided distro: $distro"
	fi
fi

### MAIN ###
pass_echo "Note: This program will create $PACKAGE ${mofed_type} for ${distro} under $TMP directory."

if [ $yes -ne 1 ]; then
read -p "Do you want to continue?[y/N]:" ans
case $ans in
	y | Y)
	;;
	*)
	exit 0
	;;
esac
fi

echo See log file $LOG
echo

mnt_point="$mlnx_ofed_dir"

if [[ ! -f "$mnt_point/.mlnx" && ! -f "$mnt_point/mlnx" ]]; then
	err_echo "$mlnx_ofed_dir is not a supported $PACKAGE directory"
	exit 1
fi

if [ -f "$mnt_point/.mlnx" ]; then
	mlnx_version=`cat "$mnt_point/.mlnx"`
else
	mlnx_version=`cat "$mnt_point/mlnx"`
fi

if [ $verbose -eq 1 ]; then
	pass_echo "Detected $PACKAGE-${mlnx_version}"
fi

MLNX_OFED_DISTRO=`cat "$mnt_point/distro" 2>/dev/null`
if [ "X$MLNX_OFED_DISTRO" != "X$distro" ] && [ "X$MLNX_OFED_DISTRO" != "Xskip-distro-check" ]; then
	echo "WARNING: The current $PACKAGE is intended for $MLNX_OFED_DISTRO !"
	echo "You may need to use the '--skip-distro-check' flag to install the resulting $PACKAGE on this system."
	echo
fi

if [ $deb -eq 0 ]; then
	rpm_kernel=${kernel//-/_}
	# Check that required RPMs not already exist in the MLNX_OFED
	if ( /bin/ls "$mnt_point"/RPMS/mlnx-ofa_kernel-modules-*${rpm_kernel}[_.]*${build_arch}.rpm > /dev/null 2>&1 ) &&
		( /bin/ls "$mnt_point"/RPMS/kernel-mft-*${rpm_kernel}.${build_arch}.rpm > /dev/null 2>&1 ) &&
		( /bin/ls "$mnt_point"/RPMS/srp-*${rpm_kernel}.${build_arch}.rpm > /dev/null 2>&1 ) &&
		( /bin/ls "$mnt_point"/RPMS/iser-*${rpm_kernel}.${build_arch}.rpm > /dev/null 2>&1 ) &&
		( /bin/ls "$mnt_point"/RPMS/knem-*${rpm_kernel}.${build_arch}.rpm > /dev/null 2>&1 ) ; then
		pass_echo "Required kernel ($kernel) is already supported by $PACKAGE"
		cleanup
		exit 30
	fi
else
	# debian
	rpm_kernel=${kernel//_/-}
	if ( /bin/ls "$mnt_point"/DEBS/mlnx-ofed-kernel-modules*${rpm_kernel}_*.deb > /dev/null 2>&1 ) &&
		( /bin/ls "$mnt_point"/DEBS/kernel-mft-modules*${rpm_kernel}_*.deb > /dev/null 2>&1 ) &&
		( /bin/ls "$mnt_point"/DEBS/srp-modules*${rpm_kernel}_*.deb > /dev/null 2>&1 ) &&
		( /bin/ls "$mnt_point"/DEBS/knem-modules*${rpm_kernel}_*.deb > /dev/null 2>&1 ) &&
		( /bin/ls "$mnt_point"/DEBS/iser-modules*${rpm_kernel}_*.deb > /dev/null 2>&1 ) ; then
		pass_echo "Required kernel ($kernel) is already supported by $PACKAGE"
		cleanup
		exit 30
	fi
fi

iso_dir=$PACKAGE-${mlnx_version}-${distro}-${arch}-ext
if [ -n "$name" ]; then
	iso_dir=$name
fi
iso_name=${iso_dir}.iso

if ! command -v -p tar >/dev/null;then
	err_echo "'tar' is not installed!"
	echo "'tar' package is needed for extracting the source $PACKAGE package."
	exit 1
fi

ex /bin/rm -rf $tmpdir/$iso_dir
# Extra quote of potential space due to the eval of ex():
ex cp -a "'$mnt_point'" $tmpdir/$iso_dir

/bin/rm -f $tmpdir/$iso_name

# Check presence of OFED tgz file
if [ -z "$ofed_tgz" ]; then
	ofed_tgz=`ls $tmpdir/$iso_dir/src/*_SRC*tgz 2> /dev/null`
fi
if [ -z "$ofed_tgz" ]; then
	err_echo "OFED tgz package not found under ${iso_dir}/src directory"
	echo "Please provide path to the OFED sources tgz package using the '--ofed-sources' flag."
	echo "Note: You can download the OFED sources tgz package from http://www.mellanox.com"
	exit 1
fi
ofed=`basename $ofed_tgz`
ofed=${ofed/.tgz/}

deb_tool_missing=0
echo "Checking if all needed packages are installed..."
if [ $skip_repo -eq 0 ]; then
	if [ $deb -eq 0 ] && ! ( which createrepo > /dev/null 2>&1 );then
		missing_pkgs=1
		err_echo "'createrepo' is not installed!"
		echo "'createrepo' package is needed for creating a repository from $PACKAGE RPMs."
		echo "Use '--skip-repo' flag if you are not going to set $PACKAGE as repository for"
		echo "installation using yum/zypper tools."
		echo
	fi
	# Debian
	if [ $deb -eq 1 ] && ! ( which apt-ftparchive > /dev/null 2>&1 );then
		missing_pkgs=1
		deb_tool_missing=1
		err_echo "'apt-utils' is not installed!"
		echo "'apt-utils' package is needed for creating a repository from $PACKAGE DEBs."
		echo
	fi
	if [ $deb -eq 1 ] && ! ( which bzip2 > /dev/null 2>&1 );then
		missing_pkgs=1
		deb_tool_missing=1
		err_echo "'bzip2' is not installed!"
		echo "'bzip2' package is needed for creating a repository from $PACKAGE DEBs."
		echo
	fi
	if [ $deb_tool_missing -eq 1 ];then
		echo "Use '--skip-repo' flag if you are not going to set $PACKAGE as repository for"
		echo "installation using apt-get tool."
		echo
	fi
fi

cd $tmpdir
# Build missing OFED kernel dependent RPMs
ex tar xzf $ofed_tgz

# Check for needed packages by install.pl
ofed_deps=$(${ofed}/install.pl --tmpdir $tmpdir_logs --kernel-only --kernel $kernel --kernel-sources $kernel_sources --builddir $tmpdir $KMP $force $disabled_pkgs --build-only $distro1 $KMP_BUMP_VER $MLNX_EXTRA_FLAGS --check-deps-only 2>/dev/null)
if (echo -e "$ofed_deps" | grep -q "Error:" 2>/dev/null); then
	missing_pkgs=1
	echo -e "$ofed_deps"
fi

if [ $missing_pkgs -eq 1 ]; then
	exit 1
fi

pass_echo "Building $PACKAGE $BINDIR . Please wait..."
ex ${ofed}/install.pl --tmpdir $tmpdir_logs --kernel-only --kernel $kernel --kernel-sources $kernel_sources --builddir $tmpdir $KMP $force $disabled_pkgs --build-only $distro1 $KMP_BUMP_VER $MLNX_EXTRA_FLAGS

# build mlnx-en
WITH_ETH_ONLY=0
if (grep -qw -- "--eth-only" $ofed/install.pl 2>/dev/null) && (/bin/ls $ofed/$SRCDIR/*mlnx-en* &>/dev/null); then
	WITH_ETH_ONLY=1
	ex ${ofed}/install.pl --tmpdir $tmpdir_logs --eth-only --kernel $kernel --kernel-sources $kernel_sources --builddir $tmpdir $KMP $force $disabled_pkgs --build-only $distro1 $KMP_BUMP_VER $MLNX_EXTRA_FLAGS
fi

# If we built new KMP rpms, we should remove the ones that came with MLNX_OFED
# (The package and the symlinks to it)
if [ "X`find ${ofed}/$BINDIR \( -name '*kmp*' -o -name '*kmod*' \) 2>/dev/null`" != "X" ]; then
	if [ "$TS" != '' ]; then
		META_BUILD_NUM="--build-num $TS"
	fi
	ex "find $tmpdir/$iso_dir/$BINDIR \( -name  '*kmp*' -o -name '*kmod*' -o -name '*kernel-mft-mlnx-utils*' \) -exec /bin/rm -fv '{}' \;"
fi

bins=`find ${ofed}/$BINDIR \
	-name "*mlnx-ofa_kernel-modules*" \
	-o -name "*kernel*" \
	-o -name "*knem*" \
	-o -name "*xpmem*" \
	-o -name "*srp*" \
	-o -name "*iser*" \
	-o -name "*mlnx-ofed-kernel-modules*" \
	-o -name "*mlnx-en*" \
	-o -name "*mlnx_en*" \
	-o -name "*mlnx-sdp*" \
	-o -name "*mlnx-rds*" \
	-o -name "*mlnx-nfsrdma*" \
	-o -name "*mlnx-nvme*" \
	-o -name "*mlnx-rdma-rxe*" \
	-o -name "*gpio*" \
	-o -name "*i2c*" \
	-o -name "*livefish*" \
	-o -name "*bootctl*" \
	-o -name "*pka-mlxbf*" \
	-o -name "*tmfifo*" \
	-o -name "*mlxbf-gige*" \
	-o -name "*mlx-trio*" \
	-o -name "*gpio-mlxbf2*" \
	-o -name "*mlx-pmc*" \
`

for p in $bins
do
	if ( echo $p | grep debuginfo > /dev/null 2>&1 ); then
		continue
	fi
	if echo $p | grep -q -E 'libxpmem|^xpmem[-_][0-9]' 2>/dev/null; then
		continue
	fi
	ex install -m 0644 $p $tmpdir/$iso_dir/$BINDIR
done

# Rebuild ETH only RPMS dir
if [ $WITH_ETH_ONLY -eq 1 ]; then
	/bin/rm -rf $tmpdir/$iso_dir/${BINDIR}_ETH
	mkdir -p $tmpdir/$iso_dir/${BINDIR}_ETH
	cd $tmpdir/$iso_dir/${BINDIR}_ETH
	bins=`find ../${BINDIR} -name "*mlnx-en*" -o -name "*mlnx_en*" \
			-o -name "*ofed-scripts*" -o -name "*mlnx-fw-updater*" -o -name "*mstflint*"`
	for p in $bins
	do
		case "$p" in
			*vma* | *eth-only* | *dpdk*)
			continue
			;;
		esac
		ex /bin/ln -s $p .
	done
	cd $tmpdir
fi

if [ $deb -eq 0 ]; then
	echo "$kernel" >> $tmpdir/$iso_dir/.supported_kernels
	echo "$kernel" >> $tmpdir/$iso_dir/supported_kernels
fi

if [ "X$distro1" != "X" ]; then
	echo "skip-distro-check" > $tmpdir/$iso_dir/distro
fi

# build metadata-rpms
if [ $skip_repo -eq 0 ]; then
	pass_echo "Creating metadata-rpms for $kernel ..."
	# build info files
	DEBFLAG=
	DKMSFLAG=
	if [ $deb -eq 1 ]; then
		DEBFLAG="--debian"
		DKMSFLAG="--without-dkms"
	fi
	KER_META_FLAG=
	if [ "X$KMP" != "X" ] || (/bin/ls $tmpdir/$iso_dir/RPMS/mlnx-ofa_kernel-modules-*${rpm_kernel}[_.]*${build_arch}.rpm > /dev/null 2>&1); then
		KER_META_FLAG="--kernel $kernel"
	fi
	group_list="all hpc basic vma vma-vpi vma-eth xlio guest hypervisor kernel-only dpdk dpdk-upstream-libs bluefield"
	METAGROUPS=
	if [ $WITH_ETH_ONLY -eq 1 ]; then
		group_list="$group_list eth-only"
		METAGROUPS="--groups vma,eth-only,dpdk --name mlnx-en"
	else
		METAGROUPS="--ignore-groups eth-only"
	fi
	for group in $group_list
	do
		$tmpdir/$iso_dir/$INSTALLER --${group} -p $DKMSFLAG -k $kernel --tmpdir $tmpdir_logs $disabled_pkgs $distro1 --skip-distro-check 2>/dev/null > $tmpdir/$iso_dir/$BINDIR/${group}_packages.txt
		# user space only packages list
		if [ "X${group}" != "Xkernel-only" ]; then
			$tmpdir/$iso_dir/$INSTALLER --${group} -p $DKMSFLAG -k $kernel --tmpdir $tmpdir_logs $disabled_pkgs $distro1 --skip-distro-check --user-space-only 2>/dev/null > $tmpdir/$iso_dir/$BINDIR/${group}-user-only_packages.txt
		fi
	done
	# create metadata rpms
	ex /usr/bin/perl $tmpdir/$iso_dir/create_mlnx_ofed_installers.pl \
		--with-hpc \
		--upstream-libs \
		--tmpdir $tmpdir_logs \
		--mofed $tmpdir/$iso_dir \
		--rpms-tdir $tmpdir/$iso_dir/$BINDIR \
		--output $tmpdir/$iso_dir \
		$DEBFLAG $KER_META_FLAG $META_BUILD_NUM $METAGROUPS
	rm -rf $tmpdir/$iso_dir/$BINDIR/*txt >/dev/null 2>&1
	# update eth ETH only RPMS dir
	if [ $WITH_ETH_ONLY -eq 1 ]; then
		/bin/mv -f $tmpdir/$iso_dir/${BINDIR}/*eth-only* $tmpdir/$iso_dir/${BINDIR}_ETH/ || true
	fi
	# create repo
	cd $tmpdir/$iso_dir
	rm -rf repodata Packages Packages.bz2 Release Release.gpg >/dev/null 2>&1
	if [ $deb -eq 0 ]; then
		GROUPFILE=
		if (createrepo --help 2>/dev/null | grep -q "groupfile" 2>/dev/null); then
			GROUPFILE="-g $tmpdir/$iso_dir/comps.xml"
		fi
		ex createrepo -q $GROUPFILE $tmpdir/$iso_dir/${BINDIR}
		if [ $WITH_ETH_ONLY -eq 1 ]; then
			ex createrepo -q $GROUPFILE $tmpdir/$iso_dir/${BINDIR}_ETH
		fi
		ex createrepo -q $GROUPFILE $tmpdir/$iso_dir/${BINDIR}
		/bin/rm -f $tmpdir/$iso_dir/comps.xml
		warn_echo "If you are going to configure this package as a repository, then please note"
		warn_echo "that it contains unsigned rpms, therefore, you need to disable the gpgcheck"
		warn_echo "by setting 'gpgcheck=0' in the repository conf file."
	else
		cd $tmpdir/$iso_dir/${BINDIR}
		/bin/rm -f Packages* Release* &>/dev/null || true
		ex "apt-ftparchive packages . > Packages"
		ex "bzip2 -kf Packages"
		ex "apt-ftparchive release . > Release"
		if [ $WITH_ETH_ONLY -eq 1 ]; then
			cd $tmpdir/$iso_dir/${BINDIR}_ETH
			/bin/rm -f Packages* Release* &>/dev/null || true
			ex "apt-ftparchive packages . > Packages"
			ex "bzip2 -kf Packages"
			ex "apt-ftparchive release . > Release"
		fi
		if [ -e "$tmpdir/$iso_dir/${BINDIR}" ]; then
			cd $tmpdir/$iso_dir/${BINDIR}/
			/bin/rm -f Packages* Release* &>/dev/null || true
			ex "apt-ftparchive packages . > Packages"
			ex "bzip2 -kf Packages"
			ex "apt-ftparchive release . > Release"
		fi
		warn_echo "If you are going to configure this package as a repository, then please note"
		warn_echo "that it is not signed, therefore, you need to set 'trusted=yes' in the sources.list file."
		warn_echo "Example: deb [trusted=yes] file:/<path to MLNX_OFED DEBS folder> ./"
	fi
	cd $tmpdir
fi

if [ $make_iso -eq 1 ]; then
    # Create new ISO image
    pass_echo "Running $mkiso..."
    "$mkiso" -A "$PACKAGE-${mlnx_version} Host Software $distro CD" \
                    -o ${TMP}/$iso_name \
                    -J -joliet-long -r $tmpdir/$iso_dir >> $LOG 2>&1

    if [ $? -ne 0 ] || [ ! -e ${TMP}/$iso_name ]; then
    	err_echo "Failed to create ${TMP}/$iso_name"
    	exit 1
    fi

    pass_echo "Created ${TMP}/$iso_name"
else
    cd $tmpdir
    ex tar czf ${TMP}/${iso_dir}.tgz $iso_dir
    pass_echo "Created ${TMP}/${iso_dir}.tgz"
fi

cleanup
/bin/rm -f $LOG
