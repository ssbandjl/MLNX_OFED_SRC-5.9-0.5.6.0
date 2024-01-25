#!/usr/bin/perl
#
# Copyright (c) 2013 Mellanox Technologies. All rights reserved.
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

use strict;
use File::Basename;
use File::Path;
use File::Find;
use File::Copy;
use File::Glob qw/:bsd_glob/;
use Cwd;
use Term::ANSIColor qw(:constants);

my $WDIR = dirname(Cwd::abs_path $0);
require("$WDIR/common.pl");

my $PREREQUISIT = "172";
my $SUCCESS = "0";
my $ERROR = "1";
my $EINVAL = "22";
my $ENOSPC = "28";
my $NONOFEDRPMS = "174";

$ENV{"LANG"} = "C";

$| = 1;

chdir $WDIR;
my $CWD     = getcwd;

###############################################################

my $DPKG = "/usr/bin/dpkg";
my $DPKG_QUERY = "/usr/bin/dpkg-query";
my $DPKG_BUILDPACKAGE = "/usr/bin/dpkg-buildpackage";
my $MODINFO = "/sbin/modinfo";
my $DPKG_FLAGS = "--force-confmiss";
my $DPKG_DEB = "/usr/bin/dpkg-deb";
my $check_linux_deps = 1;

my $builddir = "/var/tmp";
my $TMPDIR  = '/tmp';

my $ifconf = "/etc/network/interfaces";
my $config_net_given = 0;
my $config_net = "";
my %ifcfg = ();
my $umad_dev_rw = 0;
my $umad_dev_na = 0;
my $config_given = 0;
my $conf_dir = $CWD;
my $config = $TMPDIR . '/ofed.conf';
chomp $config;
my $install_option = 'all';
if (-e "$CWD/.def_option" ) {
	$install_option = `cat $CWD/.def_option 2>/dev/null`;
	chomp $install_option;
}
my $force_all = 0;
my $user_space_only = 0;
my $with_vma = 0;
my $with_xlio = 0;
my $print_available = 0;
my $force = 0;
my %disabled_packages;
my %force_enable_packages;
my %packages_deps = ();
my %modules_deps = ();
my $with_dkms = 1;
my $with_kmod_debug_symbols = 0;
my $force_dkms = 0;
my $dkms_flag_given = 0;
my $with_nvme = 0;
my $with_nfsrdma = 0;
my $with_ovs_dpdk = 0;
my $with_openvswitch = 0;
my $with_mlxdevm = 1;
my $apt_extra_params = "-o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'";

# list of scripts to run for each package
my %package_pre_install_script = ();
my %package_post_install_script = ();

$ENV{"DEBIAN_FRONTEND"} = "noninteractive";

my $CMD = "$0 " . join(' ', @ARGV);
my $MLNX_OFED_ARCH = "";
my $MLNX_OFED_DISTRO = "";
my $add_kernel_support = 0;
my $add_kernel_support_build_only = 0;
my $add_kernel_support_flags = "";
my $auto_add_kernel_support = 0;
my $enable_opensm = 0;
my @components = qw/kernel user/;

my $LOCK_EXCLUSIVE = 2;
my $UNLOCK         = 8;

my $PACKAGE = 'MLNX_OFED_LINUX';
my $INSTALLER = 'mlnxofedinstall';
if ($install_option eq 'eth-only' or -e "$CWD/install") {
    $PACKAGE = "mlnx-en";
    $INSTALLER = "install";
}
my $is_mlnx_en = 0;
if (-e "$CWD/install") {
	$is_mlnx_en = 1;
}

my $mlnx_en_pkgs = "";
my $mlnx_en_only_pkgs = "mlnx.*en|mstflint|ofed-scripts|mlnx-fw-updater|^rdma\$";
my $mlnx_en_rdma_pkgs = "$mlnx_en_only_pkgs|mlnx-ofed-kernel|ibverbs|librdmacm|libvma|sockperf|ibutils|rdma-core";

if (! -f ".mlnx" and ! -f "mlnx") {
    print RED ".mlnx file not found. Cannot continue...", RESET "\n";
    exit $PREREQUISIT;
}

my $MLNX_OFED_LINUX_VERSION = `cat .mlnx 2> /dev/null || cat mlnx`;
chomp $MLNX_OFED_LINUX_VERSION;

my $quiet = 0;
my $verbose = 0;
my $verbose2 = 0;
my $verbose3 = 0;
my %selected_for_uninstall;
my @dependant_packages_to_uninstall = ();
my %non_ofed_for_uninstall = ();

# FW
my $fw_update_flags = "";
my $update_firmware = 1;
my $firmware_update_only = 0;
my $enable_affinity = 0;
my $enable_mlnx_tune = 0;
my $err = 0;
my $update_limits_conf_soft = 1;
my $update_limits_conf_hard = 1;
my $post_start_delay = 0;

#
my %main_packages = ();
my @selected_packages = ();
my @selected_modules_by_user = ();
my @selected_kernel_modules = ();
my $kernel_configure_options = '';
my $skip_distro_check = 0;
my $skip_unsupported_devices_check = 0;

# list of the packages that will be installed (selected by user)
my @selected_by_user = ();
my @selected_to_install = ();

my $distro = "";
my $arch = `uname -m`;
chomp $arch;
my $kernel = `uname -r`;
chomp $kernel;
my $kernel_sources = "/lib/modules/$kernel/build";
chomp $kernel_sources;
my $kernel_given = 0;
my $kernel_source_given = 0;
my $check_deps_only = 0;
my $print_distro = 0;
my @saved_ARGV = ();
my $kernel_extra_args = "";
my $kernel_extra = 0;
my $do_copy_udev = 0;

my $is_bf = `lspci -s 00:00.0 2> /dev/null | grep -wq "PCI bridge: Mellanox Technologies" && echo 1 || echo 0`;
chomp $is_bf;

my $with_bluefield = 0;
if  ($is_bf) {
	$with_bluefield = 1;
}

#
# parse options
#
while ( $#ARGV >= 0 ) {
	my $cmd_flag = shift(@ARGV);

	push (@saved_ARGV, $cmd_flag) unless ($cmd_flag =~ /add-kernel-support|--skip-repo/);

	if ( $cmd_flag eq "--all" and not ($install_option eq 'eth-only' or $is_mlnx_en) ) {
		$install_option = 'all';
	} elsif ( $cmd_flag eq "--bluefield" ) {
		# Do not override other install options to enable bluefield packages as an extension
		$install_option = 'bluefield' if (not $install_option or ($install_option eq 'all' and not $force_all));
		$with_bluefield = 1;
	} elsif ( $cmd_flag eq "--hpc" and not ($install_option eq 'eth-only' or $is_mlnx_en) ) {
		$install_option = 'hpc';
	} elsif ( $cmd_flag eq "--basic" and not ($install_option eq 'eth-only' or $is_mlnx_en) ) {
		$install_option = 'basic';
	} elsif ( $cmd_flag eq "--msm" ) {
		$install_option = 'msm';
		$enable_opensm = 1;
	} elsif ( $cmd_flag eq "--with-nfsrdma" and not ($install_option eq 'eth-only' or $is_mlnx_en) ) {
		$with_nfsrdma = 1;
	} elsif ( $cmd_flag eq "--without-nfsrdma" and not ($install_option eq 'eth-only' or $is_mlnx_en) ) {
		$with_nfsrdma = 0;
	} elsif ( $cmd_flag eq "--with-nvmf" and not ($install_option eq 'eth-only' or $is_mlnx_en) ) {
		$with_nvme = 1;
	} elsif ( $cmd_flag eq "--with-vma" and not ($install_option eq 'eth-only' or $is_mlnx_en)) {
		$with_vma = 1;
	} elsif ( $cmd_flag eq "--vma" and !$is_mlnx_en ) {
		$install_option = 'vma';
		$with_vma = 1;
	} elsif ( $cmd_flag eq "--vma" and  $is_mlnx_en) {
		$install_option = 'vmaeth';
		$with_vma = 1;
	} elsif ( $cmd_flag eq "--vma-eth" ) {
		$install_option = 'vmaeth';
		$with_vma = 1;
	} elsif ( $cmd_flag eq "--vma-vpi" ) {
		$install_option = 'vmavpi';
		$with_vma = 1;
	} elsif ( $cmd_flag eq "--xlio" ) {
		$install_option = 'xlio';
		$with_xlio = 1;
	} elsif ( $cmd_flag eq "--with-xlio" ) {
		$with_xlio = 1;
	} elsif ( $cmd_flag eq "--guest" and not ($install_option eq 'eth-only' or $is_mlnx_en) ) {
		$install_option = 'guest';
		$update_firmware = 0;
	} elsif ( $cmd_flag eq "--hypervisor" and not ($install_option eq 'eth-only' or $is_mlnx_en) ) {
		$install_option = 'hypervisor';
	} elsif ( $cmd_flag eq "--kernel-only" ) {
		$install_option = 'kernel-only';
		@components = qw/kernel/;
	} elsif ( $cmd_flag eq "--user-space-only" ) {
		$user_space_only = 1;
		@components = qw/user/;
	} elsif ( $cmd_flag eq "--eth-only" ) {
		$install_option = 'eth-only';
	} elsif ( $cmd_flag eq "--dpdk" ) {
		$install_option = 'dpdk';
	} elsif ( $cmd_flag eq "--ovs-dpdk" ) {
		$with_ovs_dpdk = 1;
	} elsif ( $cmd_flag eq "--with-openvswitch" ) {
		$with_openvswitch = 1;
	} elsif ( $cmd_flag eq "--upstream-libs" ) {
		# Keep for backward compatibility
	} elsif ( $cmd_flag eq "--umad-dev-rw" ) {
		$umad_dev_rw = 1;
	} elsif ( $cmd_flag eq "--umad-dev-na" ) {
		$umad_dev_na = 1;
	}elsif ( $cmd_flag eq "--without-fw-update" ) {
		$update_firmware = 0;
	} elsif ( $cmd_flag eq "--force-fw-update" ) {
		$update_firmware = 1;
		$fw_update_flags .= " --force-fw-update";
	} elsif ( $cmd_flag eq "--fw-update-only" ) {
		$update_firmware = 1;
		$firmware_update_only = 1;
	} elsif ( $cmd_flag eq "--fw-dir" ) {
		my $firmware_directory = shift(@ARGV);
		$fw_update_flags .= " --fw-dir $firmware_directory";
		push (@saved_ARGV, $firmware_directory);
	} elsif ( $cmd_flag eq "--fw-image-dir" ) {
		my $fw_image_dir = shift(@ARGV);
		$fw_update_flags .= " --fw-image-dir $fw_image_dir";
		push (@saved_ARGV, $fw_image_dir);
	} elsif ( $cmd_flag eq "--enable-affinity" ) {
		$enable_affinity = 1;
	} elsif ( $cmd_flag eq "--disable-affinity" ) {
		$enable_affinity = 0;
	} elsif ( $cmd_flag eq "--enable-opensm" and not ($install_option eq 'eth-only' or $is_mlnx_en) ) {
		$enable_opensm = 1;
	} elsif ( $cmd_flag eq "--enable-sriov" ) {
		$fw_update_flags .= " --enable-sriov";
	} elsif ( $cmd_flag eq "-q" ) {
		$quiet = 1;
		$verbose = 0;
		$verbose2 = 0;
		$verbose3 = 0;
		$fw_update_flags .= " -q";
	} elsif ( $cmd_flag eq "-v" ) {
		$verbose = 1;
		$fw_update_flags .= " -v";
	} elsif ( $cmd_flag eq "-vv" ) {
		$verbose = 1;
		$verbose2 = 1;
		$fw_update_flags .= " -v";
	} elsif ( $cmd_flag eq "-vvv" ) {
		$verbose = 1;
		$verbose2 = 1;
		$verbose3 = 1;
		$fw_update_flags .= " -v";
	} elsif ( $cmd_flag eq "--force" ) {
		$force = 1;
	} elsif ( $cmd_flag eq "-n" or $cmd_flag eq "--net" ) {
		$config_net = shift(@ARGV);
		$config_net_given = 1;
		push (@saved_ARGV, $config_net);
	} elsif ( $cmd_flag eq "-c" or $cmd_flag eq "--config" ) {
		$config = shift(@ARGV);
		$config_given = 1;
		push (@saved_ARGV, $config);
	} elsif ( $cmd_flag eq "-p" or $cmd_flag eq "--print-available" ) {
		$print_available = 1;
	} elsif ( $cmd_flag eq "--tmpdir" ) {
		$TMPDIR = shift(@ARGV);
		$TMPDIR = clean_path($TMPDIR);
		$config = $TMPDIR . '/ofed.conf' if (not $config_given);
		push (@saved_ARGV, $TMPDIR);
	} elsif ( $cmd_flag eq "--enable-mlnx_tune" ) {
		$enable_mlnx_tune = 1;
	} elsif ( $cmd_flag eq "--without-depcheck" ) {
		$check_linux_deps = 0;
	} elsif ( $cmd_flag eq "--check-deps-only" ) {
		$check_deps_only = 1;
	} elsif ( $cmd_flag eq "--with-mlxdevm-mod" ) {
		$with_mlxdevm = 1;
	} elsif ( $cmd_flag eq "--without-mlxdevm-mod" ) {
		$with_mlxdevm = 0;
	} elsif ( $cmd_flag eq "--print-distro" ) {
		$print_distro = 1;
	} elsif ( $cmd_flag eq "--without-dkms" ) {
		$with_dkms = 0;
		$force_dkms = 0;
		$dkms_flag_given = 0;
	} elsif ( $cmd_flag eq "--with-debug-symbols" ) {
		$with_kmod_debug_symbols = 1;
	} elsif ( $cmd_flag eq "--without-debug-symbols" ) {
		$with_kmod_debug_symbols = 0;
	} elsif ( $cmd_flag eq "--dkms" ) {
		$with_dkms = 1;
		$force_dkms = 0;
		$dkms_flag_given = 1;
	} elsif ( $cmd_flag eq "--force-dkms" ) {
		$with_dkms = 1;
		$force_dkms = 1;
	} elsif ( $cmd_flag eq "--enable-gds" ) {
		# Left for backward compatibility
	} elsif ( $cmd_flag eq "-k" or $cmd_flag eq "--kernel" ) {
		$kernel = shift(@ARGV);
		$kernel_given = 1;
		push (@saved_ARGV, $kernel);
	} elsif ( $cmd_flag eq "-s" or $cmd_flag eq "--kernel-sources" ) {
		$kernel_sources = shift(@ARGV);
		$kernel_source_given = 1;
		push (@saved_ARGV, $kernel_sources);
	} elsif ( $cmd_flag =~ /--without|--disable/ ) {
		my $pckg = $cmd_flag;
		$pckg =~ s/--without-|--disable-//;
		$disabled_packages{$pckg} = 1;
	} elsif ( $cmd_flag =~ /--with-|--enable-/ ) {
		my $pckg = $cmd_flag;
		$pckg =~ s/--with-|--enable-//;
		$force_enable_packages{$pckg} = 1;
	} elsif ( $cmd_flag eq "--distro" ) {
		$distro = shift(@ARGV);
		push (@saved_ARGV, $distro);
	} elsif ( $cmd_flag eq "--post-start-delay" ) {
		$post_start_delay = shift(@ARGV);
		push (@saved_ARGV, $post_start_delay);
	} elsif ( $cmd_flag eq "--add-kernel-support" ) {
		$add_kernel_support = 1;
		$add_kernel_support_build_only = 0;
		$with_dkms = 0;
		$force_dkms = 0;
		$dkms_flag_given = 0;
	} elsif ( $cmd_flag eq "--add-kernel-support-build-only" ) {
		$add_kernel_support = 1;
		$add_kernel_support_build_only = 1;
		$with_dkms = 0;
		$force_dkms = 0;
		$dkms_flag_given = 0;
	} elsif ( $cmd_flag eq "--kernel-extra-args" ) {
		$kernel_extra = 1;
		$kernel_extra_args = shift(@ARGV);
	} elsif ( $cmd_flag eq "--skip-repo" ) {
		$add_kernel_support_flags .= " --skip-repo";
	} elsif ( $cmd_flag eq "--auto-add-kernel-support" ) {
		$auto_add_kernel_support = 1;
	} elsif ( $cmd_flag eq "--skip-distro-check" ) {
		$skip_distro_check = 1;
	} elsif ( $cmd_flag eq "--skip-unsupported-devices-check" ) {
		$skip_unsupported_devices_check = 1;
	} elsif ( $cmd_flag =~ /--pre-install-/) {
		my $pckg = $cmd_flag;
		$pckg =~ s/--pre-install-//;
		my $script = shift(@ARGV);
		$package_pre_install_script{$pckg} = $script;
		push (@saved_ARGV, $script);
	} elsif ( $cmd_flag =~ /--post-install-/) {
		my $pckg = $cmd_flag;
		$pckg =~ s/--post-install-//;
		my $script = shift(@ARGV);
		$package_post_install_script{$pckg} = $script;
		push (@saved_ARGV, $script);
	} elsif ( $cmd_flag eq "--package-install-options" ) {
		my $install_opt = shift(@ARGV);
		push (@saved_ARGV, $install_opt);
		$install_opt =~ s/,/ /g;
		$DPKG_FLAGS .= " $install_opt";
	} elsif ( $cmd_flag eq "--copy-ifnames-udev" ) {
		$do_copy_udev = 1;
	} elsif ( $cmd_flag eq "--help" or $cmd_flag eq "-h" ) {
		usage();
		exit 0;
	} elsif ( $cmd_flag eq "--script-version") {
		print_script_version();
		exit 0;
	} else {
		print RED "\nUnsupported installation option: '$cmd_flag'", RESET "\n";
		print "To see list of supported options, run: $0 --help\n";
		exit $EINVAL;
	}
}

if ($user_space_only and $install_option eq 'kernel-only') {
    print RED "\nError: The options '--kernel-only' and '--user-space-only' are incompatible. Aborting.", RESET "\n";
    exit 1;
}

if ((not $add_kernel_support_build_only) and (not $print_available) and (not $print_distro)) {
    check_root_user();
}

my $DEBS = "$CWD/DEBS";

# packages to remove
my @remove_debs = qw(ar_mgr ar-mgr cc_mgr cc-mgr compat-dapl1 compat-dapl-dev dapl1 dapl1-utils dapl2-utils dapl-dev dump_pr dump-pr ibacm ibacm-dev ibsim ibsim-utils ibutils ibutils2 ibverbs-utils infiniband-diags infiniband-diags-compat infiniband-diags-guest libdapl2 libdapl-dev libibcm libibcm1 libibcm-dev libibdm1 libibdm-dev libibmad libibmad1 libibmad5 libibmad-dev libibmad-devel libibmad-static libibmad5-dbg libibnetdisc5 libibnetdisc-dev libibnetdisc5-dbg libibumad libibumad1 libibumad-dev libibumad-devel libibumad-static libibverbs libibverbs1 libibverbs1-dbg libibverbs-dev libipathverbs1 libipathverbs1-dbg libipathverbs-dev libmlx4 libmlx4-1 libmlx4-1-dbg libmlx4-dev libmlx5 libmlx5-1 libmlx5-1-dbg libmlx5-dev librxe-1 librxe-dev librxe-1-dbg libopensm libopensm2 libopensm2-dev libopensm-dev libopensm-devel librdmacm librdmacm1 librdmacm1-dbg librdmacm-dev libsdp1 libsdp-dev libumad2sim0 mlnx-ofed-kernel-dkms mlnx-ofed-kernel-modules mlnx-ofed-kernel-utils mlnx-tools ofed-docs ofed-scripts opensm opensm-libs opensm-doc perftest rdmacm-utils rds-tools sdpnetstat srptools mft kernel-mft-dkms mft-compat mft-devel mft-devmon mft-devmondb mft-int mft-oem mft-tests mstflint mxm ucx ucx-cuda fca openmpi openshmem mpitests knem knem-dkms ummunotify ummunotify-dkms libxlio libxlio-utils libxlio-dev libvma libvma-utils libvma-dev libvma-dbg dpcp sockperf srptools iser-dkms isert-dkms srp-dkms libmthca-dev libmthca1 libmthca1-dbg ibdump mlnx-ethtool mlnx-iproute2 mlnx-fw-updater knem-modules iser-modules isert-modules srp-modules ummunotify-modules kernel-mft-modules libosmvendor libosmvendor4 libosmcomp libosmcomp3 mlnx-en mlnx-en-utils mlnx-en-dkms mlnx-en-modules mlnx-sdp-dkms mlnx-sdp-modules mlnx-rds-dkms mlnx-rds-modules mlnx-nfsrdma-dkms mlnx-nfsrdma-modules mlnx-nvme-dkms mlnx-nvme-modules mlnx-rdma-rxe-dkms mlnx-rdma-rxe-modules ibverbs-providers libibumad3 libibumad3-dbg rdma-core libdisni-java-jni neohost-backend neohost-sdk rshim-modules rshim-dkms rshim python3-pyverbs mlnx-tools nvme-snap spdk spdk-dev mlxbf-bootctl mlx-steering-dump ibarr);

my @immune_debs_list = map {"qemu-system-$_"} qw(arm misc mips ppc s390x sparc x86 x86-microvm x86-xen);
my %immune_debs = map { $_ => 1 } @immune_debs_list;

# required packages (will be always installed)
my @required_debs = qw(autotools-dev autoconf automake m4 debhelper chrpath swig graphviz dpatch libltdl-dev dpkg);

if ($kernel_given and not $kernel_source_given) {
    if (-d "/lib/modules/$kernel/build") {
        $kernel_sources = "/lib/modules/$kernel/build";
    }
    else {
        print RED "Provide path to the kernel sources for $kernel kernel.", RESET "\n";
        exit 1;
    }
}

#
# logging
#
my $ofedlogs = "$TMPDIR/$PACKAGE.$$.logs";
mkpath([$ofedlogs]);
my $glog = "$ofedlogs/general.log";
rmtree $glog;
open(GLOG, ">$glog") or die "Can't open $glog: $!\n";
close(GLOG);

sub print_and_log
{
	my $msg = shift @_;
	my $verb = shift @_;

	open(GLOG, ">>$glog") or die "Can't open $glog: $!\n";
	print GLOG "$msg";
	close(GLOG);

	if ($verb) {
		print "$msg";
	}
}

sub print_and_log_colored
{
	my $msg = shift @_;
	my $verb = shift @_;
	my $color = shift @_;

	open(GLOG, ">>$glog") or die "Can't open $glog: $!\n";
	print GLOG "$msg\n";
	close(GLOG);

	if ($verb) {
		if ($color eq "RED") {
			print RED "$msg", RESET "\n";
		} elsif ($color eq "YELLOW") {
			print YELLOW "$msg", RESET "\n";
		} elsif ($color eq "GREEN") {
			print GREEN "$msg", RESET "\n";
		} else {
			print "$msg\n";
		}
	}
}

sub warning($) {
	my $msg = shift @_;
	print_and_log_colored($msg, 1, "YELLOW");
}

print_and_log("Install command: $CMD\n", 0);

# was add kernel support ran for this kernel and --dkms not given?
if (not $force_dkms and not $dkms_flag_given and isKernelSupported()) {
    $with_dkms = 0;
}

# disable DKMS if given kernel was not installed from deb package
if (not $force_dkms and $with_dkms and -d "$kernel_sources/scripts") {
	my $src_path = Cwd::abs_path "$kernel_sources/scripts";
	chomp $src_path;
	if ($src_path eq "") {
		$src_path = "$kernel_sources/scripts";
	}
	system("$DPKG -S '$src_path' >/dev/null 2>&1");
	my $res = $? >> 8;
	my $sig = $? & 127;
	if ($sig or $res) {
		print_and_log("DKMS is not supported for kernels which were not installed as DEB.\n", $verbose2);
		$with_dkms = 0;
	}
}

## set OS, arch
# don't auto-detect distro if it's provided by the user.
if ($distro eq "") {
	print_and_log("Distro was not provided, trying to auto-detect the current distro...\n", $verbose2);
	my $dist_os  = os_release('ID');
	if (not $dist_os) {
		print_and_log("/etc/os-release is missing or invalid\n");
	}
	my $dist_ver = os_release('VERSION_ID');
	$distro = "$dist_os$dist_ver";
	$distro = lc($distro);
	print_and_log("Auto-detected $distro distro.\n", $verbose2);
} else {
	$distro = lc($distro);
	print_and_log("Using provided distro: $distro\n", $verbose2);
}
if ($print_distro) {
    print_and_log("Printing distribution name and exiting:\n", $verbose2);
    print "$distro\n";
    exit 0;
}

if ($distro !~ m/debian | ubuntu | uos/x) {
	print_and_log_colored("Current operation system is not supported ($distro)!", 1, "RED");
	exit 1;
}

# Returns the version of CUDA installed, but only if it is >= 11.2
# Format: 11-2
sub get_installed_cuda_version() {
    my $cuda_symlink = "/usr/local/cuda";
    return "" unless (-e $cuda_symlink);

    my $cuda_path = `realpath $cuda_symlink 2>/dev/null`;
    chomp $cuda_path;
    return "" unless ($cuda_path =~ /-([0-9.]+)$/);

    my $version = $1;
    if ($version < 11.6) {
	return "";
    }
    $version =~ s/\./-/;

    my @dpkg_output = `dpkg-query --status cuda-cudart-$version 2>/dev/null`;
    foreach (@dpkg_output) {
        next unless (/^Status:/);
        return $version if (/installed/);
	return "";
    }
    return ""; # Should not happen
}
my $cuda_version = get_installed_cuda_version();

##


#
# set kernel packages names
#
my $mlnX_ofed_kernel = "mlnx-ofed-kernel-dkms";
my $kernel_mft = "kernel-mft-dkms";
my $knem = "knem-dkms";
my $iser = "iser-dkms";
my $isert = "isert-dkms";
my $srp = "srp-dkms";
my $mlnx_en = "mlnx-en-dkms";
my $mlnx_nfsrdma = "mlnx-nfsrdma-dkms";
my $mlnx_nvme = "mlnx-nvme-dkms";
my $mlnx_rdma_rxe = "mlnx-rdma-rxe-dkms";

if (not $with_dkms) {
	$mlnX_ofed_kernel = "mlnx-ofed-kernel-modules";
	$kernel_mft = "kernel-mft-modules";
	$knem = "knem-modules";
	$iser = "iser-modules";
	$isert = "isert-modules";
	$srp = "srp-modules";
	$mlnx_en = "mlnx-en-modules";
	$mlnx_nfsrdma = "mlnx-nfsrdma-modules";
	$mlnx_nvme = "mlnx-nvme-modules";
	$mlnx_rdma_rxe = "mlnx-rdma-rxe-modules";
}

my $kernel_escaped = $kernel;
$kernel_escaped =~ s/\+/\\\+/g;

my $libipsec_mb = "libipsec-mb0";
if ($distro =~ /ubuntu22.04/) {
	$libipsec_mb = "libipsec-mb1";
}
if ($arch  ne 'x86_64') {
	$libipsec_mb = "";
}

my @mlnx_dpdk_packages = (
				"mlnx-dpdk",
				"mlnx-dpdk-dev",
			);

my @openvswitch_packages = (
				"libopenvswitch",
				"libopenvswitch-dev",
				"openvswitch-common",
				"openvswitch-datapath-dkms",
				"openvswitch-datapath-source",
				"openvswitch-dbg",
				"openvswitch-ipsec",
				"openvswitch-pki",
				"openvswitch-switch",
				"openvswitch-test",
				"openvswitch-testcontroller",
				"openvswitch-vtep",
				"ovn-central",
				"ovn-common",
				"ovn-controller-vtep",
				"ovn-docker",
				"ovn-host",
				"python3-openvswitch"
	);

push (@remove_debs, @mlnx_dpdk_packages);
if (($with_ovs_dpdk or $with_openvswitch or $with_bluefield) and $arch =~ /x86_64|aarch64/) {
	push (@remove_debs, @openvswitch_packages);
}

# custom packages
my @all_packages = (
				"ofed-scripts",
				"mlnx-tools",
				"mlnx-ofed-kernel-utils", "$mlnX_ofed_kernel",
				"$iser",
				"$isert",
				"$srp",
				"$mlnx_nfsrdma",
				"$mlnx_nvme",
				"$mlnx_rdma_rxe",
				"libibverbs1", "ibverbs-utils", "libibverbs-dev", "libibverbs1-dbg",
				"ibvers-providers",
				"libibumad3", "libibumad-dev",
				"ibacm",
				"librdmacm1", "rdmacm-utils", "librdmacm-dev",
				"mstflint",
				"ibdump",
				"libibmad5", "libibmad-dev",
				"opensm", "libopensm", "opensm-doc", "libopensm-devel",
				"infiniband-diags",
				"mft", "$kernel_mft",
				"perftest",
				"ibutils2",
				"cc-mgr",
				"ar-mgr",
				"dump-pr",
				"ibsim", "ibsim-doc",
				"ucx",
				"ucx-cuda",
				"sharp",
				"hcoll",
				"openmpi",
				"mpitests",
				"knem", "$knem",
				"libdapl2", "dapl2-utils", "libdapl-dev",
				"libvma", "libvma-utils", "libvma-dev",
				"libxlio", "libxlio-utils", "libxlio-dev",
				"dpcp",
				"sockperf",
				"srptools",
				"mlnx-ethtool",
				"mlnx-iproute2",
				"rshim",
				"neohost-backend",
				"neohost-sdk",
				"ibarr",
);

my @basic_packages = (
				"ofed-scripts",
				"mlnx-tools",
				"mlnx-ofed-kernel-utils", "$mlnX_ofed_kernel",
				"$iser",
				"$isert",
				"$srp",
				"$mlnx_nfsrdma",
				"$mlnx_nvme",
				"$mlnx_rdma_rxe",
				"libibverbs1", "ibverbs-utils", "libibverbs-dev", "libibverbs1-dbg",
				"ibvers-providers",
				"libibumad3", "libibumad-dev",
				"ibacm",
				"librdmacm1", "rdmacm-utils", "librdmacm-dev",
				"mstflint",
				"ibdump",
				"libibmad5", "libibmad-dev",
				"opensm", "libopensm", "opensm-doc", "libopensm-devel",
				"infiniband-diags",
				"mft", "$kernel_mft",
				"srptools",
				"rshim",
				"mlnx-ethtool",
				"mlnx-iproute2",
				"neohost-backend",
				"neohost-sdk",
);

my @bluefield_packages = (
				"ofed-scripts",
				"mlnx-tools",
				"mlnx-ofed-kernel-utils", "$mlnX_ofed_kernel",
				"$iser",
				"$isert",
				"$srp",
				"$mlnx_nvme",
				"$mlnx_rdma_rxe",
				"libibverbs1", "ibverbs-utils", "libibverbs-dev",
				"ibvers-providers",
				"libibumad3", "libibumad-dev",
				"ibacm",
				"perftest",
				"ucx",
				"ucx-cuda",
				"knem", "$knem",
				"ibutils2",
				"librdmacm1", "rdmacm-utils", "librdmacm-dev",
				"mstflint",
				"ibdump",
				"libibmad5", "libibmad-dev",
				"opensm", "libopensm", "opensm-doc", "libopensm-devel",
				"infiniband-diags",
				"mft", "mft-oem", "$kernel_mft",
				"srptools",
				"ibdump",
				"mlnx-ethtool",
				"mlnx-iproute2",
				"nvme-snap",
				"spdk",
				"spdk-dev",
				"mlxbf-bootctl",
);

my @hpc_packages = (
				@basic_packages,
				"ibacm",
				"perftest",
				"ibutils2",
				"cc-mgr",
				"ar-mgr",
				"dump-pr",
				"ibsim", "ibsim-doc",
				"ucx",
				"ucx-cuda",
				"sharp",
				"hcoll",
				"openmpi",
				"mpitests",
				"knem", "$knem",
				"libdapl2", "dapl2-utils", "libdapl-dev",
);

my @xlio_packages = (
				@basic_packages,
				"perftest",
				"ibutils2",
				"cc-mgr",
				"ar-mgr",
				"dump-pr",
				"ibsim", "ibsim-doc",
				"libxlio", "libxlio-utils", "libxlio-dev",
				"dpcp",
				"sockperf",
				"rshim",
);

my @vma_packages = (
				@basic_packages,
				"perftest",
				"ibutils2",
				"cc-mgr",
				"ar-mgr",
				"dump-pr",
				"ibsim", "ibsim-doc",
				"libvma", "libvma-utils", "libvma-dev",
				"dpcp",
				"sockperf",
				"rshim",
);

my @vmavpi_packages = (
				@basic_packages,
				"perftest",
				"ibutils2",
				"cc-mgr",
				"ar-mgr",
				"dump-pr",
				"ibsim", "ibsim-doc",
				"libvma", "libvma-utils", "libvma-dev",
				"dpcp",
				"sockperf",
				"rshim",
);

my @msm_packages = (
				@basic_packages,
				"perftest",
				"ibutils2",
				"cc-mgr",
				"ar-mgr",
				"dump-pr",
				"ibsim", "ibsim-doc",
);

my @vmaeth_packages = (
				"ofed-scripts",
				"mlnx-tools",
				"mlnx-ofed-kernel-utils", "$mlnX_ofed_kernel",
				"$iser",
				"$isert",
				"$srp",
				"$mlnx_nfsrdma",
				"$mlnx_nvme",
				"$mlnx_rdma_rxe",
				"libibverbs1", "ibverbs-utils", "libibverbs-dev", "libibverbs1-dbg",
				"ibvers-providers",
				"libibumad3", "libibumad-dev",
				"ibacm",
				"librdmacm1", "rdmacm-utils", "librdmacm-dev",
				"mstflint",
				"ibdump",
				"mft", "$kernel_mft",
				"libvma", "libvma-utils", "libvma-dev",
				"dpcp",
				"sockperf",
				"rshim",
				"mlnx-ethtool",
				"mlnx-iproute2",
);

my @guest_packages = (
				@basic_packages,
				"ibacm",
				"perftest",
				"libdapl2", "dapl2-utils", "libdapl-dev",
				"ucx",
				"ucx-cuda",
				"sharp",
				"hcoll",
				"openmpi",
				"mpitests",
				"knem", "$knem",
);

my @hypervisor_packages = (
				@basic_packages,
				"ibacm",
				"perftest",
				"libdapl2", "dapl2-utils", "libdapl-dev",
				"ibutils2",
				"ibarr",
);

my @eth_packages = (
				"$mlnx_en",
				"mlnx-tools",
				"mlnx-en-utils",
				"mstflint",
);

my @dpdk_packages = (
				"ofed-scripts", "mstflint", "mlnx-tools",
				"mlnx-ofed-kernel-utils", "$mlnX_ofed_kernel",
				"libibverbs1", "ibverbs-utils", "libibverbs-dev",
				"ibvers-providers",
				"librdmacm1", "rdmacm-utils", "librdmacm-dev", "ibacm",
);

##
my %kernel_packages = ("$mlnX_ofed_kernel" => {'ko' => ["mlx5_ib", "mlx5_core"]},
			"$mlnx_en" => {'ko' => ["mlx5_core"]},
			"$knem" => {'ko' => ["knem"]},
			"$kernel_mft" => {'ko' => ["mst_pci", "mst_pciconf"]},
			"$iser" => {'ko' => ["ib_iser"]},
			"$isert" => {'ko' => ["ib_isert"]},
			"$srp" => {'ko' => ["ib_srp"]},
			"$mlnx_nfsrdma" => {'ko' => ["rpcrdma"]},
			"$mlnx_nvme" => {'ko' => ["nvme_rdma"]},
			"$mlnx_rdma_rxe" => {'ko' => ["rdma_rxe"]},
			);

# OS specific package names
my $module_tools = "kmod";
my $libssl = "libssl1.0.0";
my $libssl_devel = "libssl-dev";
my @rdmacore_python = qw/cython3 python3-dev/;
my @libsystemd_dev = qw/libsystemd-dev/;
if ($distro =~ /ubuntu1[0-7] | debian[5-9]/x) {
	@rdmacore_python = qw/python/; # older systems have no pyverbs
} else {
	push @dpdk_packages, "python3-pyverbs";
}
if ($distro =~ /ubuntu1[0-4] | debian[5-6]/x) {
	# Technically: libnih, practically: optional dependency:
	@libsystemd_dev = ();
}
if ( $distro =~ /debian6|ubuntu1[0-2]/) {
	$module_tools = "module-init-tools";
}
if ( $distro =~ /debian6\.0/) {
	$libssl = "libssl0.9.8";
}
if ($distro =~ /debian9/) {
	$libssl = "libssl1.0.2";
	$libssl_devel = "libssl1.0-dev";
} elsif ($distro =~ /ubuntu(19|2[01]) | debian1[0-9] | uos/x) {
	$libssl = "libssl1.1";
} elsif ($distro =~ /ubuntu22/) {
	$libssl = "libssl3";
}


my $libudev = "libudev1";
my $libudev_devel = "libudev-dev";

my $dh_systemd = "debhelper";
if ($distro =~ /ubuntu1[0-7] | debian[4-8]/x) {
	$dh_systemd = "dh-systemd";
}

my $python2 = "python2";
if ($distro =~ /debian[89] | ubuntu1[1-8]/x) {
	$python2 = "python";
}

my $libgfortran = "libgfortran5";
if ($distro =~ /ubuntu18/x) {
        $libgfortran = "libgfortran4";
} elsif ($distro =~ /ubuntu1[46] | debian[89]/x) {
        $libgfortran = "libgfortran3";
}

my $distutils = "python3-distutils";
if ($distro =~ /debian[8-9] | ubuntu1[4-7]/x) {
	$distutils = "";
}

if ($with_ovs_dpdk and ($arch !~ /x86_64|aarch64/ or $distro !~ /debian10 | debian11 | ubuntu20.04 | ubuntu22.04/x)) {
	print YELLOW "\nWARNING: The '--ovs-dpdk' option is supported only on Ubuntu 20.04, Ubuntu 22.04, Debian10 and Debian11, x86_64 and aarch64. Disabling...", RESET "\n";
	$with_ovs_dpdk = 0;
}

my $libpython = "";
if ($distro =~ /debian10|uos/) {
	$libpython = "libpython3.7";
} elsif ($distro =~ /debian11/) {
	$libpython = "libpython3.9";
}
###############

# define kernel modules
my @basic_kernel_modules = ("core", "mlxfw", "mlx5", "ipoib", "mlxdevm");
my @ulp_modules = ("sdp", "srp", "srpt", "rds", "iser", "e_ipoib", "nfsrdma", 'isert', "mlxdevm");
my @kernel_modules = (@basic_kernel_modules, @ulp_modules);
my @bluefield_kernel_modules = ("core", "mlxfw", "mlx5", "ipoib", "srp", "iser", "isert", "mlxdevm");
my @hpc_kernel_modules = (@basic_kernel_modules);
my @vma_kernel_modules = (@basic_kernel_modules);
my @xlio_kernel_modules = (@basic_kernel_modules);
my @hypervisor_kernel_modules = ("core","mlxfw","mlx5","ipoib","srp","iser", 'isert', "mlxdevm");
my @guest_kernel_modules = ("core","mlxfw","mlx5","ipoib","srp","iser", 'isert', "mlxdevm");

my %kernel_modules_info = (
			'core' =>
			{ name => "core", available => 1, selected => 0,
			included_in_rpm => 0, requires => [], },
			'mlxfw' =>
			{ name => "mlxfw", available => 1, selected => 0,
			included_in_rpm => 0, requires => [], },
			'mthca' =>
			{ name => "mthca", available => 0, selected => 0,
			included_in_rpm => 0, requires => ["core"], },
			'mlx4' =>
			{ name => "mlx4", available => 1, selected => 0,
			included_in_rpm => 0, requires => ["core"], },
			'mlx5' =>
			{ name => "mlx5", available => 1, selected => 0,
			included_in_rpm => 0, requires => ["core"], },
			'mlx4_en' =>
			{ name => "mlx4_en", available => 1, selected => 0,
			included_in_rpm => 0, requires => ["core","mlx4"], },
			'mlx4_vnic' =>
			{ name => "mlx4_vnic", available => 0, selected => 0,
			included_in_rpm => 0, requires => ["core","mlx4"], },
			'mlx4_fc' =>
			{ name => "mlx4_fc", available => 0, selected => 0,
			included_in_rpm => 0, requires => ["core","mlx4_en"], },
			'ipoib' =>
			{ name => "ipoib", available => 1, selected => 0,
			included_in_rpm => 0, requires => ["core"], },
			'mlx5_fpga_tools' =>
			{ name => "mlx5_fpga_tools", available => 1, selected => 0,
			included_in_rpm => 0, requires => ["core"], },
			'sdp' =>
			{ name => "sdp", available => 0, selected => 0,
			included_in_rpm => 0, requires => ["core", "ipoib"], },
			'srp' =>
			{ name => "srp", available => 1, selected => 0,
			included_in_rpm => 0, requires => ["core", "ipoib"], },
			'srpt' =>
			{ name => "srpt", available => 0, selected => 0,
			included_in_rpm => 0, requires => ["core"], },
			'rds' =>
			{ name => "rds", available => 0, selected => 0,
			included_in_rpm => 0, requires => ["core", "ipoib"], },
			'e_ipoib' =>
			{ name => "e_ipoib", available => 0, selected => 0,
			included_in_rpm => 0, requires => ["core", "ipoib"], },
			'iser' =>
			{ name => "iser", available => 1, selected => 0,
			included_in_rpm => 0, requires => ["core", "ipoib"], ofa_req_inst => [] },
			'isert' =>
			{ name => "isert", available => 1, selected => 0,
			included_in_rpm => 0, requires => ["core", "ipoib"], ofa_req_inst => [] },
			'nfsrdma' =>
			{ name => "nfsrdma", available => 1, selected => 0,
			included_in_rpm => 0, requires => ["core", "ipoib"], },
			'mlxdevm' =>
			{ name => "mlxdevm", available => 1, selected => 0,
			included_in_rpm => 0, requires => ["mlx5"], },
);

# define packages
my %packages_info = (
			'ar-mgr' =>
				{
				dist_req_build => ["libstdc++6"],
				dist_req_inst => ["libstdc++6"],
				ofa_req_build => ["libopensm", "libopensm-devel", "ibutils2"],
				ofa_req_inst => ["opensm", "ibutils2"],
				},
			'cc-mgr' =>
				{
				dist_req_build => ["libstdc++6"],
				dist_req_inst => ["libstdc++6"],
				ofa_req_build => ["libopensm", "libopensm-devel", "ibutils2"],
				ofa_req_inst => ["opensm", "ibutils2"],
				},
			'dump-pr' =>
				{
				dist_req_build => ["libstdc++6"],
				dist_req_inst => ["libstdc++6"],
				ofa_req_build => ["libopensm", "libopensm-devel"],
				ofa_req_inst => ["opensm"],
				},
			'ibacm' =>
				{
				parent => "rdma-core",
				ofa_req_build => ["libibverbs-dev", "libibumad-dev", "$mlnX_ofed_kernel"],
				ofa_req_inst => ["libibverbs1", "libibumad3", "rdma-core"],
				},
			'ibsim-doc' =>
				{
				parent => "ibsim",
				ofa_req_build => ["libibmad-dev", "libibumad-dev"],
				ofa_req_inst => ["libibmad5", "libibumad3"],
				},
			'ibsim' =>
				{
				parent => "ibsim",
				ofa_req_build => ["libibmad-dev", "libibumad-dev"],
				ofa_req_inst => ["libibmad5", "libibumad3"],
				},
			'ibutils2' =>
				{
				dist_req_build => ["tcl-dev", "tk-dev", "libstdc++6"],
				dist_req_inst => ["tcl", "tk", "libstdc++6"],
				ofa_req_build => ["libibumad-dev"],
				ofa_req_inst => ["libibumad3"],
				},
			'infiniband-diags' =>
				{
				parent => "rdma-core",
				dist_req_build => ["libglib2.0-dev"],
				dist_req_inst => ["libglib2.0-0"],
				ofa_req_build => ["libopensm", "libopensm-devel", "libibumad-dev", "libibmad-dev"],
				ofa_req_inst => ["libibumad3", "libibnetdisc5", "libibmad5"],
				},
			'kernel-mft-dkms' =>
				{
				parent => "kernel-mft",
				mode => "kernel",
				dist_req_build => ["dkms", "gcc", "make"],
				dist_req_inst => ["dkms", "gcc", "make"],
				},
			'kernel-mft' =>
				{
				parent => "kernel-mft",
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				},
			'kernel-mft-modules' =>
				{
				parent => "kernel-mft",
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				},
			'knem-dkms' =>
				{
				parent => "knem",
				mode => "kernel",
				dist_req_build => ["build-essential", "debhelper", "pkg-config", "bzip2", "dh-autoreconf", "dkms"],
				dist_req_inst => ["dkms", "gcc", "make", "pkg-config", "libc6-dev"],
				},
			'knem-modules' =>
				{
				parent => "knem",
				mode => "kernel",
				dist_req_build => ["build-essential", "debhelper", "pkg-config", "bzip2", "dh-autoreconf"],
				},
			'knem' =>
				{
				parent => "knem",
				mode => "kernel",
				dist_req_build => ["build-essential", "debhelper", "pkg-config", "bzip2", "dh-autoreconf"],
				dist_req_inst => ["pkg-config"],
				ofa_req_inst => [$knem],
				},
			'dapl' =>
				{
				available => 0,
				ofa_req_build => ["librdmacm-dev", "libibverbs-dev"],
				ofa_req_inst => ["libibverbs1", "librdmacm1"],
				},
			'dapl2-utils' =>
				{
				parent => "dapl",
				ofa_req_build => ["librdmacm-dev", "libibverbs-dev"],
				ofa_req_inst => ["libibverbs1", "librdmacm1"],
				},
			'libdapl-dev' =>
				{
				parent => "dapl",
				ofa_req_build => ["librdmacm-dev", "libibverbs-dev"],
				ofa_req_inst => ["libdapl2", "librdmacm1"],
				},
			'libdapl2' =>
				{
				parent => "dapl",
				ofa_req_build => ["librdmacm-dev", "libibverbs-dev"],
				ofa_req_inst => ["libibverbs1", "librdmacm1"],
				},
			'libibmad-dev' =>
				{
				parent => "rdma-core",
				ofa_req_build => ["libibumad-dev"],
				ofa_req_inst => ["libibmad5"],
				},
			'libibmad5' =>
				{
				parent => "rdma-core",
				dist_req_build => ["libtool"],
				ofa_req_build => ["libibumad-dev"],
				ofa_req_inst => ["libibumad3"],
				},
			'libibnetdisc5' =>
				{
				parent => "rdma-core",
				ofa_req_inst => ["libibmad5", "libibumad3"],
				},
			'libibnetdisc-dev' =>
				{
				parent => "rdma-core",
				ofa_req_inst => ["libibnetdisc5"],
				},
			'libibnetdisc5-dbg' =>
				{
				parent => "rdma-core",
				ofa_req_inst => ["libibnetdisc5"],
				},
			'ibverbs-utils' =>
				{
				parent => "rdma-core",
				ofa_req_inst => ["libibverbs1"],
				},
			'libibverbs-dev' =>
				{
				parent => "rdma-core",
				ofa_req_inst => ["libibverbs1", "ibverbs-providers"],
				},
			'libibverbs1-dbg' =>
				{
				parent => "rdma-core",
				ofa_req_inst => ["libibverbs1", "rdma-core"],
				},
			'libibverbs1' =>
				{
				parent => "rdma-core",
				dist_req_build => ["libnl-3-dev", "libnl-route-3-dev", "pkg-config"],
				dist_req_inst => ["libnl-3-200", "libnl-route-3-200", "adduser"],
				ofa_req_inst => ["rdma-core"],
				},

			'librdmacm-dev' =>
				{
				parent => "rdma-core",
				ofa_req_build => ["libibverbs-dev"],
				ofa_req_inst => ["librdmacm1", "rdma-core", "libibverbs-dev"],
				},
			'librdmacm1' =>
				{
				parent => "rdma-core",
				ofa_req_build => ["libibverbs-dev"],
				ofa_req_inst => ["libibverbs1", "rdma-core"],
				},
			'dpcp' =>
				{
				dist_req_build => ["pkg-config", "automake", "autoconf", "libtool"],
				ofa_req_build => ["libibverbs-dev"],
				ofa_req_inst => ["libibverbs1", "ibverbs-providers"],
				},
			'libvma' =>
				{
				parent => "libvma",
				dist_req_build => ["libnl-3-dev"],
				dist_req_inst => ["libnl-3-200"],
				ofa_req_build => ["librdmacm1", "librdmacm-dev", "libibverbs1", "libibverbs-dev", "dpcp"],
				ofa_req_inst => ["librdmacm1", "libibverbs1", "ibverbs-providers", "dpcp"],
				soft_req => ["dpcp"],
				},
			'libvma-utils' =>
				{
				parent => "libvma",
				ofa_req_build => ["librdmacm1", "librdmacm-dev", "libibverbs1", "libibverbs-dev", "dpcp"],
				ofa_req_inst => ["librdmacm1", "libibverbs1", "libvma"],
				soft_req => ["dpcp"],
				},
			'libvma-dev' =>
				{
				parent => "libvma",
				ofa_req_build => ["librdmacm1", "librdmacm-dev", "libibverbs1", "libibverbs-dev", "dpcp"],
				ofa_req_inst => ["librdmacm1", "libibverbs1", "libvma"],
				soft_req => ["dpcp"],
				},
			'libxlio' =>
				{
				parent => "libxlio",
				dist_req_build => ["libnl-3-dev"],
				dist_req_inst => ["libnl-3-200"],
				ofa_req_build => ["librdmacm1", "librdmacm-dev", "libibverbs1", "libibverbs-dev", "dpcp"],
				ofa_req_inst => ["librdmacm1", "libibverbs1", "ibverbs-providers", "dpcp"],
				},
			'libxlio' =>
				{
				parent => "libxlio",
				dist_req_build => ["libnl-3-dev"],
				dist_req_inst => ["libnl-3-200"],
				ofa_req_build => ["librdmacm1", "librdmacm-dev", "libibverbs1", "libibverbs-dev", "dpcp"],
				ofa_req_inst => ["librdmacm1", "libibverbs1", "ibverbs-providers", "dpcp"],
				},
			'libxlio-utils' =>
				{
				parent => "libxlio",
				ofa_req_build => ["librdmacm1", "librdmacm-dev", "libibverbs1", "libibverbs-dev", "dpcp"],
				ofa_req_inst => ["librdmacm1", "libibverbs1", "libxlio"],
				},
			'libxlio-dev' =>
				{
				parent => "libxlio",
				ofa_req_build => ["librdmacm1", "librdmacm-dev", "libibverbs1", "libibverbs-dev", "dpcp"],
				ofa_req_inst => ["librdmacm1", "libibverbs1", "libxlio"],
				},

			'sockperf' =>
				{
				dist_req_build => ["doxygen"],
				},

			'rshim' =>
				{
				dist_req_build => ["autoconf", "autotools-dev", "pkg-config", "build-essential", "devscripts", "fakeroot", "libpci-dev", "libusb-1.0-0-dev", "libfuse-dev"],
				dist_req_inst => ["libpci3", "libusb-1.0-0", "libfuse2"],
				},

			'mft' =>
				{
				},
			'mft-oem' =>
				{
				},
			'mlnx-ofed-kernel' =>
				{
				parent => "mlnx-ofed-kernel",
				available => 0,
				mode => "kernel",
				dist_req_build => ["dkms", "quilt", "make", "gcc", "$distutils"],
				dist_req_inst => ["dkms", "quilt", "make", "gcc", "coreutils", "pciutils", "grep", "perl", "procps", "$module_tools", "lsof"],
				ofa_req_build => ["$mlnX_ofed_kernel", "mlnx-ofed-kernel-utils"],
				ofa_req_inst => ["$mlnX_ofed_kernel", "mlnx-ofed-kernel-utils"],
				soft_req => ["ofed-scripts"],
				},
			'mlnx-ofed-kernel-dkms' =>
				{
				parent => "mlnx-ofed-kernel",
				mode => "kernel",
				dist_req_build => ["dkms", "quilt", "make", "gcc", "$distutils"],
				dist_req_inst => ["dkms", "quilt", "make", "gcc", "$distutils", "coreutils", "pciutils", "grep", "perl", "procps", "$module_tools", "lsof", "libc6-dev"],
				ofa_req_inst => ["ofed-scripts", "mlnx-ofed-kernel-utils"],
				soft_req => ["ofed-scripts"],
				},
			'mlnx-ofed-kernel-modules' =>
				{
				parent => "mlnx-ofed-kernel",
				mode => "kernel",
				dist_req_build => ["quilt", "make", "gcc", "$distutils"],
				dist_req_inst => ["quilt", "make", "gcc", "coreutils", "pciutils", "grep", "perl", "procps", "$module_tools", "lsof"],
				ofa_req_inst => ["ofed-scripts", "mlnx-ofed-kernel-utils"],
				soft_req => ["ofed-scripts"],
				},
			'mlnx-ofed-kernel-utils' =>
				{
				parent => "mlnx-ofed-kernel",
				mode => "kernel",
				dist_req_build => ["quilt", "make", "gcc", "$distutils"],
				dist_req_inst => ["ethtool", "coreutils", "pciutils", "grep", "perl", "procps", "$module_tools", "lsof"],
				ofa_req_inst => ["ofed-scripts", "mlnx-tools"],
				soft_req => ["ofed-scripts"],
				},

			# eth only
			'mlnx-en' =>
				{
				parent => "mlnx-en",
				available => 0,
				mode => "kernel",
				dist_req_build => ["dkms", "quilt", "make", "gcc", "$distutils"],
				dist_req_inst => ["dkms", "quilt", "make", "gcc", "coreutils", "pciutils", "grep", "perl", "procps", "$module_tools", "lsof"],
				ofa_req_build => ["$mlnx_en", "mlnx-en-utils"],
				ofa_req_inst => ["$mlnx_en", "mlnx-en-utils"],
				soft_req => ["ofed-scripts"],
				},
			'mlnx-en-dkms' =>
				{
				parent => "mlnx-en",
				mode => "kernel",
				dist_req_build => ["dkms", "quilt", "make", "gcc", "$distutils"],
				dist_req_inst => ["dkms", "quilt", "make", "gcc", "$distutils", "coreutils", "pciutils", "grep", "perl", "procps", "$module_tools", "lsof", "libc6-dev"],
				ofa_req_inst => ["mlnx-en-utils"],
				soft_req => ["ofed-scripts"],
				},
			'mlnx-en-modules' =>
				{
				parent => "mlnx-en",
				mode => "kernel",
				dist_req_build => ["quilt", "make", "gcc", "$distutils"],
				dist_req_inst => ["quilt", "make", "gcc", "coreutils", "pciutils", "grep", "perl", "procps", "$module_tools", "lsof"],
				ofa_req_inst => ["mlnx-en-utils"],
				soft_req => ["ofed-scripts"],
				},
			'mlnx-en-utils' =>
				{
				parent => "mlnx-en",
				mode => "kernel",
				dist_req_build => ["quilt", "make", "gcc", "$distutils"],
				dist_req_inst => ["quilt", "make", "gcc", "coreutils", "pciutils", "grep", "perl", "procps", "$module_tools", "lsof"],
				ofa_req_inst => ['ofed-scripts', "mlnx-tools"],
				soft_req => ["ofed-scripts"],
				},
			'mlnx-tools' =>
				{
				dist_req_build => ["python3", "dh-python"],
				dist_req_inst => ["python3"],
				},

			'mpitests' =>
				{
				dist_req_build => ["$libgfortran"],
				dist_req_inst => ["$libgfortran", "gfortran"],
				ofa_req_build => ["openmpi", "libibumad-dev", "librdmacm-dev", "libibmad-dev"],
				ofa_req_inst => ["openmpi", "libibumad3", "librdmacm1", "libibmad5"],
				},
			'mstflint' =>
				{
				dist_req_build => ["$libssl_devel"],
				dist_req_inst => ["$libssl"],
				},
			'ucx' =>
				{
				parent => "ucx",
				dist_req_build => ["libstdc++6", "pkg-config", "libnuma-dev"],
				dist_req_inst => ["libstdc++6", "pkg-config"],
				ofa_req_build => ["libibverbs-dev", "librdmacm-dev"],
				ofa_req_inst => ["libibverbs1", "librdmacm1"],
				},
			'ucx-cuda' =>
				{
				parent => "ucx",
				available => 0,
				dist_req_build => ["libstdc++6", "pkg-config", "libnuma-dev",
					"cuda-libraries-dev-$cuda_version"],
				dist_req_inst => ["cuda-cudart-$cuda_version"],
				ofa_req_build => ["libibverbs-dev", "librdmacm-dev"],
				ofa_req_inst => ["ucx"],
				},

			'ofed-scripts' =>
				{
				},
			'openmpi' =>
				{
				dist_req_build => ["libstdc++6", "$libgfortran"],
				dist_req_inst => ["libstdc++6", "$libgfortran", "gfortran"],
				ofa_req_build => ["libibverbs-dev", "librdmacm-dev", "hcoll", "ucx", "knem", "libibmad-dev", "sharp"],
				ofa_req_inst => ["libibverbs1", "hcoll", "ucx", "knem", "libibmad5", "sharp"],
				soft_req => ["hcoll", "knem", "sharp"],
				},
			'opensm' =>
				{
				parent => "opensm",
				dist_req_build => ["bison", "flex"],
				dist_req_inst => ["bison", "flex"],
				ofa_req_build => ["libopensm", "libibumad-dev"],
				ofa_req_inst => ["libopensm", "libibumad3"],
				},
			'opensm-doc' =>
				{
				parent => "opensm",
				dist_req_build => ["bison", "flex"],
				dist_req_inst => ["bison", "flex"],
				ofa_req_build => ["opensm"],
				ofa_req_inst => ["opensm"],
				},
			'libopensm-devel' =>
				{
				parent => "opensm",
				dist_req_build => ["bison", "flex"],
				dist_req_inst => ["bison", "flex"],
				ofa_req_inst => ["opensm", "libopensm"],
				},
			'libopensm' =>
				{
				parent => "opensm",
				dist_req_build => ["bison", "flex"],
				dist_req_inst => ["bison", "flex"],
				ofa_req_build => ["libibumad-dev"],
				ofa_req_inst => ["libibumad3"],
				},
			'perftest' =>
				{
				dist_req_build => ["libpci-dev"],
				ofa_req_build => ["libibverbs-dev", "librdmacm-dev", "libibumad-dev"],
				ofa_req_inst => ["libibverbs1", "librdmacm1", "libibumad3", "ibverbs-providers"],
				},
			'srptools' =>
				{
				parent => "rdma-core",
				ofa_req_build => ["librdmacm-dev", "libibverbs-dev", "libibumad-dev"],
				ofa_req_inst => ["librdmacm1", "libibumad3", "libibverbs1", "rdma-core"],
				},

			'iser' =>
				{
				parent => "iser",
				available => 0,
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				},
			'iser-dkms' =>
				{
				parent => "iser",
				mode => "kernel",
				dist_req_build => ["dkms", "gcc", "make"],
				dist_req_inst => ["dkms", "gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},
			'iser-modules' =>
				{
				parent => "iser",
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},

			'isert' =>
				{
				parent => "isert",
				available => 0,
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				},
			'isert-dkms' =>
				{
				parent => "isert",
				available => 1,
				mode => "kernel",
				dist_req_build => ["dkms", "gcc", "make"],
				dist_req_inst => ["dkms", "gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},
			'isert-modules' =>
				{
				parent => "isert",
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},

			'srp' =>
				{
				parent => "srp",
				available => 0,
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				},
			'srp-dkms' =>
				{
				parent => "srp",
				mode => "kernel",
				dist_req_build => ["dkms", "gcc", "make"],
				dist_req_inst => ["dkms", "gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},
			'srp-modules' =>
				{
				parent => "srp",
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},

			'mlnx-nfsrdma' =>
				{
				parent => "mlnx-nfsrdma",
				available => 0,
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				},
			'mlnx-nfsrdma-dkms' =>
				{
				parent => "mlnx-nfsrdma",
				mode => "kernel",
				dist_req_build => ["dkms", "gcc", "make"],
				dist_req_inst => ["dkms", "gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},
			'mlnx-nfsrdma-modules' =>
				{
				parent => "mlnx-nfsrdma",
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},

			'mlnx-nvme' =>
				{
				parent => "mlnx-nvme",
				available => 0,
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				},
			'mlnx-nvme-dkms' =>
				{
				parent => "mlnx-nvme",
				mode => "kernel",
				dist_req_build => ["dkms", "gcc", "make"],
				dist_req_inst => ["dkms", "gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},
			'mlnx-nvme-modules' =>
				{
				parent => "mlnx-nvme",
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},

			'mlnx-rdma-rxe' =>
				{
				parent => "mlnx-rdma-rxe",
				available => 0,
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				},
			'mlnx-rdma-rxe-dkms' =>
				{
				parent => "mlnx-rdma-rxe",
				mode => "kernel",
				dist_req_build => ["dkms", "gcc", "make"],
				dist_req_inst => ["dkms", "gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},
			'mlnx-rdma-rxe-modules' =>
				{
				parent => "mlnx-rdma-rxe",
				mode => "kernel",
				dist_req_build => ["gcc", "make"],
				dist_req_inst => ["gcc", "make"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts","$mlnX_ofed_kernel","mlnx-ofed-kernel-utils"],
				},

			'nvme-snap' =>
				{
				available => 0,
				ofa_req_build => ["libibverbs-dev", "librdmacm-dev"],
				ofa_req_inst => ["libibverbs1", "librdmacm1", "spdk"],
				},

			'mlxbf-bootctl' =>
				{
				available => 0,
				},

			'ibdump' =>
				{
				dist_req_build => ["libstdc++6"],
				dist_req_inst => ["libstdc++6"],
				ofa_req_build => ["libibverbs-dev", "mstflint"],
				ofa_req_inst => ["libibverbs1", "mstflint"],
				},

			'spdk' =>
				{
				parent=> "spdk",
				available => 0,
				dist_req_build => ["libiscsi-dev", "libaio-dev", "libcunit1-dev", "libncurses-dev"],
				dist_req_inst => ["libiscsi7", "libaio1", "libcunit1", "libncurses5"],
				ofa_req_build => ["libibverbs-dev", "librdmacm-dev"],
				ofa_req_inst => ["libibverbs1", "librdmacm1"],
				},
			'spdk-dev' =>
				{
				parent=> "spdk",
				available => 0,
				dist_req_build => ["libiscsi-dev", "libaio-dev", "libcunit1-dev", "libncurses-dev"],
				dist_req_inst => ["libiscsi7", "libaio1", "libcunit1", "libncurses5"],
				ofa_req_build => ["libibverbs-dev", "librdmacm-dev"],
				ofa_req_inst => ["libibverbs1", "librdmacm1", "spdk"],
				},

			'mlnx-ethtool' =>
				{
				dist_req_build => ["pkg-config", "libmnl-dev"],
				dist_req_inst => ["libmnl0"],
				},

			'mlnx-iproute2' =>
				{
				dist_req_build => ["libelf-dev", "libselinux1-dev", "libdb-dev", "libmnl-dev", "sudo", "bison", "flex"],
				dist_req_inst => ["libelf1", "libselinux1", "libmnl0"],
				},

			# this package is listed here only for uninstall and --without.. flag support
			'mlnx-fw-updater' =>
				{
				},

			'hcoll' =>
				{
				dist_req_build => ["gcc", "libstdc++6", "$libssl_devel"],
				dist_req_inst => ["$libssl"],
				ofa_req_build => ["libibverbs-dev", "librdmacm-dev", "libibmad-dev", "libibumad-dev", "sharp"],
				ofa_req_inst => ["libibverbs1", "librdmacm1", "libibmad5", "sharp"],
				soft_req => ["sharp"],
				},
			'sharp' =>
				{
				dist_req_build => ["gcc", "libstdc++6"],
				ofa_req_build => ["libibverbs-dev", "libibumad-dev", "librdmacm-dev", "libibmad-dev", "ucx"],
				ofa_req_inst => ["libibverbs1", "libibumad3", "librdmacm1", "libibmad5", "ucx"],
				soft_req => ["ucx"],
				},

			'rdma-core' =>
				{
				parent => "rdma-core",
				dist_req_build => [
					"cmake",
					@rdmacore_python,
					$dh_systemd,
					"dh-python",
					"libnl-3-dev", "libnl-route-3-dev",
					@libsystemd_dev,
					"libudev-dev",
					"pandoc",
					"pkg-config",
					"python3-docutils",
					"valgrind"
				],
				dist_req_inst => ["lsb-base", "libnl-3-200", "udev", "$libudev"],
				ofa_req_build => ["$mlnX_ofed_kernel"],
				ofa_req_inst => ["ofed-scripts"],
				},
			'ibverbs-providers' =>
				{
				parent => "rdma-core",
				dist_req_build => ["libnuma-dev"],
				dist_req_inst => ["libnuma1"],
				ofa_req_build => ["rdma-core"],
				ofa_req_inst => ["rdma-core"],
				},
			'libibumad3' =>
				{
				parent => "rdma-core",
				dist_req_build => ["libtool"],
				ofa_req_build => ["rdma-core"],
				ofa_req_inst => ["rdma-core"],
				},
			'libibumad-dev' =>
				{
				parent => "rdma-core",
				dist_req_build => ["libtool"],
				ofa_req_build => ["rdma-core"],
				ofa_req_inst => ["libibumad3", "rdma-core"],
				},
			'rdmacm-utils' =>
				{
				parent => "rdma-core",
				ofa_req_build => ["rdma-core"],
				ofa_req_inst => ["librdmacm1", "rdma-core"],
				},
			'python3-pyverbs' =>
				{
				parent => "rdma-core",
				dist_req_inst => ["python3", "$libpython"],
				ofa_req_build => ["rdma-core"],
				ofa_req_inst => ["rdma-core", "libibverbs1", "librdmacm1", "ibverbs-providers"],
				},
			'mlx-steering-dump' =>
				{
				available => 0,
				dist_req_inst => ["$python2"],
				},

			'neohost-backend' =>
				{ name => "neohost-backend", parent => "neohost-backend",
				selected => 0, installed => 0, rpm_exist => 0, rpm_exist32 => 0,
				available => 0, mode => "user",
				dist_req_build => [],
				dist_req_inst => ["python"],
				ofa_req_build => [], ofa_req_inst => [], configure_options => '' },
			'neohost-sdk' =>
				{ name => "neohost-sdk", parent => "neohost-sdk",
				selected => 0, installed => 0, rpm_exist => 0, rpm_exist32 => 0,
				available => 0, mode => "user", dist_req_build => [],
				dist_req_inst => [], ofa_req_build => [], ofa_req_inst => ["neohost-backend"], configure_options => '' },
			'mlnx-dpdk' =>
				{
				parent => "mlnx-dpdk",
				dist_req_build => [
				],
				dist_req_inst => [
					"hwdata", "lsb-base", "pciutils", "libbsd0", "libelf1",
					"libjansson4", "libnuma1", "libpcap0.8", "zlib1g"
				],
				ofa_req_build => ["libibverbs-dev"],
				ofa_req_inst => ["libibverbs1"],
				},
			'mlnx-dpdk-dev' =>
				{
				parent => "mlnx-dpdk",
				available => 0,
				dist_req_build => [
				],
				dist_req_inst => [
					"libbsd-dev", "libmnl-dev", "libnuma-dev",
					"libpcap-dev", "libssl-dev", "zlib1g-dev"
				],
				ofa_req_build => ["libibverbs-dev"],
				ofa_req_inst => ["libibverbs1", "mlnx-dpdk"],
				},
			'mlnx-dpdk-doc' =>
				{
				parent => "mlnx-dpdk",
				available => 0,
				dist_req_build => ["libcap-dev", "libpcap-dev", "libnuma-dev", "python3", "python3-sphinx"],
				ofa_req_build => ["libibverbs-dev", "librdmacm-dev"],
				ofa_req_inst => ["libibverbs1", "librdmacm1"],
				},
			'ibarr' =>
				{
				dist_req_build => ["libnl-3-dev", "libnl-route-3-dev", "cmake", "pkg-config"],
				dist_req_inst => ["libnl-3-200"],
				ofa_req_build => ["libibverbs-dev", "libibumad-dev"],
				ofa_req_inst => ["libibverbs1", "libibumad3"],
				},
);

foreach my $package (keys %packages_info) {
	for my $key (qw/name parent/) {
		if (not exists $packages_info{$package}{$key}) {
			$packages_info{$package}{$key} = $package;
		}
	}
	for my $key (qw/selected installed deb_exist/) {
		if (not exists $packages_info{$package}{$key}) {
			$packages_info{$package}{$key} = 0;
		}
	}
	if (not exists $packages_info{$package}{'available'}) {
		$packages_info{$package}{'available'} = 1;
	}
	if (not exists $packages_info{$package}{'mode'}) {
		$packages_info{$package}{'mode'} = "user";
	}
	for my $key (qw/dist_req_build dist_req_inst ofa_req_build ofa_req_build/) {
		if (not exists $packages_info{$package}{$key}) {
			$packages_info{$package}{$key} = [];
		}
	}
	if (not exists $packages_info{$package}{'configure_options'}) {
		$packages_info{$package}{'configure_options'} = '';
	}
}


for my $ovsp (@openvswitch_packages) {
	$packages_info{$ovsp}{'name'} = $ovsp;
	$packages_info{$ovsp}{'parent'} = "openvswitch";
	$packages_info{$ovsp}{'selected'} = 0;
	$packages_info{$ovsp}{'installed'} = 0;
	$packages_info{$ovsp}{'deb_exist'} = 0;
	$packages_info{$ovsp}{'available'} = 0;
	$packages_info{$ovsp}{'mode'} = 'user';
	$packages_info{$ovsp}{'dist_req_build'} = [
		"openssl", "libssl-dev", "graphviz", "dh-autoreconf",
		"procps", "python3-all", "libunwind-dev",
		"python-zopeinterface",
		"libunbound-dev", "python3-six",
	];
	$packages_info{$ovsp}{'dist_req_inst'} = [];
	$packages_info{$ovsp}{'ofa_req_build'} = ["mlnx-dpdk-dev"];
	$packages_info{$ovsp}{'ofa_req_inst'} = [];
	$packages_info{$ovsp}{'configure_options'} = '';
}

$packages_info{"libopenvswitch"}{'available'} = 1;
$packages_info{"openvswitch-common"}{'available'} = 1;
$packages_info{"openvswitch-switch"}{'available'} = 1;
$packages_info{"libopenvswitch"}{'ofa_req_inst'} = [];
$packages_info{"libopenvswitch-dev"}{'ofa_req_inst'} = ["libopenvswitch"];
$packages_info{"libopenvswitch-dev"}{'dist_req_inst'} = ["$libssl_devel", "libunbound-dev"];
$packages_info{"openvswitch-common"}{'ofa_req_inst'} = ["libopenvswitch"];
$packages_info{"openvswitch-common"}{'dist_req_inst'} = ["libbsd0", "libnuma1", "$libssl", "libunbound8", "libunwind8"];
$packages_info{"openvswitch-datapath-dkms"}{'dist_req_inst'} = ["dkms", "libelf-dev"];
$packages_info{"openvswitch-datapath-source"}{'dist_req_inst'} = ["module-assistant"];
$packages_info{"openvswitch-ipsec"}{'ofa_req_inst'} = ["openvswitch-common", "openvswitch-switch", "python3-openvswitch"];
$packages_info{"openvswitch-ipsec"}{'dist_req_inst'} = ["python3", "strongswan", "strongswan-swanctl"];
$packages_info{"openvswitch-switch"}{'ofa_req_inst'} = ["openvswitch-common", "libopenvswitch", "libibverbs1", "ibverbs-providers"];
$packages_info{"openvswitch-switch"}{'dist_req_inst'} = ["python3", "netbase", "procps", "uuid-runtime", "libpcap0.8", "libjansson4", "$libipsec_mb", "ifupdown"];
$packages_info{"openvswitch-pki"}{'ofa_req_inst'} = ["openvswitch-common"];
$packages_info{"openvswitch-test"}{'dist_req_inst'} = ["python3-twisted"];
$packages_info{"openvswitch-testcontroller"}{'ofa_req_inst'} = ["openvswitch-common", "openvswitch-pki"];
$packages_info{"openvswitch-vtep"}{'ofa_req_inst'} = ["openvswitch-common", "openvswitch-switch", "python3-openvswitch"];
$packages_info{"python3-openvswitch"}{'dist_req_inst'} = ["python3", "python3-six"];
$packages_info{"openvswitch-dbg"}{'ofa_req_inst'} = ["openvswitch-common", "openvswitch-switch"];

if ($rdmacore_python[0] eq "python") {
	$packages_info{"python3-pyverbs"}{"available"} = 0;
}

$packages_info{"libibverbs-dev"}{'dist_req_inst'} = ['libnl-3-dev', 'libnl-route-3-dev'];
$packages_info{"infiniband-diags"}{'dist_req_build'} = [''];
$packages_info{"infiniband-diags"}{'dist_req_inst'} = [''];

my $components_filter = get_components_filter(0, [@components]);

###############

###############################################################
# functions
###############################################################
sub getch
{
	my $c;
	system("stty -echo raw");
	$c=getc(STDIN);
	system("stty echo -raw");
	# Exit on Ctrl+c or Esc
	if ($c eq "\cC" or $c eq "\e") {
		print "\n";
		exit 1;
	}
	print "$c\n";
	return $c;
}

sub is_installed_deb
{
	my $name = shift @_;

	my $installed_deb = `$DPKG_QUERY -l $name 2> /dev/null | awk '/^[rhi][iU]/{print \$2}'`;
	return ($installed_deb) ? 1 : 0;
}

sub get_all_matching_installed_debs
{
	my $name = shift @_;

	my $installed_debs = `dpkg-query -l "*$name*" 2> /dev/null | awk '/^[rhi][iU]/{print \$2}' | sed -e 's/:.*//g'`;
	return (split "\n", $installed_debs);
}

my %check_uninstall = ();
my %purge_no_deps = ();

# Removes a potential ':<archname>' suffix. e.g.
# 'package:amd64' -> 'package'
sub strip_package_arch($) {
	my $package = shift;
	$package =~ s/:.*//;
	return $package;
}

sub is_immuned($) {
	my $package = shift;
	$package = strip_package_arch($package);
	return exists $purge_no_deps{$package};
}

sub set_immuned($) {
	my $package = shift;
	$package = strip_package_arch($package);
	$purge_no_deps{$package} = 1;
}

sub mark_for_uninstall
{
	my $package = shift @_;

	return if ($is_mlnx_en and $package =~ /mft/);
	return if ($package =~ /^xen|ovsvf-config|opensmtpd/);
	return if (is_immuned($package));

	if (not $selected_for_uninstall{$package}) {
		if (is_installed_deb $package) {
			print_and_log("$package will be removed.\n", $verbose2);
			push (@dependant_packages_to_uninstall, "$package");
			$selected_for_uninstall{$package} = 1;
			if (not (exists $packages_info{$package} or $package =~ /mlnx-ofed-/)) {
				$non_ofed_for_uninstall{$package} = 1;
			}
		}
	}
}

sub get_requires
{
	my $package = shift @_;

	chomp $package;

	if ($check_uninstall{$package}) {
		return; # already checked here
	}
	$check_uninstall{$package} = 1;

	if ($package eq "rdma") {
		# don't remove packages that needs rdma package
		return;
	}

	my @what_requires = `/usr/bin/dpkg --purge --dry-run $package 2>&1 | grep "depends on" 2> /dev/null`;

	for my $pack_req (@what_requires) {
		chomp $pack_req;
		$pack_req =~ s/\s*(.+) depends.*/$1/g;
		$pack_req =~ s/:.*//g;
		if (exists $immune_debs{$pack_req}) {
			print_and_log("get_requires: $package is required by $pack_req, but $pack_req won't be removed.\n", $verbose);
			set_immuned($package);
			$check_uninstall{$pack_req} = 1;
			return;
		}
		print_and_log("get_requires: $package is required by $pack_req\n", $verbose2);
		get_requires($pack_req);
		mark_for_uninstall($pack_req);
	}
}

sub is_configured_deb
{
	my $name = shift @_;

	my $installed_deb = `$DPKG_QUERY -l $name 2> /dev/null | awk '/^rc/{print \$2}'`;
	return ($installed_deb) ? 1 : 0;
}

sub ex
{
	my $cmd = shift @_;
	my $sig;
	my $res;

	print_and_log("Running: $cmd\n", $verbose2);
	system("$cmd >> $glog 2>&1");
	$res = $? >> 8;
	$sig = $? & 127;
	if ($sig or $res) {
		print_and_log_colored("Failed command: $cmd", 1, "RED");
		print_and_log("See $glog", 1);
		exit 1;
	}
}

sub ex_deb_build
{
	my $name = shift @_;
	my $cmd = shift @_;
	my $sig;
	my $res;

	print_and_log("Running $cmd\n", $verbose);
	system("echo $cmd > $ofedlogs/$name.debbuild.log 2>&1");
	system("$cmd >> $ofedlogs/$name.debbuild.log 2>&1");
	$res = $? >> 8;
	$sig = $? & 127;
	if ($sig or $res) {
		print_and_log_colored("Failed to build $name DEB", 1, "RED");
		addSetupInfo ("$ofedlogs/$name.debbuild.log");
		print_and_log_colored("See $ofedlogs/$name.debbuild.log", 1, "RED");
		exit 1;
	}
}

sub ex_deb_install
{
	my $name = shift @_;
	my $cmd = shift @_;
	my $sig;
	my $res;

	if (exists $package_pre_install_script{$name}) {
		print_and_log("Running $name pre install script: $package_pre_install_script{$name}\n", $verbose);
		ex1("$package_pre_install_script{$name}");
	}

	print_and_log("Running $cmd\n", $verbose);
	system("echo $cmd > $ofedlogs/$name.debinstall.log 2>&1");
	system("$cmd >> $ofedlogs/$name.debinstall.log 2>&1");
	$res = $? >> 8;
	$sig = $? & 127;
	if ($sig or $res) {
		print_and_log_colored("Failed to install $name DEB", 1, "RED");
		addSetupInfo ("$ofedlogs/$name.debinstall.log");
		print_and_log_colored("See $ofedlogs/$name.debinstall.log", 1, "RED");
		if ($name =~ /-dkms$/) {
			copy_make_log($name);
		}
		exit 1;
	}

	if (exists $package_post_install_script{$name}) {
		print_and_log("Running $name post install script: $package_post_install_script{$name}\n", $verbose);
		ex1("$package_post_install_script{$name}");
	}
}

sub check_linux_dependencies
{
	my $kernel_dev_missing = 0;
	my %missing_packages = ();

	if (! $check_linux_deps) {
		return 0;
	}

	print_and_log("Checking SW Requirements...\n", (not $quiet));
	foreach my $req_name (@required_debs) {
		my $is_installed_flag = is_installed_deb($req_name);
		if (not $is_installed_flag) {
			print_and_log_colored("$req_name deb is required", $verbose2, "RED");
			$missing_packages{"$req_name"} = 1;
		}
	}

	foreach my $package (@selected_packages) {
		if ($package =~ /kernel|knem|mlnx-en/) {
			# kernel sources are required to install mlnx-ofed-kernel-dkms
			# require only if with_dkms=1
			if ($with_dkms and not -d "$kernel_sources/scripts" and not $user_space_only) {
				print_and_log_colored("$kernel_sources/scripts is required to install $package package.", $verbose2, "RED");
				$missing_packages{"linux-headers-$kernel"} = 1;
				$kernel_dev_missing = 1;
			}
		}

		# Check installation requirements
		for my $req_name ( @{ $packages_info{$package}{'dist_req_inst'} } ) {
			next if not $req_name;
			my $is_installed_flag = is_installed_deb($req_name);
			if (not $is_installed_flag) {
				print_and_log_colored("$req_name deb is required to install $package", $verbose2, "RED");
				$missing_packages{"$req_name"} = 1;
			}
		}
	}

	# display a summary of missing packages
	if (keys %missing_packages) {
		print_and_log_colored("One or more required packages for installing $PACKAGE are missing.", 1, "RED");
		if ($kernel_dev_missing) {
			print_and_log_colored("$kernel_sources/scripts is required for the Installation.", 1, "RED");
		}
		if ($check_deps_only) {
			print_and_log("Run:\napt-get install " . join(' ', (keys %missing_packages)) . "\n", 1);
			exit $PREREQUISIT;
		} else {
			purge_failed_dkms_packages();
			print_and_log_colored("Attempting to install the following missing packages:\n" . join(' ', (keys %missing_packages)), 1, "RED");
			my $cmd = "apt-get install -y $apt_extra_params " . join(' ', (keys %missing_packages));
			print_and_log("Running: apt-get update\n", $verbose2);
			system("apt-get update >> $glog 2>&1");
			ex "$cmd";
		}
	}

	if ($check_deps_only) {
		print_and_log("All required packages are installed, the system is ready for $PACKAGE installation.\n", 1);
		exit 0;
	}
}

sub get_module_list_from_dkmsConf
{
	my $conf = shift;

	my @modules = ();
	open(IN, "$conf") or print_and_log_colored("Error: cannot open file: $conf", 1, "RED");
	while(<IN>) {
		my $mod = $_;
		chomp $mod;
		if ($mod =~ /BUILT_MODULE_NAME/) {
			$mod =~ s/BUILT_MODULE_NAME\[[0-9]*\]=//g;
			$mod =~ s@^ib_@@g;
			if ($mod =~ /eth_ipoib/) {
				$mod =~ s/eth_ipoib/e_ipoib/g;
			}
			push(@modules, $mod);
		}
	}
	close(IN);
	return @modules;
}

sub is_module_in_deb
{
	my $name = shift;
	my $module = shift;

	my $ret = 0;
	my $deb = "";

	if ($name =~ /mlnx-ofed-kernel/) {
		($deb) = glob ("$DEBS/$mlnX_ofed_kernel*.deb");
	} elsif ($name =~ /mlnx-en/) {
		($deb) = glob ("$DEBS/$mlnx_en*.deb");
	} else {
		($deb) = glob ("$DEBS/$name*.deb");
	}

	if ($deb) {
		if ($module =~ /srp|iser|sdp|rds|nfsrdma|mlnx-nvme|mlnx-rdma-rxe/) {
			return 1;
		}
		rmtree "$builddir/$name\_module-check";
		mkpath "$builddir/$name\_module-check";
		ex "$DPKG_DEB -x '$deb' $builddir/$name\_module-check 2>/dev/null";
		if (basename($deb) =~ /dkms/) {
			my $conf = `find $builddir/$name\_module-check -name dkms.conf 2>/dev/null | grep -vE "drivers/|net/"`;
			chomp $conf;
			if (grep( /$module.*$/, get_module_list_from_dkmsConf($conf))) {
				print_and_log("is_module_in_deb: $module is in $deb\n", $verbose2);
				$ret = 1;
			} else {
				print_and_log("is_module_in_deb: $module is NOT in $deb\n", $verbose2);
				$ret = 0;
			}
		} else {
			my $modpath = `find $builddir/$name\_module-check -name "*${module}*.ko" 2>/dev/null`;
			chomp $modpath;
			if ($modpath ne "") {
				print_and_log("is_module_in_deb: $module is in $deb\n", $verbose2);
				$ret = 1;
			} else {
				print_and_log("is_module_in_deb: $module is NOT in $deb\n", $verbose2);
				$ret = 0;
			}
		}
		rmtree "$builddir/$name\_module-check";
	} else {
		print_and_log("deb file was not found for pacakge: $name\n", $verbose2);
	}

	return $ret;
}

#
# print usage message
#
sub usage
{
   print GREEN;
   print "\n";
   print "Usage: $0 [-c <packages config_file>|--all|--hpc|--vma|--xlio|--basic|--bluefield] [OPTIONS]\n";

   print "\n";
   print "Installation control:\n";
   print "    --force              Force installation\n";
   print "    --tmpdir             Change tmp directory. Default: $TMPDIR\n";
   print "    -k|--kernel <version>\n";
   print "                         Default on this system: $kernel (relevant if --without-dkms is given)\n";
   print "    -s|--kernel-sources <path>\n";
   print "                         Default on this system: $kernel_sources (relevant if --without-dkms is given)\n";
   print "    --distro             Set Distro name for the running OS (e.g: ubuntu14.04). Default: Use auto-detection.\n";
   print "    --skip-distro-check  Do not check $PACKAGE vs Distro matching\n";
   print "    --without-depcheck   Run the installation without verifying that all required Distro's packages are installed\n";
   print "    --check-deps-only    Check for missing required Distro's packages and exit\n";
   print "    --print-distro       Print distribution name and exit\n";
   print "\n";
   print "    --add-kernel-support\n";
   print "                         Add kernel support (Run mlnx_add_kernel_support.sh) and install it - implies --without-dkms\n";
   print "    --add-kernel-support-build-only\n";
   print "                         Add kernel support (Run mlnx_add_kernel_support.sh) and exit - implies --without-dkms\n";
   print "\n";
   print "    --kernel-extra-args '<args>'\n";
   print "                         pass <args> to kernel configure script (single paraeter, space separated)\n";
   print "                         - Pass it along with --add-kernel-support\n";
   print "\n";
   print "    --dkms               Install kernel packages with DKMS support\n";
   print "                         - Enabled by default with official $PACKAGE releases\n";
   print "                         - Disabled by default if new $PACKAGE was created with mlnx_add_kernel_support.sh\n";
   print "                         - This flag is ignored if running kernel was not installed from deb package (to override see --force-dkms)\n";
   print "    --force-dkms         Force installing kernel packages with DKMS support\n";
   print "    --without-dkms       Don't install kernel packages with DKMS support\n";
   print "                         - Enabled by default if new $PACKAGE was created with mlnx_add_kernel_support.sh\n";
   print "                         - Enabled by default if running kernel was not installed from deb package (to override see --force-dkms)\n";
   print "\n";
   print "    --umad-dev-rw        Grant non root users read/write permission for umad devices instead of default\n";
   print "    --umad-dev-na        Prevent from non root users read/write access for umad devices. Overrides '--umad-dev-rw'\n";
   print "    --enable-mlnx_tune   Enable Running the mlnx_tune utility\n";
   print "    --enable-affinity    Run mlnx_affinity script upon boot\n";
   print "    --disable-affinity   Disable mlnx_affinity script (Default)\n";
   print "    --skip-unsupported-devices-check\n";
   print "                         Don't abort if system has an older, unsupported card\n";
if (not ($install_option eq 'eth-only' or $is_mlnx_en)) {
   print "    --enable-opensm      Run opensm upon boot\n";
}
   print "\n";
   print "    --package-install-options\n";
   print "                         DPKG install options to use when installing DEB packages (comma separated list)\n";
   print "    --pre-install-<package> <path to script>\n";
   print "                         Run given script before given package's install\n";
   print "    --post-install-<package> <path to script>\n";
   print "                         Run given script after given package's install\n";
   print "\n";
   print "Firmware update control:\n";
   print "    --without-fw-update  Skip firmware update\n";
   print "    --fw-update-only     Update firmware. Skip driver installation\n";
   print "    --force-fw-update    Force firmware update\n";
   print "    --fw-image-dir       Firmware images directory to use instead of default package content\n";
   print "\n";
   print "Package selection:\n";
   print "    -c|--config <packages config_file>\n";
   print "                         Example of the config file can be found under docs (ofed.conf-example)\n";
if (not ($install_option eq 'eth-only' or $is_mlnx_en)) {
   print "    --all                Install all available packages\n";
   print "    --bluefield          Install BlueField packages\n";
   print "    --hpc                Install minimum packages required for HPC\n";
   print "    --basic              Install minimum packages for basic functionality\n";
} else {
   print "    --eth-only           Install Ethernet drivers only (Default option)\n";
}
   print "    --dpdk               Install minimum packages required for DPDK\n";
   print "    --ovs-dpdk           Install DPDK and OVS packages\n";
   print "    --vma                Install minimum packages required for VMA\n";
   print "    --xlio                Install minimum packages required for XLIO\n";
if (not ($install_option eq 'eth-only' or $is_mlnx_en)) {
   print "    --guest              Install minimum packages required by guest OS\n";
   print "    --hypervisor         Install minimum packages required by hypervisor OS\n";
   print "    --with-nvmf          Enable NVMEoF support\n";
   print "    --with-nfsrdma       Enable NFSoRDMA support\n";
   print "    --without-nfsrdma    Disable NFSoRDMA support (Default)\n";
}
   print("\n");
   print "Extra package filtering:\n";
if (not ($install_option eq 'eth-only' or $is_mlnx_en)) {
   print "    --kernel-only        Install kernel space packages only\n";
   print "    --user-space-only    Filter selected packages and install only User Space packages\n";
}
   print "    --without-<package>  Do not install package\n";
   print "    --with-<package>     Force installing package\n";
   print "\n";
   print "Miscellaneous:\n";
   print "    -h|--help            Display this help message and exit\n";
   print "    --post-start-delay <sec>\n";
   print "                         Set openibd POST_START_DELAY parameter in seconds. (Default 0)\n";
   print "    -p|--print-available Print available packages for current platform\n";
if (not ($install_option eq 'eth-only' or $is_mlnx_en)) {
   print "    --copy-ifnames-udev  Copy compatibility udev rules for interface names\n";
}
   print "                         And create corresponding ofed.conf file\n";
   print "\n";
   print "Output control:\n";
   print "    -v|-vv|-vvv          Set verbosity level\n";
   print "    -q                   Set quiet - no messages will be printed\n";
   print RESET "\n\n";
}

sub is_less_then
{
        my $a = shift @_;
        my $b = shift @_;

        my @a = (split('\.', $a));
        my @b = (split('\.', $b));

        if ($a[0] < $b[0]
            or ($a[0] == $b[0] and $a[1] < $b[1])
            or ($a[0] == $b[0] and $a[1] == $b[1] and $a[2] < $b[2])) {
                return 1;
        }
        return 0;
}

sub count_ports
{
	my $cnt = 0;
	open(LSPCI, "/usr/bin/lspci -n|");

	while (<LSPCI>) {
		if (/15b3:6282/) {
			$cnt += 2;  # infinihost iii ex mode
		}
		elsif (/15b3:5e8c|15b3:6274/) {
			$cnt ++;    # infinihost iii lx mode
		}
		elsif (/15b3:5a44|15b3:6278/) {
			$cnt += 2;  # infinihost mode
		}
		elsif (/15b3:6340|15b3:634a|15b3:6354|15b3:6732|15b3:673c|15b3:6746|15b3:6750|15b3:1003/) {
			$cnt += 2;  # connectx
		}
	}
	close (LSPCI);

	return $cnt;
}

# removes the settings for a given interface from /etc/network/interfaces
sub remove_interface_settings
{
	my $interface = shift @_;

	open(IFCONF, $ifconf) or die "Can't open $ifconf: $!";
	my @ifconf_lines;
	while (<IFCONF>) {
		push @ifconf_lines, $_;
	}
	close(IFCONF);

	open(IFCONF, ">$ifconf") or die "Can't open $ifconf: $!";
	my $remove = 0;
	foreach my $line (@ifconf_lines) {
		chomp $line;
		if ($line =~ /(iface|mapping|auto|allow-|source) $interface/) {
			$remove = 1;
		}
		if ($remove and $line =~ /(iface|mapping|auto|allow-|source)/ and $line !~ /$interface/) {
			$remove = 0;
		}
		next if ($remove);
		print IFCONF "$line\n";
	}
	close(IFCONF);
}

sub is_carrier
{
	my $ifcheck = shift @_;
	open(IFSTATUS, "ip link show dev $ifcheck |");
	while ( <IFSTATUS> ) {
		next unless m@(\s$ifcheck).*@;
		if( m/NO-CARRIER/ or not m/UP/ ) {
			close(IFSTATUS);
			return 0;
		}
	}
	close(IFSTATUS);
	return 1;
}

sub config_interface
{
	my $interface = shift @_;
	my $ans;
	my $dev = "ib$interface";
	my $ret;
	my $ip;
	my $nm;
	my $nw;
	my $bc;
	my $onboot = 1;
	my $found_eth_up = 0;
	my $eth_dev;

	if (not $config_net_given) {
		return;
	}
	print "Going to update $dev in $ifconf\n" if ($verbose2);
	if ($ifcfg{$dev}{'LAN_INTERFACE'}) {
		$eth_dev = $ifcfg{$dev}{'LAN_INTERFACE'};
		if (not -e "/sys/class/net/$eth_dev") {
			print "Device $eth_dev is not present\n" if (not $quiet);
			return;
		}
		if ( is_carrier ($eth_dev) ) {
			$found_eth_up = 1;
		}
	}
	else {
		# Take the first existing Eth interface
		my @eth_devs = </sys/class/net/eth*>;
		for my $tmp_dev ( @eth_devs ) {
			$eth_dev = $tmp_dev;
			$eth_dev =~ s@/sys/class/net/@@g;
			if ( is_carrier ($eth_dev) ) {
				$found_eth_up = 1;
				last;
			}
		}
	}

	if ($found_eth_up) {
		get_net_config($eth_dev, \%ifcfg, '');
	}

	if (not $ifcfg{$dev}{'IPADDR'}) {
		print "IP address is not defined for $dev\n" if ($verbose2);
		print "Skipping $dev configuration...\n" if ($verbose2);
		return;
	}
	if (not $ifcfg{$dev}{'NETMASK'}) {
		print "Netmask is not defined for $dev\n" if ($verbose2);
		print "Skipping $dev configuration...\n" if ($verbose2);
		return;
	}
	if (not $ifcfg{$dev}{'NETWORK'}) {
		print "Network is not defined for $dev\n" if ($verbose2);
		print "Skipping $dev configuration...\n" if ($verbose2);
		return;
	}
	if (not $ifcfg{$dev}{'BROADCAST'}) {
		print "Broadcast address is not defined for $dev\n" if ($verbose2);
		print "Skipping $dev configuration...\n" if ($verbose2);
		return;
	}

	my @ipib = (split('\.', $ifcfg{$dev}{'IPADDR'}));
	my @nmib = (split('\.', $ifcfg{$dev}{'NETMASK'}));
	my @nwib = (split('\.', $ifcfg{$dev}{'NETWORK'}));
	my @bcib = (split('\.', $ifcfg{$dev}{'BROADCAST'}));

	my @ipeth = (split('\.', $ifcfg{$eth_dev}{'IPADDR'}));
	my @nmeth = (split('\.', $ifcfg{$eth_dev}{'NETMASK'}));
	my @nweth = (split('\.', $ifcfg{$eth_dev}{'NETWORK'}));
	my @bceth = (split('\.', $ifcfg{$eth_dev}{'BROADCAST'}));

	for (my $i = 0; $i < 4 ; $i ++) {
		if ($ipib[$i] =~ m/\*/) {
			if ($ipeth[$i] =~ m/(\d\d?\d?)/) {
				$ipib[$i] = $ipeth[$i];
			}
			else {
				print "Cannot determine the IP address of the $dev interface\n" if (not $quiet);
				return;
			}
		}
		if ($nmib[$i] =~ m/\*/) {
			if ($nmeth[$i] =~ m/(\d\d?\d?)/) {
				$nmib[$i] = $nmeth[$i];
			}
			else {
				print "Cannot determine the netmask of the $dev interface\n" if (not $quiet);
				return;
			}
		}
		if ($bcib[$i] =~ m/\*/) {
			if ($bceth[$i] =~ m/(\d\d?\d?)/) {
				$bcib[$i] = $bceth[$i];
			}
			else {
				print "Cannot determine the broadcast address of the $dev interface\n" if (not $quiet);
				return;
			}
		}
		if ($nwib[$i] !~ m/(\d\d?\d?)/) {
			$nwib[$i] = $nweth[$i];
		}
	}

	$ip = "$ipib[0].$ipib[1].$ipib[2].$ipib[3]";
	$nm = "$nmib[0].$nmib[1].$nmib[2].$nmib[3]";
	$nw = "$nwib[0].$nwib[1].$nwib[2].$nwib[3]";
	$bc = "$bcib[0].$bcib[1].$bcib[2].$bcib[3]";

	print GREEN "IPoIB configuration for $dev\n";
	if ($onboot) {
		print "auto $dev\n";
	}
	print "iface $dev inet static\n";
	print "address $ip\n";
	print "netmask $nm\n";
	print "network $nw\n";
	print "broadcast $bc\n";
	print RESET "\n";

	# Remove old interface's settings
	remove_interface_settings($dev);

	# append the new interface's settings to the interfaces file
	open(IF, ">>$ifconf") or die "Can't open $ifconf: $!";
	print IF "\n";
	if ($onboot) {
		print IF "auto $dev\n";
	}
	print IF "iface $dev inet static\n";
	print IF "\taddress $ip\n";
	print IF "\tnetmask $nm\n";
	print IF "\tnetwork $nw\n";
	print IF "\tbroadcast $bc\n";
	close(IF);
}

sub ipoib_config
{
	if (not $config_net_given) {
		return;
	}

	my $ports_num = count_ports();
	for (my $i = 0; $i < $ports_num; $i++ ) {
		config_interface($i);
	}
}

sub is_tarball_available
{
	my $name = shift;

	for my $ver (keys %{$main_packages{$name}}) {
		if ($main_packages{$name}{$ver}{'tarballpath'}) {
			return 1;
		}
	}

	return 0;
}

sub is_deb_available
{
	my $name = shift;
	for my $ver (keys %{$main_packages{$name}}) {
		if ($main_packages{$name}{$ver}{'debpath'}) {
			return 1;
		}
	}

	return 0;
}

sub add_packages($$@) {
	my $fh = shift;
	my $cnt = shift;
	for my $package (@_) {
		next if (grep /^$package$/, @selected_by_user);
		next if (not $packages_info{$package}{'available'});
		next if (not is_deb_available($package));
		push (@selected_by_user, $package);
		print $fh "$package=y\n";
		$cnt ++;
	}
	return $cnt;
}

sub get_uninstall_env_str() {
    my $components_str = 'MLNX_OFED_COMPONENTS="'. join(" ", @components) . '"';
    return "$components_str";
}

# select packages to install
sub select_packages
{
	my $cnt = 0;
	if ($config_given) {
		open(CONFIG, "$config") || die "Can't open $config: $!";;
		while(<CONFIG>) {
			next if (m@^\s+$|^#.*@);
			my ($package,$selected) = (split '=', $_);
			chomp $package;
			chomp $selected;

			# fix kernel packages names
			# DKMS enabled
			if ($with_dkms) {
				if ($package =~ /-modules/) {
					$package =~ s/-modules/-dkms/g;;
				}
			} else {
			# DKMS disabled
				if ($package =~ /-dkms/) {
					$package =~ s/-dkms/-modules/g;;
				}
			}

			print_and_log("$package=$selected\n", $verbose2);

#			if (not $packages_info{$package}{'parent'}) {
#				my $modules = "@kernel_modules";
#				chomp $modules;
#				$modules =~ s/ /|/g;
#				if ($package =~ m/$modules/) {
#					if ( $selected eq 'y' ) {
#						if (not $kernel_modules_info{$package}{'available'}) {
#							print "$package is not available on this platform\n" if (not $quiet);
#						}
#						else {
#							push (@selected_modules_by_user, $package);
#						}
#						next;
#					}
#				}
#				else {
#					print "Unsupported package: $package\n" if (not $quiet);
#					next;
#				}
#			}

			if (not $packages_info{$package}{'available'} and $selected eq 'y') {
				print_and_log("$package is not available on this platform\n", (not $quiet));
				next;
			}

			if ( $selected eq 'y' ) {
				my $parent = $packages_info{$package}{'parent'};
				if (not is_deb_available($package)) {
					print_and_log("Unsupported package: $package\n", (not $quiet));
					next;
				}
				push (@selected_by_user, $package);
				print_and_log("select_package: selected $package\n", ($verbose2));
				$cnt ++;
			}
		}
	}
	else {
		open(CONFIG, ">$config") || die "Can't open $config: $!";
		flock CONFIG, $LOCK_EXCLUSIVE;
		if ($install_option eq 'all') {
			for my $package ( @all_packages ) {
				next if (not $packages_info{$package}{'available'});
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
#			for my $module ( @kernel_modules ) {
#				next if (not $kernel_modules_info{$module}{'available'});
#				push (@selected_modules_by_user, $module);
#				print CONFIG "$module=y\n";
#			}
		}
		elsif ($install_option eq 'bluefield') {
			for my $package ( @bluefield_packages ) {
				next if (not $packages_info{$package}{'available'});
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
			for my $module ( @bluefield_kernel_modules ) {
				next if (not $kernel_modules_info{$module}{'available'});
				push (@selected_modules_by_user, $module);
				print CONFIG "$module=y\n";
			}
		}
		elsif ($install_option eq 'hpc') {
			for my $package ( @hpc_packages ) {
				next if (not $packages_info{$package}{'available'});
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
#			for my $module ( @hpc_kernel_modules ) {
#				next if (not $kernel_modules_info{$module}{'available'});
#				push (@selected_modules_by_user, $module);
#				print CONFIG "$module=y\n";
#			}
		}
		elsif ($install_option =~ m/vma/) {
			my @list = ();
			if ($install_option eq 'vma') {
				@list = (@vma_packages);
			} elsif ($install_option eq 'vmavpi') {
				@list = (@vmavpi_packages);
			} elsif ($install_option eq 'vmaeth') {
				@list = (@vmaeth_packages);
			}
			for my $package ( @list ) {
				next if (not $packages_info{$package}{'available'});
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
#			for my $module ( @vma_kernel_modules ) {
#				next if (not $kernel_modules_info{$module}{'available'});
#				push (@selected_modules_by_user, $module);
#				print CONFIG "$module=y\n";
#			}
		}
		elsif ($install_option eq 'xlio') {
			for my $package (@xlio_packages) {
				next if (not $packages_info{$package}{'available'});
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
		}
		elsif ($install_option eq 'basic') {
			for my $package (@basic_packages) {
				next if (not $packages_info{$package}{'available'});
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
#			for my $module ( @basic_kernel_modules ) {
#				next if (not $kernel_modules_info{$module}{'available'});
#				push (@selected_modules_by_user, $module);
#				print CONFIG "$module=y\n";
#			}
		}
		elsif ($install_option eq 'hypervisor') {
			for my $package ( @hypervisor_packages ) {
				next if (not $packages_info{$package}{'available'});
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
#			for my $module ( @hypervisor_kernel_modules ) {
#				next if (not $kernel_modules_info{$module}{'available'});
#				push (@selected_modules_by_user, $module);
#				print CONFIG "$module=y\n";
#			}
		}
		elsif ($install_option eq 'guest') {
			for my $package ( @guest_packages ) {
				next if (not $packages_info{$package}{'available'});
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
#			for my $module ( @guest_kernel_modules ) {
#				next if (not $kernel_modules_info{$module}{'available'});
#				push (@selected_modules_by_user, $module);
#				print CONFIG "$module=y\n";
#			}
		}
		elsif ($install_option eq 'msm') {
			for my $package ( @msm_packages ) {
			next if (not $packages_info{$package}{'available'});
			next if (not is_deb_available($package));
			push (@selected_by_user, $package);
			print CONFIG "$package=y\n";
			$cnt ++;
			}
		}
		elsif ($install_option eq 'kernel-only') {
			for my $package ( @all_packages ) {
				next if (not $packages_info{$package}{'available'});
				next if (not $packages_info{$package}{'mode'} eq 'kernel');
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
		}
		elsif ($install_option eq 'eth-only') {
			for my $package (@eth_packages) {
				next if (not $packages_info{$package}{'available'});
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
		}
		elsif ($install_option =~ m/dpdk/) {
			for my $package ( @dpdk_packages ) {
				next if (not $packages_info{$package}{'available'});
				my $parent = $packages_info{$package}{'parent'};
				next if (not is_deb_available($package));
				push (@selected_by_user, $package);
				print CONFIG "$package=y\n";
				$cnt ++;
			}
		}
		else {
			print_and_log_colored("\nUnsupported installation option: $install_option", (not $quiet), "RED");
			exit 1;
		}
	}

	if ($with_bluefield and $install_option ne 'bluefield') {
		$cnt = add_packages(*CONFIG, $cnt, @bluefield_packages);
	}

	if ($with_ovs_dpdk) {
		$cnt = add_packages(*CONFIG, $cnt, @mlnx_dpdk_packages, @openvswitch_packages);
	}

	if ($with_openvswitch) {
		$cnt = add_packages(*CONFIG, $cnt, @openvswitch_packages);
	}


	flock CONFIG, $UNLOCK;
	close(CONFIG);

	return $cnt;
}

#
# install selected packages by the user (@selected_packages)
#
sub install_selected
{
	print_and_log("Installing new packages\n", (not $quiet));
	my $i = 0;

	chdir $CWD;
	foreach my $name (@selected_packages) {
	   for my $version (keys %{$main_packages{$name}}) {
		delete $ENV{"DEB_CONFIGURE_EXTRA_FLAGS"};
		delete $ENV{"configure_options"};
		delete $ENV{"PACKAGE_VERSION"};
		delete $ENV{"MPI_HOME"};
		delete $ENV{"KNEM_PATH"};
		delete $ENV{"DESTDIR"};
		delete $ENV{"libpath"};
		delete $ENV{"rdmascript"};
		delete $ENV{"CONFIG_ARGS"};
		delete $ENV{"WITH_DKMS"};
		delete $ENV{"kernelver"};
		delete $ENV{"kernel_source_dir"};
		delete $ENV{"KVER"};
		delete $ENV{"K_BUILD"};

		my $parent = $packages_info{$name}{'parent'};
		my $deb_name = $packages_info{$name}{'name'};
		my @debs = ();
		@debs = glob ("$DEBS/${deb_name}[-_]${version}*.deb");
		if ($name =~ /dapl/ or (not @debs and $name =~ /ucx|openmpi|mpitests/)) {
			# TODO: this is neeeded only because of the bad version number in changelog
			@debs = glob ("$DEBS/${deb_name}[-_]*.deb");
		} elsif ($parent =~ /mlnx-ofed-kernel/) {
			if ($with_dkms) {
				@debs = glob ("$DEBS/${deb_name}[-_]${version}*OFED*.deb");
			} else {
				@debs = glob ("$DEBS/${deb_name}[-_]${version}-*.kver.${kernel}_*.deb");
				if (not @debs) {
					@debs = glob ("$DEBS/${deb_name}[-_]${version}-${kernel}_*.deb");
				}
				if (not @debs and $user_space_only) {
					# running user space only with non-dkms mode on a kernel that
					# we don't have bins for. so just take the dkms utils package
					@debs = glob ("$DEBS/${deb_name}[-_]${version}*OFED*.deb");
				}
			}
		} elsif (not $with_dkms and $parent =~ /iser|srp$|knem|kernel-mft|mlnx-en|mlnx-nfsrdma|mlnx-nvme|mlnx-rdma-rxe/) {
			@debs = glob ("$DEBS/${deb_name}[-_]${version}-*.kver.${kernel}_*.deb");
			if (not @debs) {
				@debs = glob ("$DEBS/${deb_name}[-_]${version}-${kernel}_*.deb");
			}
		}

		if (not @debs) {
			# this script does not support building debs!
			print_and_log_colored("Error: DEB for $name was not created !", 1, "RED");
			exit 1;
		}

		print_and_log("Installing ${name}-${version}...\n", (not $quiet));
		if ($parent =~ /spdk/) {
			# spdk depends on libiscsi7 which depends on librdmacm1 and
			# therefore will be removed by the uninstall procedure.
			# So, reinstall SPDK dependencies here.
			my $cmd = "apt-get install -y $apt_extra_params " . join(' ', (@{ $packages_info{$parent}{'dist_req_inst'} }));
			ex "$cmd";
		}
		my $deb_names = join " ", map {"'$_'"} @debs;
		if ($parent =~ /mlnx-ofed-kernel|libvma/) {
			$ENV{"PACKAGE_VERSION"} = "$version";
			ex_deb_install($name, "$DPKG -i --force-confnew $DPKG_FLAGS $deb_names");
		} else {
			ex_deb_install($name, "$DPKG -i $DPKG_FLAGS $deb_names");
		}

		# verify that kernel packages were successfuly installed
		if ($kernel_packages{"$name"}) {
			system("/sbin/depmod $kernel >/dev/null 2>&1");
			for my $object (@{$kernel_packages{"$name"}{"ko"}}) {
				my $file = `$MODINFO -k $kernel $object 2> /dev/null | grep filename | cut -d ":" -f 2 | sed -s 's/\\s//g'`;
				chomp $file;
				my $origin;
				if (-f $file) {
					$origin = `$DPKG -S '$file' 2> /dev/null | cut -d ":" -f 1`;
					chomp $origin;
				}
				if (not $file or $origin =~ /$kernel_escaped/) {
					print_and_log_colored("\nError: $name installation failed!", 1, "RED");
					if ($file) {
						print_and_log("Problem: $object: module file: $file, from package: $origin.\n", 1);
					} else {
						print_and_log("Problem: $object: module file not found.\n", 1);
					}
					addSetupInfo ("$ofedlogs/$name.debinstall.log");
					print_and_log_colored("See:\n\t$ofedlogs/$name.debinstall.log", 1, "RED");
					copy_make_log($name);
					my $ofed_uninstall = `which ofed_uninstall.sh 2>/dev/null`;
					chomp $ofed_uninstall;
					if (-f "$ofed_uninstall") {
						print_and_log_colored("Removing newly installed packages...\n", 1, "RED");
						my $uninstall_flags = "";
						if (`$ofed_uninstall --help 2>/dev/null | grep -- keep-mft 2>/dev/null` ne "") {
							$uninstall_flags .= " --keep-mft";
						}
						my $env_str = get_uninstall_env_str();
						ex "$env_str $ofed_uninstall --force $uninstall_flags";
					}
					exit 1;
				}
			}
		}
	    }
	}
}

sub get_tarball_name_version
{
	my $tarname = shift @_;
	$tarname =~ s@.*/@@g;
	my $name = $tarname;
	$name =~ s/_.*//;
	my $version = $tarname;
	$version =~ s/${name}_//;
	$version =~ s/(.orig).*//;

	return ($name, $version);
}

sub get_deb_name_version
{
	my $debname = shift @_;
	$debname =~ s@.*/@@g;
	my $name = $debname;
	$name =~ s/_.*//;
	my $version = $debname;
	$version =~ s/${name}_//;
	$version =~ s/_.*//;
	$version =~ s/-.*//;# remove release if available

	return ($name, $version);
}

sub set_existing_debs
{
	for my $deb (glob "$DEBS/*.deb") {
		my ($deb_name, $ver) = get_deb_name_version($deb);
		# skip unrelevnt debs
		if ($deb_name =~ /-modules/ and $deb !~ /-${kernel_escaped}_|\.kver\.${kernel_escaped}_/) {
			next;
		}

		set_cfg ("$deb");
		$packages_info{$deb_name}{$ver}{'deb_exist'} = 1;
		print_and_log("set_existing_debs: $deb_name $ver DEB exist\n", $verbose2);
	}
}

sub set_cfg
{
	my $deb_full_path = shift @_;

	my ($name, $version) = get_deb_name_version($deb_full_path);

	$main_packages{$name}{$version}{'name'} = $name;
	$main_packages{$name}{$version}{'version'} = $version;
	$main_packages{$name}{$version}{'debpath'} = $deb_full_path;

	print_and_log("set_cfg: " .
	"name: $name, " .
	"version: $main_packages{$name}{$version}{'version'}, " .
	"debpath: $main_packages{$name}{$version}{'debpath'}\n", $verbose3);
}

# return 0 if pacakge not selected
# return 1 if pacakge selected
sub select_dependent
{
	my $package = shift @_;

	if ($user_space_only and ($packages_info{$package}{'mode'} eq 'kernel')) {
		print_and_log("select_dependent: in user-space-only mode, skipping kernel package: $package\n", $verbose2);
		return 0;
	}

	my $scanned = 0;
	for my $ver (keys %{$main_packages{$package}}) {
		$scanned = 1;

		# prevent loop
		if (not exists $packages_info{$package}{'entered_select_dependent'}) {
			$packages_info{$package}{'entered_select_dependent'}  = 1;
		} else {
			return 0 if (not $packages_info{$package}{'available'});
			return 1;
		}

		if ( not $packages_info{$package}{$ver}{'deb_exist'} ) {
			for my $req ( @{ $packages_info{$package}{'ofa_req_build'} } ) {
				next if not $req;
				print_and_log("resolve_dependencies: $package requires $req for deb build\n", $verbose2);
				my $req_selected = 0;
				if ($packages_info{$req}{'available'}) {
					if (not $packages_info{$req}{'selected'}) {
						$req_selected = select_dependent($req);
					} else {
						$req_selected = 1;
					}
				}
				# Check if this is a strict requirment
				if (not $req_selected and not grep( /^$req$/, @{ $packages_info{$package}{'soft_req'} } )) {
					print_and_log("select_dependent: $req requiement not satisfied for $package, skipping it\n", $verbose2);
					$packages_info{$package}{'available'} = 0;
					return 0;
				}
			}
		}

		for my $req ( @{ $packages_info{$package}{'ofa_req_inst'} } ) {
			next if not $req;
			print_and_log("resolve_dependencies: $package requires $req for deb install\n", $verbose2);
			my $req_selected = 0;
			if ($packages_info{$req}{'available'}) {
				if (not $packages_info{$req}{'selected'}) {
					$req_selected = select_dependent($req);
				} else {
					$req_selected = 1;
				}
			}
			if (not $req_selected and not grep( /^$req$/, @{ $packages_info{$package}{'soft_req'} } )) {
				print_and_log("select_dependent: $req requiement not satisfied for $package, skipping it\n", $verbose2);
				$packages_info{$package}{'available'} = 0;
				return 0;
			}
		}

		if (not $packages_info{$package}{'selected'}) {
			return 0 if (not $packages_info{$package}{'available'});
			$packages_info{$package}{'selected'} = 1;
			push (@selected_packages, $package);
			print_and_log("select_dependent: Selected package $package\n", $verbose2);
			return 1;
		}
	}
	if ($scanned eq "0") {
		print_and_log("resolve_dependencies: $package does not exist. Skip dependencies check\n", $verbose2);
	}
	# if we get here, then nothing got selected.
	return 0;
}

sub select_dependent_module
{
	my $module = shift @_;

	# prevent loop
	if (not exists $kernel_modules_info{$module}{'entered_select_dependent_module'}) {
		$kernel_modules_info{$module}{'entered_select_dependent_module'}  = 1;
	} else {
		return;
	}

	for my $req ( @{ $kernel_modules_info{$module}{'requires'} } ) {
		print_and_log("select_dependent_module: $module requires $req for deb build\n", $verbose2);
		if (not $kernel_modules_info{$req}{'selected'}) {
			select_dependent_module($req);
		}
	}
	if (not $kernel_modules_info{$module}{'selected'}) {
		$kernel_modules_info{$module}{'selected'} = 1;
		push (@selected_kernel_modules, $module);
		print_and_log("select_dependent_module: Selected module $module\n", $verbose2);
	}
}

sub resolve_dependencies
{
	for my $package ( @selected_by_user ) {
		# Get the list of dependencies
		select_dependent($package);
	}

	for my $module ( @selected_modules_by_user ) {
		select_dependent_module($module);
	}

	my $kernel_rpm = "$mlnX_ofed_kernel";
	my $pname = $packages_info{$kernel_rpm}{'parent'};
	for my $ver (keys %{$main_packages{$pname}}) {
		if ($packages_info{$kernel_rpm}{$ver}{'deb_exist'}) {
			for my $module (@selected_kernel_modules) {
				if (not is_module_in_deb($kernel_rpm, "$module")) {
					$packages_info{$kernel_rpm}{$ver}{'deb_exist'} = 0;
					$packages_info{'mlnx-ofed-kernel'}{$ver}{'deb_exist'} = 0;
					last;
				}
			}
		}
	}
}

# Enable/disable mlnx_affinity upon boot
sub set_mlnx_affinity
{
    if ( -e "/etc/infiniband/openib.conf") {
        my @lines;
        open(FD, "/etc/infiniband/openib.conf");
        while (<FD>) {
            push @lines, $_;
        }
        close (FD);

        open(FD, ">/etc/infiniband/openib.conf");
        foreach my $line (@lines) {
            chomp $line;
            if ($line =~ m/(^RUN_AFFINITY_TUNER=).*/) {
                if ($enable_affinity) {
                    print FD "${1}yes\n";
                } else {
                    print FD "${1}no\n";
                }
            } else {
                    print FD "$line\n";
            }
        }
        close (FD);
    }
}

# Set POST_START_DELAY
sub set_post_start_delay
{
    my $set_delay = 0;
    if ( -e "/etc/infiniband/openib.conf") {
        my @lines;
        open(FD, "/etc/infiniband/openib.conf");
        while (<FD>) {
            push @lines, $_;
        }
        close (FD);

        open(FD, ">/etc/infiniband/openib.conf");
        foreach my $line (@lines) {
            chomp $line;
            if ($line =~ m/(^POST_START_DELAY=).*/) {
                print FD "${1}$post_start_delay\n";
                $set_delay ++;
            } else {
                print FD "$line\n";
            }
        }
        if (not $set_delay) {
            print FD "\n# Seconds to sleep after openibd start finished and before releasing the shell\n";
            print FD "POST_START_DELAY=$post_start_delay\n";
        }
        close (FD);
    }
}

sub set_mlnx_tune
{
	# Enable/disable mlnx_tune
	if ( -e "/etc/infiniband/openib.conf") {
		my @lines;
		open(FD, "/etc/infiniband/openib.conf");
		while (<FD>) {
			push @lines, $_;
		}
		close (FD);

		open(FD, ">/etc/infiniband/openib.conf");
		foreach my $line (@lines) {
			chomp $line;
			if ($line =~ m/(^RUN_MLNX_TUNE=).*/) {
				if ($enable_mlnx_tune) {
					print FD "${1}yes\n";
				} else {
					print FD "${1}no\n";
				}
			} else {
					print FD "$line\n";
			}
		}
		close (FD);
	}
}

#
# set opensm service
#
sub set_opensm_service
{
	if ($enable_opensm or $install_option eq 'msm') {
		# Switch on opensmd service
		if (-e "/sbin/chkconfig") {
			system("/sbin/chkconfig --add opensmd > /dev/null 2>&1");
			system("/sbin/chkconfig --set opensmd on > /dev/null 2>&1");
			system("/sbin/chkconfig --level 345 opensmd on > /dev/null 2>&1");
		} elsif (-e "/usr/sbin/update-rc.d") {
			system("/usr/sbin/update-rc.d opensmd defaults > /dev/null 2>&1");
		} else {
			system("/usr/lib/lsb/install_initd /etc/init.d/opensmd > /dev/null 2>&1");
		}
	} else {
		# Switch off opensmd service
		if (-e "/sbin/chkconfig") {
			system("/sbin/chkconfig --del opensmd > /dev/null 2>&1");
			system("/sbin/chkconfig --set opensmd off > /dev/null 2>&1");
			system("/sbin/chkconfig opensmd off > /dev/null 2>&1");
		} elsif (-e "/usr/sbin/update-rc.d") {
			system("/usr/sbin/update-rc.d -f opensmd remove > /dev/null 2>&1");
		} else {
			system("/usr/lib/lsb/remove_initd /etc/init.d/opensmd > /dev/null 2>&1");
		}
	}
}

#
# remove old packages
#
sub remove_old_packages
{
	print_and_log("Removing old packages...\n", (not $quiet));

	if ($install_option eq 'eth-only') {
		$mlnx_en_pkgs = $mlnx_en_only_pkgs;
	} else {
		$mlnx_en_pkgs = $mlnx_en_rdma_pkgs;
	}

	my $ofed_uninstall = `which ofed_uninstall.sh 2> /dev/null`;
	chomp $ofed_uninstall;
	if (-f "$ofed_uninstall") {
		print_and_log("Uninstalling the previous version of $PACKAGE\n", (not $quiet));
		my $uninstall_flags = "";
		if ($force) {
			$uninstall_flags .= " --force"
		}
		if (`$ofed_uninstall --help 2>/dev/null | grep -- keep-mft 2>/dev/null` ne "") {
			$uninstall_flags .= " --keep-mft";
		}

		# W/A for bad releases
		if (is_installed_deb("neohost-backend") and $components_filter->("neohost-backend")) {
			system("apt-get remove -y neohost-backend neohost-sdk >> $ofedlogs/ofed_uninstall.log 2>&1");
		}
		if (is_installed_deb("infiniband-diags") and $components_filter->("infiniband-diags")) {
			system("apt-get remove -y infiniband-diags >> $ofedlogs/ofed_uninstall.log 2>&1");
		}

		my $env_str = get_uninstall_env_str();
		system("yes | $env_str ofed_uninstall.sh $uninstall_flags >> $ofedlogs/ofed_uninstall.log 2>&1");
		my $res = $? >> 8;
		my $sig = $? & 127;
		if ($sig or $res) {
			if ($res == 174) {
				print_and_log("Error: One or more packages depends on $PACKAGE.\nThese packages should be removed before uninstalling $PACKAGE:\n", 1);
				system("cat $ofedlogs/ofed_uninstall.log | perl -ne '/Those packages should be/ && do {\$a=1; next}; /To force uninstallation use/ && do {\$a=0}; print if \$a'");
				print_and_log("To force uninstallation use '--force' flag.\n", 1);
				addSetupInfo ("$ofedlogs/ofed_uninstall.log");
				print_and_log_colored("See $ofedlogs/ofed_uninstall.log", 1, "RED");
				exit $NONOFEDRPMS;
			}
			print_and_log_colored("Failed to uninstall the previous installation", 1, "RED");
			addSetupInfo ("$ofedlogs/ofed_uninstall.log");
			print_and_log_colored("See $ofedlogs/ofed_uninstall.log", 1, "RED");
			exit $ERROR;
		}
	}
	my @list_to_remove;
	foreach (@remove_debs){
		next if ($is_mlnx_en and $_ !~ /$mlnx_en_pkgs/);
		next if ($_ =~ /^xen|ovsvf-config|opensmtpd/);
		foreach (get_all_matching_installed_debs($_)) {
			next if ($is_mlnx_en and $_ =~ /mft/);
			next if ($_ =~ /^xen|ovsvf-config|opensmtpd/);
			next if (not $components_filter->($_));
			if (not $selected_for_uninstall{$_}) {
				my $package = strip_package_arch($_);
				push (@list_to_remove, $_);
				$selected_for_uninstall{$package} = 1;
				print_and_log("\t" . $_ . " - will be removed.\n", $verbose2);
				if (not (exists $packages_info{$package} or $package =~ /mlnx-ofed-/)) {
					$non_ofed_for_uninstall{$package} = 1;
				}
				get_requires($_);
			}
		}
	}

	if (not $force and keys %non_ofed_for_uninstall) {
		print_and_log("\nError: One or more packages depends on $PACKAGE.\nThose packages should be removed before uninstalling $PACKAGE:\n\n", 1);
		print_and_log(join(" ", (keys %non_ofed_for_uninstall)) . "\n\n", 1);
		print_and_log("To force uninstallation use '--force' flag.\n", 1);
		exit $NONOFEDRPMS;
	}

	my @list_to_remove_all = grep {not is_immuned($_)}
		(@list_to_remove, @dependant_packages_to_uninstall);
	ex "apt-get remove -y @list_to_remove_all" if (scalar(@list_to_remove_all));
	foreach (@list_to_remove_all){
		if (is_configured_deb($_)) {
			if (not /^opensm/) {
				ex "apt-get remove --purge -y $_";
			} else {
				system("apt-get remove --purge -y $_");
			}
		}
	}
	system ("/bin/rm -rf /usr/src/mlnx-ofed-kernel* > /dev/null 2>&1");
}

#
# set vma flags in /etc/modprobe.d/mlnx.conf
#
sub set_vma_flags
{
	return if ($user_space_only);
	my $mlnx_conf = "/etc/modprobe.d/mlnx.conf";
    if ($with_vma and -e "$mlnx_conf") {
        my @lines;
        open(FD, "$mlnx_conf");
        while (<FD>) {
            push @lines, $_;
        }
        close (FD);
        open(FD, ">$mlnx_conf");
        foreach my $line (@lines) {
            chomp $line;
            print FD "$line\n" unless ($line =~ /disable_raw_qp_enforcement|fast_drop|log_num_mgm_entry_size/);
        }
        print FD "options mlx4_core fast_drop=1\n";
        print FD "options mlx4_core log_num_mgm_entry_size=-1\n";
        close (FD);
    }

    if (-f "/etc/infiniband/openib.conf") {
        my @lines;
        open(FD, "/etc/infiniband/openib.conf");
        while (<FD>) {
            push @lines, $_;
        }
        close (FD);
        # Do not start SDP
        # Do not start QIB to prevent http://bugs.openfabrics.org/bugzilla/show_bug.cgi?id=2262
        open(FD, ">/etc/infiniband/openib.conf");
        foreach my $line (@lines) {
            chomp $line;
            if ($line =~ m/(^SDP_LOAD=|^QIB_LOAD=).*/) {
                    print FD "${1}no\n";
            } elsif ($line =~ m/(^SET_IPOIB_CM=).*/ and $with_vma) {
                # Set IPoIB Datagram mode in case of VMA installation
                print FD "SET_IPOIB_CM=no\n";
            } else {
                    print FD "$line\n";
            }
        }
        close (FD);
    }
}

sub updateLimitsConf
{
	# Update limits.conf (but not for Containers)
	if (-e "/.dockerenv" or `grep docker /proc/self/cgroup 2>/dev/null` ne "") {
		return;
	}

	if (-e "/etc/security/limits.conf") {
		open(LIMITS, "/etc/security/limits.conf");
		while (<LIMITS>) {
			if (/soft\s*memlock/) {
				$update_limits_conf_soft = 0;
			}
			if (/hard\s*memlock/) {
				$update_limits_conf_hard = 0;
			}
		}
		close LIMITS;

		if($update_limits_conf_soft or $update_limits_conf_hard) {
			print_and_log("Configuring /etc/security/limits.conf.\n", (not $quiet));
		}

		open(LIMITS, ">>/etc/security/limits.conf");
		if($update_limits_conf_soft) {
			print LIMITS "* soft memlock unlimited\n";
		}
		if($update_limits_conf_hard) {
			print LIMITS "* hard memlock unlimited\n";
		}
		close LIMITS;
	}
}

sub print_selected
{
	print_and_log_colored("\nBelow is the list of ${PACKAGE} packages that you have chosen
	\r(some may have been added by the installer due to package dependencies):\n", 1, "GREEN");
	for my $package ( @selected_packages ) {
		print_and_log("$package\n", 1);
	}
	print_and_log("\n", 1);
}

sub disable_package
{
    my $key = shift;

    if (exists $packages_info{$key}) {
	$packages_info{$key}{'disable_package'} = 1;
        $packages_info{$key}{'available'} = 0;
        for my $requester (@{$packages_deps{$key}{'required_by'}}) {
	    next if (exists $packages_info{$requester}{'disable_package'});
            disable_package($requester);
        }
    }
    # modules
    if (exists $kernel_modules_info{$key}) {
        $kernel_modules_info{$key}{'available'} = 0;
        for my $requester (@{$modules_deps{$key}{'required_by'}}) {
            disable_package($requester);
        }
    }

    if (not (exists $packages_info{$key} or exists $kernel_modules_info{$key})) {
        print_and_log_colored("Unsupported package: $key", (not $quiet), "YELLOW");
    }
}

# used for blocking packages that are replaced with rdma-core and vice versa
sub block_package
{
    my $key = shift;

    if (exists $packages_info{$key}) {
        $packages_info{$key}{'available'} = 0;
        $packages_info{$key}{'disabled'} = 1;
    }
    # modules
    if (exists $kernel_modules_info{$key}) {
        $kernel_modules_info{$key}{'available'} = 0;
        $kernel_modules_info{$key}{'disabled'} = 1;
    }
}

sub enable_package
{
    my $key = shift;

    return unless (exists $packages_info{$key});
    return if (exists $packages_info{$key}{'enabled_package'});

    $packages_info{$key}{'available'} = 1;
    $packages_info{$key}{'enabled_package'} = 1;
    for my $req ( @{ $packages_info{$key}{'ofa_req_inst'} } ) {
        enable_package($req);
    }
}

sub enable_module
{
    my $key = shift;

    if (exists $kernel_modules_info{$key}) {
        $kernel_modules_info{$key}{'available'} = 1;
        for my $req ( @{ $kernel_modules_info{$key}{'requires'} } ) {
            enable_module($req);
        }
    }
}

sub add_enabled_pkgs_by_user
{
    ##############
    # handle with/enable flags
    for my $key ( keys %force_enable_packages ) {
	# fix kernel packages names
	# DKMS enabled
	if ($with_dkms) {
		if ($key =~ /-modules/) {
			$key =~ s/-modules/-dkms/g;;
		}
	} else {
	# DKMS disabled
		if ($key =~ /-dkms/) {
			$key =~ s/-dkms/-modules/g;;
		}
	}

        if (exists $packages_info{$key}) {
            next if ($packages_info{$key}{'disabled'});
            enable_package($key);
            push (@selected_by_user, $key);
        }
        if (exists $kernel_modules_info{$key}) {
            next if ($kernel_modules_info{$key}{'disabled'});
            enable_module($key);
            push (@selected_modules_by_user , $key);
        }

        if (not (exists $packages_info{$key} or exists $kernel_modules_info{$key})) {
            print_and_log_colored("Unsupported package: $key", (not $quiet), "YELLOW");
        }
    }
}

sub set_availability
{
	if ($user_space_only) {
		$packages_info{"mlnx-ofed-kernel-utils"}{"mode"} = "user";
	}

	if ($arch =~ /arm|aarch/i) {
		$packages_info{'dapl'}{'available'} = 0;
		$packages_info{'libdapl2'}{'available'} = 0;
		$packages_info{'dapl2-utils'}{'available'} = 0;
		$packages_info{'libdapl-dev'}{'available'} = 0;
	}

	if ($kernel =~ /fbk/ or $arch =~ /arm|aarch/) {
		$kernel_modules_info{'sdp'}{'available'} = 0;
	}

	if ($arch =~ /ppc/i) {
		$packages_info{'srp'}{'available'} = 0;
		$packages_info{'srp-dkms'}{'available'} = 0;
		$packages_info{'srp-modules'}{'available'} = 0;
	}

	# disable iproute2 for unsupported OSs
	if ($distro =~ /ubuntu1[45] | debian8/x) {
			$packages_info{'mlnx-iproute2'}{'available'} = 0;
	}

	if ($cuda_version) {
		$packages_info{'ucx-cuda'}{'available'} = 1;
	}

	if ( not ($with_vma or $with_xlio) or $arch !~ m/x86_64|ppc64|arm|aarch/) {
		for my $p (qw/libvma sockperf libxlio/) {
			$packages_info{$p}{'available'} = 0;
		}
	}

	if ( $arch =~ m/aarch64/ and $with_bluefield) {
		if ($distro =~ /debian10 | ubuntu18.04 | ubuntu20.04/x) {
			$packages_info{'nvme-snap'}{'available'} = 1;
			$packages_info{'spdk'}{'available'} = 1;
			$packages_info{'spdk-dev'}{'available'} = 1;
			$packages_info{'mlxbf-bootctl'}{'available'} = 1;
		}
	}

	if ($is_bf) {
		# Avoid rshim installation on BlueField
		$packages_info{'rshim'}{'available'} = 0;
	}

	# turn on isert if we are on follow OS and arch
	if (not ($distro =~ /
			ubuntu16.04 | ubuntu17.10 | ubuntu1[89] | ubuntu2. |
			debian9 | debian1.
		/x and	$kernel =~ /^[5-9] | ^4\.[4-9] | ^4\.1[0-9]\. | ^4\.20 | ^3\.1[3-9]/x
	)) {
		$kernel_modules_info{'isert'}{'available'} = 0;
		$packages_info{'isert-dkms'}{'available'} = 0;
		$packages_info{'isert-modules'}{'available'} = 0;
	}

	if (not $with_dkms) {
		# we use only knem-modules when not working with dkms
		$packages_info{'knem'}{'available'} = 0;
	}

	if (($arch ne 'x86_64') or ($kernel !~ /
		^4\.15\.0-  # Ubuntu 18.04
		| ^5\.4\.0- # Ubuntu 20.04
		| ^5\.13\.0- # Ubuntu 21.10
		| ^5\.13\b
		| ^5\.15\b
		| ^5\.17\b   # Latest rebase's base
		| ^5\.18\b
		| ^5\.19\b
		| ^6\.0\b
		| ^6\.1\b    # Latest mainline
		/x) or
	    not $with_nfsrdma
	) {
		if ($with_nfsrdma) {
			# user asked to install it, but it's not supported by the kernel
			print_and_log_colored("WARNING: NFSoRDMA is not supported over kernel $kernel, will continue installation without it.\n", 1, "YELLOW");
		}
		$kernel_modules_info{'nfsrdma'}{'available'} = 0;
		$packages_info{"$mlnx_nfsrdma"}{'available'} = 0;
	}

	if (not $with_nvme or $kernel !~ /^4\.[8-9] | ^4\.[12][0-9] | ^[5-9]/x) {
		if ($with_nvme) {
			# user asked to install it, but it's not supported by the kernel
			print_and_log_colored("WARNING: NVMEoF is not supported over kernel $kernel, will continue installation without it.\n", 1, "YELLOW");
		}
		$packages_info{"$mlnx_nvme"}{'available'} = 0;
	}

	if ($kernel !~ /^[5-9]|^4\.[8-9]|^4\.1[0-9]\./) {
		$packages_info{"$mlnx_rdma_rxe"}{'available'} = 0;
	}

	# turn off srp and iser if we are not on follow OS and arch
	if (not($distro =~ /
			ubuntu14.04 |
			ubuntu16.04 | ubuntu17.10 | ubuntu1[89] | ubuntu2. |
			debian8\.[7-9] | debian8\.1. | debian9 | debian1.
		/x and	$kernel =~ /^[4-9] | ^3\.1[6-9] | ^3.13.0-/x
	) ) {
		$kernel_modules_info{'srp'}{'available'} = 0;
		$packages_info{'srp'}{'available'} = 0;
		$packages_info{'srp-modules'}{'available'} = 0;
		$packages_info{'srp-dkms'}{'available'} = 0;
	}

	if (
		($distro =~ /ubuntu1[6-9]/) or
		($distro =~ /debian(9 | 10)/x) or
		0) {
			$packages_info{'neohost-backend'}{'available'} = 1;
			$packages_info{'neohost-sdk'}{'available'} = 1;
  }

	# turn off iser if we are not on follow OS and arch
	if (not($distro =~ /
			ubuntu16.04 | ubuntu17.10 | ubuntu18.04 | ubuntu18.10 |
			debian8\.[7-9] | debian8\.1[01] | debian9\.[0-5]
		/x and	$kernel =~ /^[5-9] | ^4\.[0-9] | ^3\.1[6-9]/x
	) ) {
		$kernel_modules_info{'iser'}{'available'} = 0;
		$packages_info{'iser'}{'available'} = 0;
	}

	# See https://redmine.mellanox.com/issues/1929856
	if ($distro eq 'ubuntu19.10') {
		block_package("ar-mgr");
	}

    ##############
    # handle without/disable flags
    if (keys %disabled_packages) {
        # build deps list
        for my $pkg (keys %packages_info) {
            for my $req ( @{ $packages_info{$pkg}{'ofa_req_inst'}} , @{ $packages_info{$pkg}{'ofa_req_build'}} ) {
                next if not $req;
                push (@{$packages_deps{$req}{'required_by'}}, $pkg);
            }
        }
        for my $mod (keys %kernel_modules_info) {
            for my $req ( @{ $kernel_modules_info{$mod}{'requires'} } ) {
                next if not $req;
                push (@{$modules_deps{$req}{'required_by'}}, $mod);
            }
        }
        # disable packages
        for my $key ( keys %disabled_packages ) {
            disable_package($key);
        }
    }
    # end of handle without/disable flags

	# keep this at the end of the function.
	add_enabled_pkgs_by_user();
}

sub find_misconfigured_packages() {
	my @package_problems = ();
	open(DPKG, "dpkg-query -W -f '\${Status}::\${Package} \${Version}\n' |");
	while (<DPKG>) {
		chomp;
		my ($status_str, $package) = split('::');
		my ($required, $error, $status) = split(/ /, $status_str);
		next if ($status =~ /installed | config-files/x);
		push @package_problems, ("$package:\t$status_str\n");
	}
	close(DPKG);
	return @package_problems;
}

sub addSetupInfo
{
	my $log = shift @_;

	print "Collecting debug info...\n" if (not $quiet);

	if (not open (LOG, ">> $log")) {
		print "-E- Can't open $log for appending!\n";
		return;
	}
	my @package_problems = find_misconfigured_packages();

	print LOG "\n\n\n---------------- START OF DEBUG INFO -------------------\n";
	print LOG "Install command: $CMD\n";

	print LOG "\nVars dump:\n";
	print LOG "- ofedlogs: $ofedlogs\n";
	print LOG "- MLNX_OFED_LINUX_VERSION: $MLNX_OFED_LINUX_VERSION\n";
	print LOG "- MLNX_OFED_ARCH: $MLNX_OFED_ARCH\n";
	print LOG "- MLNX_OFED_DISTRO: $MLNX_OFED_DISTRO\n";
	print LOG "- distro: $distro\n";
	print LOG "- arch: $arch\n";
	print LOG "- kernel: $kernel\n";
	print LOG "- config: $config\n";
	print LOG "- update_firmware: $update_firmware\n";

	print LOG "\nSetup info:\n";
	print LOG "\n- uname -r: " . `uname -r 2>&1`;
	print LOG "\n- uname -m: " . `uname -m 2>&1`;
	print LOG "\n- lsb_release -a: " . `lsb_release -a 2>&1`;
	print LOG "\n- cat /etc/issue: " . `cat /etc/issue 2>&1`;
	print LOG "\n- cat /proc/version: " . `cat /proc/version 2>&1`;
	print LOG "\n- gcc --version: " . `gcc --version 2>&1`;
	print LOG "\n- lspci -n | grep 15b3: " . `lspci -n 2>&1 | grep 15b3`;
	if (@package_problems) {
		print LOG "\n- Potentiall broken packages:";
		print LOG "\n- ". join("\n- ", @package_problems);
	}
	print LOG "\n- dpkg --list: " . `dpkg --list 2>&1`;

	print LOG "---------------- END OF DEBUG INFO -------------------\n";
	close (LOG);
}

sub ex1
{
    my $cmd = shift @_;

    system("$cmd 2>&1");
    my $res = $? >> 8;
    my $sig = $? & 127;
    if ($sig or $res) {
        print_and_log_colored("Command execution failed: $cmd", 1, "RED");
        exit 1;
    }
}

sub invoke_add_kernel_support
{
	my $new_package = "$PACKAGE-$MLNX_OFED_LINUX_VERSION-" . lc($distro) . "-ext";
	my $flags = $add_kernel_support_flags;
	if ($force) {
		$flags .= " --force";
	}
	for my $key ( keys %disabled_packages ) {
		$flags .= " --without-$key";
	}
	if (not $check_linux_deps) {
		$flags .= " --without-depcheck";
	}
	if (not $with_kmod_debug_symbols) {
		$flags .= " --without-debug-symbols";
	}
	if (not $with_mlxdevm) {
		$flags .= " --without-mlxdevm-mod";
	}
	if ($kernel_extra) {
		$ENV{'MLNX_EXTRA_FLAGS'} = "$ENV{'MLNX_EXTRA_FLAGS'} --kernel-extra-args $kernel_extra_args";
	}

	system("TMP=$TMPDIR/$PACKAGE-$MLNX_OFED_LINUX_VERSION-$kernel $CWD/mlnx_add_kernel_support.sh -m $CWD -k $kernel -s $kernel_sources --make-tgz --name $new_package --yes $flags --distro $distro");
	my $res = $? >> 8;
	my $sig = $? & 127;
	# mlnx_add_kernel_support.sh gives exit status 30 when kernel already supported (w/o DKMS support).
	if ($sig == 30 or $res == 30) {
		print_and_log("Kernel $kernel is already supported.\n", ($verbose2 or $add_kernel_support_build_only));
		if ($add_kernel_support_build_only) {
			exit $SUCCESS;
		}
		print_and_log("Resuming installation from current MLNX_OFED package...\n", $verbose2);
		remove_old_packages();
		return;
	}
	if ($sig or $res) {
		print_and_log_colored("Failed to build $PACKAGE for $kernel", 1, "RED");
		exit $ERROR;
	}

	if ( -e "$TMPDIR/$PACKAGE-$MLNX_OFED_LINUX_VERSION-$kernel/$new_package.tgz") {
		if ($add_kernel_support_build_only) {
			print_and_log("New image ready at: $TMPDIR/$PACKAGE-$MLNX_OFED_LINUX_VERSION-$kernel/$new_package.tgz\n", 1);
			exit $SUCCESS;
		}
		remove_old_packages();
		print_and_log_colored("Installing $TMPDIR/$PACKAGE-$MLNX_OFED_LINUX_VERSION-$kernel/$new_package", 1, "GREEN");
		system("/bin/rm -rf $TMPDIR/$PACKAGE-$MLNX_OFED_LINUX_VERSION-$kernel/$new_package");
		system("cd $TMPDIR/$PACKAGE-$MLNX_OFED_LINUX_VERSION-$kernel; tar xzf $new_package.tgz");
		print_and_log("$TMPDIR/$PACKAGE-$MLNX_OFED_LINUX_VERSION-$kernel/$new_package/$INSTALLER --force --without-dkms @saved_ARGV\n", 1);
		system("$TMPDIR/$PACKAGE-$MLNX_OFED_LINUX_VERSION-$kernel/$new_package/$INSTALLER --force --without-dkms @saved_ARGV");
		my $res = $? >> 8;
		my $sig = $? & 127;
		if ($sig or $res) {
			print_and_log_colored("Failed to install $new_package for $kernel", 1, "RED");
			exit $ERROR;
		}
	} else {
		print_and_log_colored("New package was not created at '$TMPDIR/$PACKAGE-$MLNX_OFED_LINUX_VERSION-$kernel/$new_package.tgz' !", 1, "RED");
		exit $ERROR;
	}
	exit $SUCCESS;
}

sub isKernelSupported
{
	my $m = 0;

	my @supported_kernels = ();
	my $mod_pat = "mlnx-ofed-kernel-modules";
	if ($install_option eq 'eth-only') {
		my $mod_pat = "mlnx-en-modules";
	}
	@supported_kernels = `dpkg --contents '$DEBS'/*$mod_pat*.deb 2>/dev/null | grep lib.modules | awk -F '/' '{print\$5}' | grep -v '^\$' | sort -u`;

	for my $sk (@supported_kernels) {
		chomp $sk;
		if ($sk eq $kernel) {
			$m = 1;
			last;
		}
	}

	return $m;
}


########
# MAIN #
########
sub main
{
	if ($distro =~ m/unsupported/ or ($distro !~ m/ubuntu | debian | uos/x)) {
		print_and_log_colored("Current operation system in not supported!", 1, "RED");
		exit 1;
	}

	if (-f ".arch" or -f "arch") {
		$MLNX_OFED_ARCH = `cat .arch 2> /dev/null || cat arch`;
		chomp $MLNX_OFED_ARCH;

		if ($arch =~ /i[0-9]86/ and $MLNX_OFED_ARCH ne "i686" or
			$arch !~ /i[0-9]86/ and $MLNX_OFED_ARCH ne $arch) {
			print_and_log_colored("Error: The current $PACKAGE is intended for a $MLNX_OFED_ARCH architecture", 1, "RED");
			exit $PREREQUISIT;
		}
	}

	$MLNX_OFED_DISTRO = `cat distro 2> /dev/null`;
	chomp $MLNX_OFED_DISTRO;
	if ("$MLNX_OFED_DISTRO" eq "skip-distro-check") {
		$skip_distro_check = 1;
	}
	if (not $skip_distro_check) {
		if ($MLNX_OFED_DISTRO ne lc($distro)) {
			print_and_log_colored( "Error: The current $PACKAGE is intended for $MLNX_OFED_DISTRO", 1, "RED");
			exit $PREREQUISIT;
		}
	}

	# install packages in case the user didn't choose firmware_update_only
	if (not $firmware_update_only) {

		if (not ($skip_unsupported_devices_check or $print_available or $check_deps_only or !$update_firmware)) {
			unsupported_devices_check();
		}
		if ($add_kernel_support and not $print_available) {
			invoke_add_kernel_support();
		}

		if ($config_net_given) {
			if (not -e $config_net) {
				print_and_log_colored("Error: network config_file '$config_net' does not exist!", 1, "RED");
				exit 1;
			}

			open(NET, "$config_net") or die "Can't open $config_net: $!";
			while (<NET>) {
				my ($param, $value) = split('=');
				chomp $param;
				chomp $value;
				my $dev = $param;
				$dev =~ s/(.*)_(ib[0-9]+)/$2/;
				chomp $dev;

				if ($param =~ m/IPADDR/) {
					$ifcfg{$dev}{'IPADDR'} = $value;
				}
				elsif ($param =~ m/NETMASK/) {
					$ifcfg{$dev}{'NETMASK'} = $value;
				}
				elsif ($param =~ m/NETWORK/) {
					$ifcfg{$dev}{'NETWORK'} = $value;
				}
				elsif ($param =~ m/BROADCAST/) {
					$ifcfg{$dev}{'BROADCAST'} = $value;
				}
				elsif ($param =~ m/ONBOOT/) {
					$ifcfg{$dev}{'ONBOOT'} = $value;
				}
				elsif ($param =~ m/LAN_INTERFACE/) {
					$ifcfg{$dev}{'LAN_INTERFACE'} = $value;
				}
				else {
					print_and_log_colored("Unsupported parameter '$param' in $config_net\n", $verbose2, "RED");
				}
			}
			close(NET);
		}

		set_availability();
		set_existing_debs();

		# if DKMS is disabled, check the supported kernels list
		# skip kernel check when in user space mode only
		if (not $with_dkms and not $print_available and not $user_space_only and not $check_deps_only)
		{
			my $match = isKernelSupported();

			if (not $match) {
				print_and_log_colored("DKMS is disabled for $kernel kernel, $PACKAGE does not have non-DKMS driver packages available for this kernel.", 1, "RED");
				if ($auto_add_kernel_support) {
					print_and_log("Auto add kernel support requested, going to run mlnx_add_kernel_support.sh...\n", 1);
					invoke_add_kernel_support();
				}
				print_and_log_colored("You can run mlnx_add_kernel_support.sh in order to to generate an $PACKAGE package with drivers for this kernel.", 1, "RED");
				print_and_log_colored( "Or, you can provide '--add-kernel-support' flag to generate an $PACKAGE package and automatically start the installation.", 1, "RED");
				print_and_log("Note: You can force enabling DKMS support by using '--force-dkms' installation flag, however, DKMS may build and install drivers for a different kernel.\n", 1);
				exit $ERROR;
			}
		}

		my $num_selected = select_packages();
		resolve_dependencies();

		if ($print_available) {
			$config = $TMPDIR . "/ofed-$install_option.conf";
			chomp $config;
			open(CONFIG, ">$config") || die "Can't open $config: $!";
			flock CONFIG, $LOCK_EXCLUSIVE;
			print "\nMLNX_OFED packages: ";
			for my $package ( @selected_packages ) {
				if ($packages_info{$package}{'available'} and is_deb_available($package)) {
					print $package . ' ';
					print CONFIG "$package=y\n";
				}
			}
			flock CONFIG, $UNLOCK;
			close(CONFIG);
			print GREEN "\nCreated $config", RESET "\n";
			exit $SUCCESS;
		}

		warn("Logs dir: $ofedlogs\n");
		warn("General log file: $glog\n");

		if (not $num_selected) {
			print_and_log_colored("$num_selected packages selected. Exiting...", 1, "RED");
			exit 1;
		}

		if (not $quiet and not $check_deps_only) {
			print_selected();
		}

		if ($arch =~ /ppc/ and ($force_enable_packages{'srp-dkms'} or
								$force_enable_packages{'srp-modules'})) {
			print_and_log_colored("WARNING: srp module installaion was forced, ibmvscsi module will not be operational after $PACKAGE installation!", 1, "YELLOW");
		}

		if (not $check_deps_only) {
			print "This program will install the $PACKAGE package on your machine.\n"
			    . "Note that all other Mellanox, OEM, OFED, RDMA or Distribution IB packages will be removed.\n"
			    . "Those packages are removed due to conflicts with $PACKAGE, do not reinstall them.\n\n" if (not $quiet);
			if (not $force and not $quiet) {
				print "Do you want to continue?[y/N]:";
				my $ans = getch();
				print "\n";
				if ($ans !~ m/[yY]/) {
					exit $ERROR;
				}
			}
		}

		# install required packages
		check_linux_dependencies();

		# verify that dpkg DB is ok
		print_and_log("Running: dpkg --configure -a --force-all --force-confdef --force-confold \n", $verbose2);
		system("dpkg --configure -a  --force-all --force-confdef --force-confold >> $glog 2>&1");
		print_and_log("Running: apt-get install -f $apt_extra_params \n", $verbose2);
		system("apt-get install -f -y $apt_extra_params >> $glog 2>&1");

		# remove old packages
		remove_old_packages();

		# install new packages chosen by the user
		install_selected();

	} # end not firmware_update_only

	# update FW
	my $fwerr = 0;
	if (not exists $disabled_packages{"mlnx-fw-updater"}) {
		my $fwup = $update_firmware ? 'yes' : 'no';
		my ($fwbin) = glob("$DEBS/mlnx-fw-updater*.deb");
		if (-f "$fwbin") {
			if (is_installed_deb("mlnx-fw-updater")) {
				print_and_log("Removing old version of mlnx-fw-updater...\n", $verbose);
				system("$DPKG --purge mlnx-fw-updater >/dev/null");
			}
			my $cmd = "FW_UPDATE_FLAGS='--log $ofedlogs/fw_update.log $fw_update_flags --tmpdir $TMPDIR' RUN_FW_UPDATER='$fwup' $DPKG -i '$fwbin'";
			print_and_log("Running: $cmd\n", $verbose2);
			system("$cmd");
			$fwerr = `grep EXIT_STATUS: $ofedlogs/fw_update.log 2>/dev/null`;
			chomp $fwerr;
			$fwerr =~ s/EXIT_STATUS://g;
			$fwerr =~ s/\s//g;
			$fwerr = $update_firmware if("$fwerr" eq "");
		} elsif ($update_firmware) {
			# rpm doesn't exist and FW update was requested.
			print_and_log_colored("Error: mlnx-fw-updater deb doesn't exist! Cannot perform firmware update!", 1, "RED");
			$fwerr = 2;# DEVICE_INI_MISSING
		}
	}
	exit $fwerr if ($firmware_update_only);

	if ($do_copy_udev) {
		copy_udev_rules($verbose2);
	}

	if (is_module_in_deb("mlnx-ofed-kernel", "ipoib")) {
		ipoib_config();
	}

	# Set mlnx_affinity
	set_mlnx_affinity();

	set_mlnx_tune();

	# Set POST_START_DELAY
	set_post_start_delay() if ($post_start_delay);

	# set vma flags in /etc/modprobe.d/mlnx.conf in case the user chosen to enable vma
	set_vma_flags();

	# set opensm service
	set_opensm_service();

	# Update limits.conf
	updateLimitsConf();

	if ($umad_dev_rw or $umad_dev_na) {
		set_umad_permissions($umad_dev_na);
	}

        if ( not $quiet ) {
            check_pcie_link();
        }

    # Update ofed_info
    if (-f "/usr/bin/ofed_info") {
        my @ofed_info;
        open(INFO, "/usr/bin/ofed_info");
        while (<INFO>) {
           push @ofed_info, $_;
        }
        close(INFO);
        open(INFO, ">/usr/bin/ofed_info");
        foreach my $line (@ofed_info) {
           if ($line =~ m/^OFED/) {
              chomp $line;
              $line =~ s/://;
              $line =~ s/internal-//;
              print INFO "$PACKAGE-$MLNX_OFED_LINUX_VERSION ($line):\n";
           } elsif ($line =~ m/^if/ and $line =~ m/exit/ and $line =~ /X-s/) {
              $line = "if [ \"X\$1\" == \"X-s\" ]; then echo $PACKAGE-$MLNX_OFED_LINUX_VERSION:; exit 0; fi";
              print INFO "$line\n";
           } elsif ($line =~ m/^if/ and $line =~ m/exit/ and $line =~ /X-n/) {
              $line = "if [ \"X\$1\" == \"X-n\" ]; then echo $MLNX_OFED_LINUX_VERSION; exit 0; fi";
              print INFO "$line\n";
           } else {
              print INFO $line;
           }
        }
        close(INFO);
        system("sed -i -e \"s/OFED-internal/$PACKAGE/g\" /usr/bin/ofed_info");
    }

	if (is_installed_deb("$knem") and -f "/etc/modules"){
		system("echo knem >> /etc/modules");
		system ("/sbin/modprobe -r knem > /dev/null 2>&1");
		system ("/sbin/modprobe knem > /dev/null 2>&1");
	}

	print_and_log_colored("Installation passed successfully", (not $quiet), "GREEN");
	if (not $user_space_only) {
		if ($install_option eq 'eth-only') {
		print_and_log_colored("To load the new driver, run:\n/etc/init.d/mlnx-en.d restart", (not $quiet), "GREEN");
		} else {
			print_and_log_colored("To load the new driver, run:\n/etc/init.d/openibd restart", (not $quiet), "GREEN");
			if ($with_nvme) {
				print_and_log("Note: In order to load the new nvme-rdma and nvmet-rdma modules, the nvme module must be reloaded.\n", 1);
			}
		}
	}
} # end main
###############################################################

main();
exit $err;
