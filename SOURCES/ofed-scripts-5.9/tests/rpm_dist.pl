#!/usr/bin/perl

use strict;
use warnings;

use Cwd;
use File::Basename;

use v5.10;

my $WDIR = dirname(dirname(Cwd::abs_path $0));
require("$WDIR/common.pl");

my $me = basename($0);
my $fail_count;

sub check_package($$) {
	my $package = shift;
	my $expected = shift;
	if (system("rpm -qpl \"$package\" 2>/dev/null | grep -E -q '^(/etc/issue|/etc/os-release)\$'")) {
		say "$me: Invalid $package (no os-release / issue file)";
		return;
	}
	my $version_str = `rpm -qp $package 2>/dev/null`;
	chomp $version_str;
	my ($rpm_distro, $DISTRO) = parse_rpm_dist($version_str, "");
	if ($rpm_distro eq "") {
		$rpm_distro = "UNSUPPORTED"; # Distributions we should not parse
	}
	if ($rpm_distro ne $expected) {
		say "$me: Expect: '$expected', got: '$rpm_distro (package: $package)";
		$fail_count++;
	}
}

sub check_package_installpl_rhel {
	my $dist_ver = shift;
	my $target = shift;
	$target = "rhel$dist_ver" unless ($target);
	$target =~ y/./u/;
	my $subdir = "x86_64/BaseOS/Packages";
	my $glob = "/auto/LIT/PXE/RH/$dist_ver/$subdir/redhat-release-$dist_ver-*.rpm";
	my @packages = glob $glob;
	if (not @packages) {
		say "$me: no package was found for RHEL $dist_ver. (Tried $glob).";
		return;
	}
	my $package = (sort @packages)[0];
	check_package $package, $target;
}

sub check_package_installpl_rhel_old {
	my $dist_ver = shift;
	my $target = shift;
	$target = "rhel$dist_ver" unless ($target);
	$target =~ y/./u/;
	my $subdir = "";
	my $dirname = "$dist_ver";
	if ($dist_ver =~ /^7\.[456]alternate/) {
		$subdir = "ppc64le/Packages";
		$dirname = $dist_ver;
		$dirname =~ s/alternate/ALT/;
	} elsif ($dist_ver =~ /^[67]\./) {
		$subdir = "x86_64/Packages";
	} elsif ($dist_ver =~ /^[5]\./) {
		$subdir = "x86_64/cdrom/Server";
	}
	my $glob = "/auto/LIT/PXE/RH/$dirname/$subdir/redhat-release-server-*.rpm";
	my @packages = glob $glob;
	if (not @packages) {
		say "$me: no package was found for RHEL $dist_ver. (Tried $glob).";
		return;
	}
	my $package = (sort @packages)[0];
	check_package $package, $target;
}

sub check_package_installpl_fedora {
	my $dist_ver = shift;
	my $target = shift;
	$target = "fc$dist_ver" unless ($target);
	#target=${2:-fc$1}
	my $common = "-common";
	if ($dist_ver < 30) {
		$common = "";
	}
	my $package = "/auto/LIT/PXE/Fedora/$dist_ver/x86_64/Packages/f/fedora-release$common-$dist_ver-1.noarch.rpm";
	check_package $package, $target;
}

sub check_package_installpl_sles($$) {
	my $dist_ver = shift;
	my $target = shift;

	my $subdir = "x86_64/Product-SLES/x86_64";
	if ($dist_ver eq "15.0") {
		$subdir = "x86_64/x86_64";
	} elsif ($dist_ver eq "15.1") {
		$subdir = "x86_64/Packages/Product-SLES/x86_64";
	} elsif ($dist_ver eq "15.3") {
		$subdir = "x86_64/DVD1/Product-SLES/x86_64";
	} elsif ($dist_ver =~ /^1[12]/) {
		$subdir = "x86_64/suse/x86_64";
	}
	my $glob = "/auto/LIT/PXE/SLES/$dist_ver/$subdir/sles-release-$dist_ver-*.rpm";
	my @packages = glob $glob;
	if (not @packages) {
		say "$me: no package was found for SLES $dist_ver. (Tried $glob).";
		return;
	}
	my $package = (sort @packages)[0];
	check_package $package, $target;
}

sub main() {
	$fail_count = 0;
	#check_package_installpl_sles "11.0", "UNSUPPORTED";
	check_package_installpl_sles "11.1", "sles11sp1";
	check_package_installpl_sles "11.2", "sles11sp2";
	check_package_installpl_sles "11.3", "sles11sp3";
	check_package_installpl_sles "11.4", "sles11sp4";
	check_package_installpl_sles "12",   "sles12sp0";
	#check_package_installpl_sles "12.0", "sles12sp0";
	check_package_installpl_sles "12.1", "sles12sp1";
	check_package_installpl_sles "12.2", "sles12sp2";
	check_package_installpl_sles "12.3", "sles12sp3";
	check_package_installpl_sles "12.4", "sles12sp4";
	check_package_installpl_sles "12.5", "sles12sp5";
	#check_package_installpl_sles "15"  , "UNSUPPORTED";
	#check_package_installpl_sles "15.0", "UNSUPPORTED";
	check_package_installpl_sles "15.1", "sles15sp1";
	check_package_installpl_sles "15.2", "sles15sp2";
	check_package_installpl_sles "15.3", "sles15sp3";
	check_package_installpl_fedora 27;
	check_package_installpl_fedora 28;
	check_package_installpl_fedora 29;
	check_package_installpl_fedora 30;
	check_package_installpl_fedora 31;
	check_package_installpl_fedora 32;
	check_package_installpl_fedora 33, "UNSUPPORTED";
	check_package_installpl_fedora 34, "UNSUPPORTED";

	check_package_installpl_rhel_old "6.0";
	check_package_installpl_rhel_old "6.1";
	check_package_installpl_rhel_old "6.2";
	check_package_installpl_rhel_old "6.3";
	check_package_installpl_rhel_old "6.4";
	check_package_installpl_rhel_old "6.5";
	check_package_installpl_rhel_old "6.6";
	check_package_installpl_rhel_old "6.7";
	check_package_installpl_rhel_old "6.8";
	check_package_installpl_rhel_old "6.9";
	check_package_installpl_rhel_old "6.10";
	#check_package_installpl_rhel_old "7.0";
	check_package_installpl_rhel_old "7.1";
	check_package_installpl_rhel_old "7.2";
	check_package_installpl_rhel_old "7.3";
	check_package_installpl_rhel_old "7.4";
	check_package_installpl_rhel_old "7.4alternate";
	check_package_installpl_rhel_old "7.5";
	check_package_installpl_rhel_old "7.5alternate";
	check_package_installpl_rhel_old "7.6";
	check_package_installpl_rhel_old "7.6alternate";
	check_package_installpl_rhel_old "7.7";
	check_package_installpl_rhel_old "7.8";
	check_package_installpl_rhel_old "7.9";
	check_package_installpl_rhel "8.0"; # Without the quote, perl considers
	check_package_installpl_rhel "8.1"; # 8.0 same as 8
	check_package_installpl_rhel "8.2";
	check_package_installpl_rhel "8.3";

	if ($fail_count > 0) {
		say "$me: $fail_count tests failed";
		return 1;
	}
}

main;
