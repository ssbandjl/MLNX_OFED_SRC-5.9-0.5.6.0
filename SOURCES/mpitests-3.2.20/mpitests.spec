# $COPYRIGHT$
# 
# Additional copyrights may follow
# 
# $HEADER$
#
############################################################################


#############################################################################
#
# Configuration Options
#
#############################################################################

# Path to mpi home
# type: string 
%{!?path_to_mpihome: %define path_to_mpihome /usr/local/mpi}

# Name for tests home directory
# type: string 
%{!?test_home: %define test_home %{path_to_mpihome}/tests}

# Some compilers can be installed via tarball or RPM (e.g., Intel,
# PGI).  If they're installed via RPM, then rpmbuild's auto-dependency
# generation stuff will work fine.  But if they're installed via
# tarball, then rpmbuild's auto-dependency generation stuff will
# break; complaining that it can't find a bunch of compiler .so files.
# So provide an option to turn this stuff off.
# type: bool (0/1)
%{!?disable_auto_requires: %define disable_auto_requires 0}

# upc package
%{?_with_upc: %define bupc yes}%{!?_with_upc: %define bupc no}

#############################################################################
#
# Configuration Logic
#
#############################################################################
%define _prefix %{path_to_mpihome}
%define _sysconfdir %{path_to_mpihome}/etc
%define _libdir %{path_to_mpihome}/lib
%define _includedir %{path_to_mpihome}/include
# disable debuginfo
%define debug_package %{nil}
# disable broken macro - check_files
%define __check_files %{nil}

#############################################################################
#
# Preamble Section
#
#############################################################################

Summary: MPI Benchmarks and tests
%if "%{bupc}"=="yes"
Name: %{?_name:%{_name}_with_upc}%{!?_name:mpitests_with_upc}
%else
Name: %{?_name:%{_name}}%{!?_name:mpitests}
%endif
Version: 3.2.20
Release: de56b6b
License: BSD
Group: Applications
Source: mpitests-%{version}.tar.gz
Packager: %{?_packager:%{_packager}}%{!?_packager:%{_vendor}}
Vendor: %{?_vendorinfo:%{_vendorinfo}}%{!?_vendorinfo:%{_vendor}}
Distribution: %{?_distribution:%{_distribution}}%{!?_distribution:%{_vendor}}
Prefix: %{_prefix}
Provides: mpitests
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
%if 0%{?suse_version}
BuildRequires: gcc-fortran gcc autoconf automake libtool
%else
BuildRequires: gcc-gfortran gcc autoconf automake libtool
%endif

%if %{disable_auto_requires}
AutoReq: no
%endif

%description
Set of popular MPI benchmarks and tools:
IMB
OSU benchmarks
mpiP
IPM-2.0.6

#############################################################################
#
# Prepatory Section
#
#############################################################################
%prep
%setup -q -n mpitests-%{version}

%build
%{__make} MPIHOME=%{path_to_mpihome} INSTALL_DIR=%{test_home}\
          PATH=${PATH}:%{path_to_mpihome}/bin \
          WITH_UPC=%{bupc} \
          LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:%{path_to_mpihome}/lib:%{path_to_mpihome}/lib64

#############################################################################
#
# Install Section
#
#############################################################################
%install
%{__make} MPIHOME=%{path_to_mpihome} INSTALL_DIR=%{test_home} DESTDIR=$RPM_BUILD_ROOT\
          PATH=${PATH}:%{path_to_mpihome}/bin \
          WITH_UPC=%{bupc} \
          LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:%{path_to_mpihome}/lib:%{path_to_mpihome}/lib64 install

#############################################################################
#
# cLEAN Section
#
#############################################################################
%clean
# We should leave build root for IBED installation
# test "x$RPM_BUILD_ROOT" != "x" && rm -rf $RPM_BUILD_ROOT
cd /tmp

test "x$RPM_BUILD_ROOT" != "x" && rm -rf $RPM_BUILD_ROOT


#############################################################################
#
# Post (Un)Install Section
#
#############################################################################
%post
# Stub

%postun
# Stub

#############################################################################
#
# Files Section
#
#############################################################################


%files 
%defattr(-, root, root)
%{test_home}

#############################################################################
#
# Changelog
#
#############################################################################
%changelog
* Mon Sep  25 2017 Dmitry Kuzmin (dmitryk@mellanox.com)
  updated IPM and IMB
* Thu Jun  19 2013 Igor Usarov (igoru@mellanox.com)
  Add "--with upc" parameter
* Thu Jun  18 2013 Mike Dubman (miked@mellanox.com)
  Add mpiP profiler
* Thu Jun  3 2013 Igor Usarov (igoru@mellanox.com)
  Don't exit if oshcc/upcc is missing
* Wed May 08 2013 Aleksey Senin (alekseys@mellanox.com)
  Added IMB-3.2.4 and OSU benchmark 4.0.1
* Thu Mar 31 2013 Igor Usarov (igoru@mellanox.com)
  Patch for osu-micro-benchmarks-3.9
* Thu Mar  3 2013 Igor Usarov (igoru@mellanox.com)
  OSU benchmarks was updated to osu-micro-benchmarks-3.9
* Thu Feb 10 2013 Igor Usarov (igoru@mellanox.com)
  OSU benchmarks was updated to osu-micro-benchmarks-3.8
* Thu Oct 28 2012 Igor Usarov (igoru@mellanox.com)
  OSU benchmarks was updated to osu-micro-benchmarks-3.7
* Thu Aug 30 2012 Igor Usarov (igoru@mellanox.com)
  OSU benchmarks was updated to osu-micro-benchmarks-3.6
* Mon May  7 2012 Yevgeny Kliteynik (kliteyn@mellanox.com)
  Intel MPI benchmark was updated to IMB-3.2.3 
* Wed Apr  7 2010 Pavel Shamis (pasha@mellanox.co.il)
  disable_auto_requires configuration option was added
  The patch was provided by Todd Rimmer, Qlogic.
* Sun Nov 15 2009 Pavel Shamis (pasha@mellanox.co.il)
  Intel MPI benchmark IMB-3.1 was updated to IMB-3.2
  OSU MPI benchmark version 3.0 was updated to 3.1.1
* Thu Oct  2 2008 Pavel Shamis (pasha@mellanox.co.il)
  Intel MPI benchmark IMB-3.0 was updated to IMB-3.1
* Thu Nov 22 2006 Pavel Shamis (pasha@mellanox.co.il)
  Intel MPI benchmark IMB-2.3 was updated to IMB-3.0
  OSU benchmarks were updated from 2.0 to 3.0
  mpitest package version updated from 2.0 to 3.0
  removing old code from spec
* Tue Jun 20 2006 Pavel Shamis (pasha@mellanox.co.il)
  Pallas benchmark 2.2.1 was replaced with Intel MPI benchmark IMB-2.3
  Presta 1.2 was updated to 1.4.0
  OSU benchmarks were updated from 1.0 to 2.0
  mpitest package version updated from 1.0 to 2.0
* Wed Apr 01 2006 Pavel Shamis (pasha@mellanox.co.il)
  Spec file for mpitests was created.
