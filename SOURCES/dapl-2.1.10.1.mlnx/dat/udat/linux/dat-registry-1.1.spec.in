# Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    in the file LICENSE.txt in the root directory. The license is also
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is in the file
#    LICENSE2.txt in the root directory. The license is also available from
#    the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a 
#    copy of which is in the file LICENSE3.txt in the root directory. The 
#    license is also available from the Open Source Initiative, see
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
# DAT Registry RPM SPEC file
#

%define make_dir 	udat

# Defining these to nothing overrides the stupid automatic RH9
# functionality of making "debuginfo" RPMs.

%define debug_package %{nil}
%define __check_files %{nil}
%define dual_arch 0

%ifarch x86_64
%define dual_arch 1
%endif

#
# Preamble
#

Summary:      	DAT Registry
Name:         	dat-registry
Version:      	1.1
Release:        0	
Vendor:      	Dat Collaborative
Exclusiveos:  	Linux
License:      	BSD and CPL
Group:        	System/Libraries
Source:		%{name}-%{version}.tgz
URL:          	http://www.datcollaborative.org
BuildRoot:      /var/tmp/%{name}-%{version}

%description
This package contains the DAT Registry.

#
# Preparation
#

%prep
%setup -n dat

#
# Build
#

%build
cd %{make_dir}
make

#
# Install
#

%install
if [ -d %{buildroot} ]; then rm -rf %{buildroot}; fi
mkdir -p %{buildroot}/usr/include/dat
mkdir -p %{buildroot}/usr/lib
%if %{dual_arch}
mkdir -p %{buildroot}/usr/lib64
%endif
cd %{make_dir}
make install PREFIX=%{buildroot}

#
# Files
#

%files
%defattr(-,root,root)
/usr/include/dat
/usr/lib/libdat.so
/usr/lib/libdat.a
%if %{dual_arch}
/usr/lib64/libdat.so
/usr/lib64/libdat.a
%endif
