# This is a version of iproute2.spec sent to upstream with mlnx customization.

%global _prefix /opt/mellanox/iproute2
%global _exec_prefix %{_prefix}
%global package_name mlnx-iproute2
%global package_version 6.0.0
%global configs_under_prefix 1
%global netns_package_name netns-mlnx

%bcond_with bluefield

# Specify mandatory rpmbuild parameter package_version, like:
#   rpmbuild -d'package_version 5.1.0'
#
# Other optional parameters are: package_name, netns_package_name
# and configs_under_prefix.

%global debug_package %{nil}

%{!?package_name: %global package_name iproute2}
%{!?netns_package_name: %global netns_package_name netns}

%if 0%{?configs_under_prefix:1}
	%global config_dir %{_prefix}%{_sysconfdir}
	%global netns_config_dir %{config_dir}/netns
%else
	%global config_dir %{_sysconfdir}/mlnx-iproute2
	%global netns_config_dir %{_sysconfdir}/%{netns_package_name}
%endif

Summary:	Advanced IP routing and network device configuration tools
Name:		mlnx-iproute2
Version:	6.0.0
Release:	1
License:	GPL
Group:		Networking/Admin
Source0:	http://www.kernel.org/pub/linux/utils/net/iproute2/%{name}-%{version}.tar.gz
URL:		http://www.linuxfoundation.org/collaborate/workgroups/networking/iproute2
BuildRequires:	bison
BuildRequires:	flex
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

%description
The iproute package contains networking utilities (like ip and tc)
designed to use the advanced networking capabilities of the Linux kernel.

%package -n libnetlink-devel
Summary:	Library for the netlink interface
Group:		Development/Libraries

%description -n libnetlink-devel
This library provides an interface for kernel-user netlink interface.

%prep
%setup -q

%build
%if %{with bluefield}
export MLNX_OFED_BLUEFIELD_BUILD=1
%endif
./configure
%{__make} \
	CC="%{__cc}" \
	PREFIX="%{_prefix}" \
	LIBDIR="%{_libdir}" \
	SBINDIR="%{_sbindir}" \
	CONFDIR="%{config_dir}" \
	NETNS_RUN_DIR="%{_var}/run/%{netns_package_name}" \
	NETNS_ETC_DIR="%{netns_config_dir}" \

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_includedir},%{_libdir},%{_sbindir}}

%{__make} install \
	DESTDIR=$RPM_BUILD_ROOT	\
	PREFIX="%{_prefix}" \
	LIBDIR="%{_libdir}" \
	SBINDIR="%{_sbindir}" \
	CONFDIR="%{config_dir}" \
	NETNS_RUN_DIR="%{_var}/run/%{netns_package_name}" \
	NETNS_ETC_DIR="%{netns_config_subdir}" \

install lib/libnetlink.a $RPM_BUILD_ROOT%{_libdir}
install include/libnetlink.h $RPM_BUILD_ROOT%{_includedir}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc README README.devel doc/actions
%config(noreplace) %verify(not md5 mtime size) %{config_dir}/*
%{_prefix}/include/*
%{_prefix}/share/*
%{_libdir}/*
%{_sbindir}/*
