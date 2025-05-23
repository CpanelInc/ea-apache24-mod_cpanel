%global ns_name ea-apache24
%global module_name mod_cpanel

# Doing release_prefix this way for Release allows for OBS-proof versioning, See EA-4556 for more details
%define release_prefix 3

Name:           %{ns_name}-%{module_name}
Version:        1.5
Release:        %{release_prefix}%{?dist}.cpanel
Summary:        EOL Perform cPanel specific checks when handling requests

Vendor:         cPanel, Inc
License:        cPanel
URL: https://docs.cpanel.net/ea4/apache/apache-module-cpanel/
Source0:        %{module_name}.c
Source1:        %{module_name}.conf
Source2:        %{module_name}-debug.conf

BuildRequires:  ea-apache24-devel
Requires:       ea-apache24-mmn = %{_httpd_mmn}
Requires(pre):  ea-apache24

%description
apache24-mod_cpanel has reached End of Life.

This module performs cPanel-specific checks when handling requests, such as
ensuring that requests for suspended users/websites get redirected to the
suspendedpage, etc.

%package -n     %{ns_name}-%{module_name}-debug
Summary:        EOL Perform cPanel specific checks when handling requests (debug)
Conflicts:      %{ns_name}-%{module_name}

%description -n %{ns_name}-%{module_name}-debug
apache24-mod_cpanel has reached End of Life.

This package contains the debug version of %{module_name}

%prep
# TODO: Should probably have a separate repo for the module,
# and store a static "package" of it in the rpm repo
cp -p %SOURCE0 .

%build
%{_httpd_apxs} -c %{module_name}.c
%{_httpd_apxs} -D CPANEL_DEBUG=1 -o %{module_name}-debug.so -c %{module_name}.c

mv .libs/%{module_name}.so .
mv .libs/%{module_name}-debug.so .

%{__strip} -g %{module_name}.so

%install
mkdir -p %{buildroot}%{_httpd_moddir}
install %{module_name}.so %{buildroot}%{_httpd_moddir}/
install %{module_name}-debug.so %{buildroot}%{_httpd_moddir}/
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/apache2/conf.modules.d/
install -p %SOURCE1 $RPM_BUILD_ROOT%{_sysconfdir}/apache2/conf.modules.d/%{module_name}.conf
install -p %SOURCE2 $RPM_BUILD_ROOT%{_sysconfdir}/apache2/conf.modules.d/%{module_name}-debug.conf

%clean
rm -rf %{buildroot}

%files
%defattr(0640,root,root,0755)
%attr(755,root,root)%{_httpd_moddir}/%{module_name}.so
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/apache2/conf.modules.d/%{module_name}.conf

%files -n %{ns_name}-%{module_name}-debug
%defattr(0640,root,root,0755)
%attr(755,root,root)%{_httpd_moddir}/%{module_name}-debug.so
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/apache2/conf.modules.d/%{module_name}-debug.conf

%changelog
* Mon May 05 2025 Dan Muey <daniel.muey@webpros.com> - 1.5-3
- ZC-12813: Add Almalinux_10 to DISABLE_BUILD in Makefile

* Tue Mar 26 2024 Dan Muey <dan@cpanel.net> - 1.5-2
- ZC-11717: Mark ea-apache24-mod_cpanel as EOL

* Tue Sep 18 2018 Tim Mullin <tim@cpanel.net> - 1.5-1
- EA-7386: Eliminate warning when suspended account directory does not exist.

* Mon Sep 17 2018 Rishwanth Yeddula <rish@cpanel.net> - 1.4-1
- EA-7821: Don't strip symbools from the debug package.
- EA-7822: Handle edge cases where request_rec->filename == NULL.
    * Some modules that hook into the map_to_storage process (eg. mod_pagespeed),
      can alter the request_rec in an unexpected manner, that resulted
      result in a segfault.

* Tue Aug 14 2018 Rishwanth Yeddula <rish@cpanel.net> - 1.3-1
- ZC-3819: Avoid thread deadlocks on certain threaded MPM systems.

* Fri Jun 29 2018 Rishwanth Yeddula <rish@cpanel.net> - 1.2-1
- EA-7639: Ensure the suspended users check is more accurate.

* Wed Apr 18 2018 Rishwanth Yeddula <rish@cpanel.net> - 1.1-1
- EA-7387: Avoid segfaults when used with threaded MPMs.

* Tue Mar 20 2018 Rishwanth Yeddula <rish@cpanel.net> - 1.0-1
- EA-7191: Initial implementation of mod_cpanel:
    * Handle requests to suspended users in apache without requiring
      an include file to be generated on the product side.

