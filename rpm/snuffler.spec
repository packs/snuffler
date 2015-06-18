%define real_name Snuffler

Summary: Tracking and thorough inspection of suspicious systems.
Name: snuffler
Version: 0.2
Release: 1%{?dist}
License: Artistic/GPL
Group: Applications/Internet
Source: snuffler-0.2.tar.gz
Packager: Scott Pack <scott.pack@gmail.com>

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

Requires: snort

%description
Snuffler is an extention to the Snort intrusion detection system that allows for a more
thorough inspection of select systems.

%prep
%setup

%build

%install
%{__rm} -rf %{buildroot}
%{__install} -d -m0755 %{buildroot}%{_sysconfdir}/snuffler
%{__install} -d -m0755 %{buildroot}%{_sysconfdir}/snuffler/rules
%{__install} -d -m0755 %{buildroot}%{_sysconfdir}/sysconfig
%{__install} -d -m0755 %{buildroot}%{_initrddir}
%{__install} -d -m0755 %{buildroot}%{_sbindir}
%{__install} -d -m0755 %{buildroot}%{_var}/log/snuffler

%{__install} -m0644 snuffler.conf %{buildroot}%{_sysconfdir}/snuffler/snuffler.conf
%{__install} -m0644 snuffler.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/snuffler
%{__install} -m0644 suspicious_hosts.bpf %{buildroot}%{_sysconfdir}/snuffler/suspicious_hosts.bpf
%{__install} -m0755 snuffler.init %{buildroot}%{_initrddir}/snufflerd

ln -sf %{_sbindir}/snort %{buildroot}%{_sbindir}/snuffler
ln -sf %{_sysconfdir}/snort/classification.config %{buildroot}%{_sysconfdir}/snuffler/classification.config
ln -sf %{_sysconfdir}/snort/reference.config %{buildroot}%{_sysconfdir}/snuffler/reference.config
ln -sf %{_sysconfdir}/snort/unicode.map %{buildroot}%{_sysconfdir}/snuffler/unicode.map

%clean
%{__rm} -rf %{buildroot}

%post
/sbin/chkconfig --add snufflerd

%files
%defattr(-, root, root, 0755)
%dir %{_sysconfdir}/snuffler
%dir %{_sysconfdir}/snuffler/rules
%dir %{_var}/log/snuffler
%{_sysconfdir}/snuffler/classification.config
%{_sysconfdir}/snuffler/reference.config
%{_sysconfdir}/snuffler/unicode.map
%config(noreplace) %{_sysconfdir}/snuffler/snuffler.conf
%config(noreplace) %{_sysconfdir}/sysconfig/snuffler
%config(noreplace) %{_sysconfdir}/snuffler/suspicious_hosts.bpf
%{_sbindir}/snuffler
%{_initrddir}/snufflerd

%changelog
* Sat Apr 21 2012 Scott Pack <scott.pack@gmail.com> - 0.2
- Initial package.
