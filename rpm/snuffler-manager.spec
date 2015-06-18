%define perl_vendorlib %(eval "`%{__perl} -V:privlib`"; echo $privlib)
%define perl_vendorarch %(eval "`%{__perl} -V:installvendorarch`"; echo $installvendorarch)

Summary: Tracking and IP database management tools for Snuffler
Name: snuffler-manager
Version: 0.3
Release: 2%{?dist}
License: Freeware/BY-NC-ND
Group: Applications/Internet
Source: %{name}-%{version}.tar.gz
Packager: Scott Pack <scott.pack@gmail.com>
BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

Requires: perl(Net::IP), perl(DBD::SQLite)

%description
Snuffler Manager is an addon to the Snuffler snort extention that provides a mechanism for
automating the snuffler BPF files. It provides the functionality to add, delete, and set
autoexpirations hosts to a database, then generate a BPF file based on the database entries.

%prep
%setup

%build

%install
%{__rm} -rf %{buildroot}
%{__install} -d -m0755 %{buildroot}%{_usr}/local/sbin/
%{__install} -d -m0755 %{buildroot}%{perl_vendorlib}/Net/

%{__install} -m0755 snuffler_managehost.pl %{buildroot}%{_usr}/local/sbin/snuffler_managehost.pl
%{__install} -m0644 Snuffler.pm %{buildroot}%{perl_vendorlib}/Net/Snuffler.pm

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%{_usr}/local/sbin/snuffler_managehost.pl
%{perl_vendorlib}/Net/Snuffler.pm

%changelog
* Wed Oct 31 2012 Scott Pack <scott.pack@gmail.com> - 0.3
- Version bump
* Sat Aug  1 2012 Scott Pack <scott.pack@gmail.com> - 0.1
- Initial package.
