Summary: N2N peer-to-peer virtual private network system.
Name: n2n
Version: 2.1.0
Release: 1
License: GPLv3
Vendor: ntop.org
Group: None
URL: http://www.ntop.org/n2n
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
N2N is a peer-to-peer virtual private network system. N2N uses the universal
TUNTAP interface to create TAP network interfaces to an encrypted virtual
LAN. Members of a community share encryption keys which allow exchange of
data. The supernode is used for peer discovery and initial packet relay before
direct peer-to-peer exchange is established.  Once direct packet exchange is
established, the supernode is not required.

N2N-2 introduces additional security features and multiple supernodes.

%prep

%setup -q

echo -e "\n *** Building ${RPM_PACKAGE_NAME}-${RPM_PACKAGE_VERSION}-${RPM_PACKAGE_RELEASE} ***\n"

%build
make

%install
make PREFIX=${RPM_BUILD_ROOT}/usr install

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
     /usr/sbin/supernode
     /usr/sbin/edge
%doc /usr/share/man/man1/supernode.1.gz
%doc /usr/share/man/man8/edge.8.gz
%doc /usr/share/man/man7/n2n_v2.7.gz


%changelog
* Fri Oct 30 2009 Richard Andrews <andrews@ntop.org> -
- First beta for n2n-2
* Sat May  3 2008 Richard Andrews <andrews@ntop.org> - 
- Initial build.

