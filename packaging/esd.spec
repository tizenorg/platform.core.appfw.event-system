Name:       esd
Summary:    Event system daemon
Version:    0.0.1
Release:    1
Group:      Application Framework/Service
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    esd.service
BuildRequires:  cmake
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(appsvc)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(pkgmgr)
BuildRequires:  pkgconfig(eventsystem)
BuildRequires:  pkgconfig(vconf)

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Event System Daemon

%package devel
Summary:    Event system daemon (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Event system Daemon (devel)

%prep
%setup -q

%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"


%cmake .
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_unitdir}/default.target.wants
install -m 0644 %SOURCE1 %{buildroot}%{_unitdir}/esd.service
ln -sf ../esd.service %{buildroot}%{_unitdir}/default.target.wants/esd.service
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest esd.manifest
%config %{_sysconfdir}/dbus-1/system.d/eventsystem.conf
%defattr(-,root,root,-)
%{_bindir}/esd
%{_unitdir}/esd.service
%{_unitdir}/default.target.wants/esd.service
/usr/share/license/%{name}

%files devel
%defattr(-,root,root,-)
