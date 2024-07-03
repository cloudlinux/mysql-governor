%define g_version   1.2
%define g_release   113
%define g_key_library 13

%if %{undefined _unitdir}
%define _unitdir /usr/lib/systemd/system
%endif

%define cl_venv_path /opt/cloudlinux/venv
%define __python %{cl_venv_path}/bin/python3
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')


Name: governor-mysql
Version: %{g_version}
Release: %{g_release}%{?dist}.cloudlinux
Summary: DB control utilities
License: GPLv2
URL: http://cloudlinux.com
Group: System Environment/Base
Source0: %{name}-%{version}.tar.bz2
Requires: glib2
Requires: ncurses
Requires: lve-utils >= 6.5.2-1
Requires: lve-stats >= 0.9-27
Requires: yum-utils
Requires: tmpwatch
Requires: wget
Requires: libxml2
Requires: alt-python27-cllib >= 3.3.3-1
Requires: cloudlinux-venv
Requires(preun): /sbin/chkconfig
BuildRequires: cmake
BuildRequires: ncurses-devel
BuildRequires: glib2-devel
BuildRequires: autoconf
BuildRequires: tar
BuildRequires: libxml2-devel
BuildRequires: pcre-devel
BuildRequires: patch
BuildRequires: alt-python27-cllib >= 3.3.3-1
BuildRequires: cloudlinux-venv
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
BuildRequires: systemd
BuildRequires: systemd-devel
%endif
%if 0%{?rhel} == 7
BuildRequires: mariadb-libs
BuildRequires: mariadb
%else
BuildRequires: mysql-libs
BuildRequires: mysql
%endif
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Conflicts: db-governor
Conflicts: db-governor-mysql
Conflicts: db_governor
Conflicts: cpanel-db-governor
AutoReq: 0

%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
Requires: systemd-units
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
Requires(post): systemd-sysv
%else
Requires(preun): initscripts
Requires(postun): initscripts
%endif

%description
This package provides dbtop, db_governor utilities.

%package devel
Summary: Development header files for db_governor client applications
Group: System Environment/Base

%description devel
This package contains the development header files necessary
to develop db_governor client applications.

%prep

%setup -q

%build
export PYTHONINTERPRETER=%{__python}

echo -e "#ifndef VERSION_H_\n#define VERSION_H_\n#define GOVERNOR_CUR_VER \"%{g_version}-%{g_release}\"\n#define GOVERNOR_OS_CL%{?rhel} 1\n#endif\n" > src/version.h

mkdir build_clean
pushd build_clean
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
cmake .. -DSYSTEMD_FLAG:BOOL=1 -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON
%else
cmake ..
%endif
make
popd

pushd install
autoconf
%configure
make
popd

mkdir build_test
pushd build_test
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
cmake .. -DSYSTEMD_FLAG:BOOL=1
%else
cmake ..
%endif
make
popd

%install
%{__rm} -rf $RPM_BUILD_ROOT

if [ -e autoconf ]; then
# Yuck. We're using autoconf 2.1x.
  export PATH=.:$PATH 
fi

cd install
#make DESTDIR=$RPM_BUILD_ROOT install
cd -
mkdir -p $RPM_BUILD_ROOT/var/lve/dbgovernor/
mkdir -p $RPM_BUILD_ROOT/var/lve/dbgovernor-store/

mkdir -p $RPM_BUILD_ROOT%{_sbindir}/
mkdir -p $RPM_BUILD_ROOT%{_libdir}/
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/container/
mkdir -p $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/
mkdir -p $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/modules
mkdir -p $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts
mkdir -p $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/utils
mkdir -p $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/tmp
mkdir -p $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/storage
mkdir -p $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/history
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
# install systemd unit files and scripts for handling server startup
mkdir -p ${RPM_BUILD_ROOT}%{_unitdir}
install -m 644 db_governor.service ${RPM_BUILD_ROOT}%{_unitdir}/
install -m 644 governor_sentry_daemon.service ${RPM_BUILD_ROOT}%{_unitdir}/
install -m 644 var-lve-dbgovernor\\x2dshm.mount ${RPM_BUILD_ROOT}%{_unitdir}/
%else
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/rc.d/init.d/
install -D -m 755 script/db_governor $RPM_BUILD_ROOT%{_sysconfdir}/rc.d/init.d/
%endif

install -D -m 755 build_clean/bin/db_governor $RPM_BUILD_ROOT%{_sbindir}/
install -D -m 755 build_clean/bin/dbtop $RPM_BUILD_ROOT%{_sbindir}/
install -D -m 755 build_clean/bin/mysql_unfreeze $RPM_BUILD_ROOT%{_sbindir}/
install -D -m 755 build_clean/bin/dbctl $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/utils/dbctl_orig
install -D -m 755 install/dbctl $RPM_BUILD_ROOT%{_sbindir}/dbctl
install -D -m 600 db-governor.xml $RPM_BUILD_ROOT%{_sysconfdir}/container/mysql-governor.xml
install -D -m 664 governor_package_limit.json $RPM_BUILD_ROOT%{_sysconfdir}/container/governor_package_limit.json
install -D -m 755 build_clean/lib/libgovernor.so $RPM_BUILD_ROOT%{_libdir}/libgovernor.so.%{version}
ln -fs libgovernor.so.%{version} $RPM_BUILD_ROOT%{_libdir}/libgovernor.so

install -D -m 755 build_test/bin/db_governor $RPM_BUILD_ROOT%{_sbindir}/db_governor_test
install -D -m 755 build_test/lib/libgovernor.so $RPM_BUILD_ROOT%{_libdir}/libgov_test.so.%{version}

#install utility
install -D -m 755 install/db-select-mysql $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/db-select-mysql
install -D -m 755 install/mysqlgovernor.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/mysqlgovernor.py
install -D -m 755 install/governor_package_limitting.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/governor_package_limitting.py
install -D -m 755 install/creates_individual_limits_vector_list.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/creates_individual_limits_vector_list.py

install -D -m 644 install/cl-mysql.repo.default $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/cl-mysql.repo.default
install -D -m 644 install/utilities.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/utilities.py
install -D -m 644 install/modules/__init__.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/modules/__init__.py
install -D -m 644 install/modules/base.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/modules/base.py
install -D -m 644 install/modules/cpanel.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/modules/cpanel.py
install -D -m 644 install/modules/da.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/modules/da.py
install -D -m 644 install/modules/plesk.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/modules/plesk.py
install -D -m 644 install/modules/iworx.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/modules/iworx.py
install -D -m 644 install/modules/ispmanager.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/modules/ispmanager.py
install -D -m 644 install/modules/storage.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/modules/storage.py

install -D -m 755 install/scripts/chek_mysql_rpms_local $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/chek_mysql_rpms_local
install -D -m 755 install/scripts/cpanel-delete-hooks $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/cpanel-delete-hooks
install -D -m 755 install/scripts/cpanel-install-hooks $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/cpanel-install-hooks
install -D -m 755 install/scripts/cpanel-common-lve $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/cpanel-common-lve
install -D -m 755 install/scripts/cpanel_map_rebuilder $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/cpanel_map_rebuilder
install -D -m 755 install/scripts/dbgovernor_map $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/dbgovernor_map
install -D -m 755 install/scripts/dbgovernor_map.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/dbgovernor_map.py
install -D -m 755 install/scripts/dbgovernor_map_plesk.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/dbgovernor_map_plesk.py
install -D -m 755 install/scripts/sentry_daemon.py $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/sentry_daemon.py
install -D -m 755 install/scripts/detect-cpanel-mysql-version.pm $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/detect-cpanel-mysql-version.pm
install -D -m 755 install/scripts/cpanel-mysql-url-detect.pm $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/cpanel-mysql-url-detect.pm
install -D -m 755 install/scripts/set_cpanel_mysql_version.pm $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/set_cpanel_mysql_version.pm
install -D -m 755 install/scripts/mysql_hook $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/mysql_hook
install -D -m 755 install/scripts/map_hook $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/map_hook
install -D -m 755 install/scripts/sync_hook $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/scripts/sync_hook

install -D -m 644 logrotate/mysql-governor $RPM_BUILD_ROOT/etc/logrotate.d/mysql-governor
install -D -m 644 logrotate/mysql-governor-slow $RPM_BUILD_ROOT/etc/logrotate.d/mysql-governor-slow
install -D -m 644 logrotate/mysql-governor-mysqld $RPM_BUILD_ROOT/etc/logrotate.d/mysql-governor-mysqld
install -D -m 644 install/utils/cloudlinux.versions $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/utils/cloudlinux.versions
install -D -m 644 install/utils/dbgovernor $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/utils/db_governor
install -D -m 600 install/list_problem_files.txt $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/

install -D -m 755 install/utils/mysql_export $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/utils/mysql_export

install -D -m 755 install/cpanel/upgrade-mysql-disabler.sh $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/cpanel/upgrade-mysql-disabler.sh
ln -s ../scripts/dbgovernor_map $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/utils/dbgovernor_map

#install cron utility
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/cron.d/
install -D -m 644 cron/lvedbgovernor-utils-cron $RPM_BUILD_ROOT%{_sysconfdir}/cron.d/

touch $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/tmp/INFO
echo "CloudLinux" > $RPM_BUILD_ROOT/usr/share/lve/dbgovernor/tmp/INFO

mkdir -p $RPM_BUILD_ROOT%{_includedir}/
install -D -m 644 src/governor_write_data.h $RPM_BUILD_ROOT%{_includedir}/libgovernor.h

%check
ls -l /usr/bin/mysql
/usr/bin/mysql -V
echo "****Start unittests for python code"
PYTHONPATH=install:install/scripts:. %{cl_venv_path}/bin/pytest tests/py/

%pre
/sbin/service db_governor stop > /dev/null 2>&1 || :
pkill db_governor || :

#Check if libgovernor.so will be changed on package action
#if install just save KEY
#if this KEY will change - need to stop mysql before governor installation
gKEY=`echo -n "%{g_key_library}"`
if [ $1 -eq 1 ] ; then
    touch /etc/container/dbgovernor-libcheck
    echo "$gKEY" > /etc/container/dbgovernor-libcheck
fi
#if update check KEY
if [ $1 -eq 2 ] ; then
   if [ -e "/etc/container/dbgovernor-libcheck" ]; then
        rKEY=`cat /etc/container/dbgovernor-libcheck | tr -d '\n'`
        if [ "$rKEY" != "$gKEY" ]; then
            touch /etc/container/dbgovernor-libcheck
            echo "U" > /etc/container/dbgovernor-libcheck
            echo "Stop MySQL for safe installation"
            if [ -e /usr/lib/systemd/system/mysql.service -a -e /usr/bin/systemctl ]; then
                systemctl stop mysql.service
            elif [ -e /usr/lib/systemd/system/mysqld.service -a -e /usr/bin/systemctl ]; then
                systemctl stop mysqld.service
            elif [ -e /usr/lib/systemd/system/mariadb.service -a -e /usr/bin/systemctl ]; then
                systemctl stop mariadb.service
            elif [ -e /etc/init.d/mysql ]; then
                /etc/init.d/mysql stop
            elif [ -e /etc/init.d/mysqld ]; then
                /etc/init.d/mysqld stop
            fi
        fi
   else
        touch /etc/container/dbgovernor-libcheck
        echo "U" > /etc/container/dbgovernor-libcheck
        echo "Stop MySQL for safe installation"
        if [ -e /usr/lib/systemd/system/mysql.service -a -e /usr/bin/systemctl ]; then
            systemctl stop mysql.service
        elif [ -e /usr/lib/systemd/system/mysqld.service -a -e /usr/bin/systemctl ]; then
            systemctl stop mysqld.service
        elif [ -e /usr/lib/systemd/system/mariadb.service -a -e /usr/bin/systemctl ]; then
            systemctl stop mariadb.service
        elif [ -e /etc/init.d/mysql ]; then
            /etc/init.d/mysql stop
        elif [ -e /etc/init.d/mysqld ]; then
            /etc/init.d/mysqld stop
        fi
   fi
fi

%post
if [ $1 -gt 0 ]; then
    # Initial installation or upgrade
    [ -d /var/lve/dbgovernor-shm ] || mkdir -p /var/lve/dbgovernor-shm
    mount | grep -q /var/lve/dbgovernor-shm || mount -t tmpfs none /var/lve/dbgovernor-shm -o 'rw,nosuid,nodev'
fi

if [ $1 -gt 0 ] ; then
    if [ -e "/usr/share/lve/dbgovernor/mysqlgovernor.py" ]; then
        /usr/share/lve/dbgovernor/mysqlgovernor.py --fs-suid
    fi
fi

%if 0%{?rhel} >= 7
if [ $1 -gt 0 ]; then
    # Initial installation or upgrade

    # Remove governor dropin introduced in MYSQL-853 because
    # it does not need anymore after reverting
    # and also can cause the troubles with libjemalloc
    if [[ ! -a /usr/share/lve/dbgovernor/CLOS-2049 ]]; then
        dropin_found="N"
        for f in "/etc/systemd/system/mariadb.service.d/governor.conf" \
                 "/etc/systemd/system/mysqld.service.d/governor.conf" \
                 "/etc/systemd/system/mysql.service.d/governor.conf" \
                 "/etc/systemd/system/mariadb.service.d/gov.conf" \
                 "/etc/systemd/system/mysqld.service.d/gov.conf"
        do
            if [[ -a "$f" ]]; then
                rm $f >/dev/null 2>&1 || :
                dropin_found="Y"
            fi
        done
        if [[ "$dropin_found" == "Y" ]]; then
            systemctl daemon-reload >/dev/null 2>&1 || :
        fi
        touch /usr/share/lve/dbgovernor/CLOS-2049
    fi
fi
if [ $1 = 1 ]; then
    # Ensure autostart for db_governor service (on install, not upgrade)
    systemctl enable db_governor >/dev/null 2>&1 || :
    systemctl enable governor_sentry_daemon >/dev/null 2>&1 || :
fi
%else
if [ $1 = 1 ]; then
    /sbin/chkconfig --add db_governor
    /sbin/chkconfig --level 35 db_governor on
fi
%endif

if [ $1 -gt 0 ]; then
    # Initial installation or upgrade
    [ -e /dev/shm/governor_bad_users_list ] && rm /dev/shm/governor_bad_users_list 2>&1 >/dev/null || :
fi

#check if in signal file saved U, than need to start mysql
gKEY=`echo -n "%{g_key_library}"`
if [ -e "/etc/container/dbgovernor-libcheck" ]; then
    rKEY=`cat /etc/container/dbgovernor-libcheck | tr -d '\n'`
        if [ "$rKEY" == "U" ]; then
            echo "Start MySQL for safe installation"
            if [ -e /usr/lib/systemd/system/mysql.service -a -e /usr/bin/systemctl ]; then
                systemctl status mysql.service
                if [ "$?" != "0" ]; then
                    systemctl start mysql.service
                else
                    echo "MySQL already started"
                fi
            elif [ -e /usr/lib/systemd/system/mysqld.service -a -e /usr/bin/systemctl ]; then
                systemctl status mysqld.service
                if [ "$?" != "0" ]; then
                    systemctl start mysqld.service
                else
                    echo "MySQL already started"
                fi
            elif [ -e /usr/lib/systemd/system/mariadb.service -a -e /usr/bin/systemctl ]; then
                systemctl status mariadb.service
                if [ "$?" != "0" ]; then
                    systemctl start mariadb.service
                else
                    echo "MySQL already started"
                fi
            elif [ -e /etc/init.d/mysql ]; then
                /etc/init.d/mysql status
                if [ "$?" != "0" ]; then
                    /etc/init.d/mysql start
                else
                    echo "MySQL already started"
                fi
            elif [ -e /etc/init.d/mysqld ]; then
                /etc/init.d/mysqld status
                if [ "$?" != "0" ]; then
                    /etc/init.d/mysqld start
                else
                    echo "MySQL already started"
                fi
            fi
            echo "$gKEY" > /etc/container/dbgovernor-libcheck
        fi
fi

# Governor watchdog was introduced by CLOS-2385 in governor 1.2-111
# but reverted by CLOS-2705 in governor 1.2-112
# So let's remove cron job possibly created by 1.2-111
if [ -e /etc/cron.d/dbgovernor_watchdog_cron ]; then
    rm /etc/cron.d/dbgovernor_watchdog_cron
fi

if [ -e "/usr/share/lve/dbgovernor/sentry_dsn" ]; then
    rm -f /usr/share/lve/dbgovernor/sentry_dsn
fi

%preun
%if 0%{?rhel} >= 7
if [ $1 -eq 0 ]; then
    # Package removal, not upgrade
    systemctl --no-reload disable db_governor.service >/dev/null 2>&1 || :
    systemctl --no-reload disable governor_sentry_daemon.service >/dev/null 2>&1 || :
    systemctl stop db_governor.service >/dev/null 2>&1 || :
fi
%else
if [ $1 -eq 0 ]; then
    /sbin/service db_governor stop > /dev/null 2>&1
    /sbin/chkconfig --del db_governor
fi
%endif
if [ $1 -eq 1 -o $1 -eq 0 ] ; then
 if [ -e /var/run/mysql-governor-config.xml ]; then
    rm -f /var/run/mysql-governor-config.xml
 fi
fi

# Governor watchdog was introduced by CLOS-2385 in governor 1.2-111
# but reverted by CLOS-2705 in governor 1.2-112
# So let's remove cron job possibly created by 1.2-111
if [ -e "/etc/cron.d/dbgovernor_watchdog_cron" ]; then
    rm -f /etc/cron.d/dbgovernor_watchdog_cron
fi

if [ -e "/usr/share/lve/dbgovernor/sentry_dsn" ]; then
    rm -f /usr/share/lve/dbgovernor/sentry_dsn
fi

%postun
%if 0%{?rhel} >= 7
if [ $1 -eq 0 ]; then
    # Package removal, not upgrade
    systemctl daemon-reload >/dev/null 2>&1 || :
fi
%endif

%posttrans

/sbin/ldconfig
rm -rf /%{_libdir}/liblve.so.1
ln -s /%{_libdir}/liblve.so.0.9.0 /%{_libdir}/liblve.so.1
/sbin/ldconfig

if [ -e /usr/share/lve/dbgovernor/mysqlgovernor.py ]; then
    /usr/share/lve/dbgovernor/mysqlgovernor.py --correct-cloud-version
fi


/sbin/ldconfig

if [ -e /usr/share/lve/dbgovernor/mysqlgovernor.py ]; then
    if [ ! -e /usr/share/lve/dbgovernor/MYSQLG-178 ]; then
        /usr/share/lve/dbgovernor/mysqlgovernor.py --fix-config
        touch /usr/share/lve/dbgovernor/MYSQLG-178
    fi
fi

/usr/share/lve/dbgovernor/mysqlgovernor.py --update-cpanel-hooks

%if 0%{?rhel} >= 7
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
/bin/systemctl enable var-lve-dbgovernor\\x2dshm.mount >/dev/null 2>&1 || :
/bin/systemctl restart db_governor.service >/dev/null 2>&1 || :
%else
/etc/init.d/db_governor restart
%endif

if [ ! -e /usr/share/lve/dbgovernor/vectors_are_already_present ]; then
    /usr/share/lve/dbgovernor/creates_individual_limits_vector_list.py
    touch /usr/share/lve/dbgovernor/vectors_are_already_present
fi

echo "Run script: /usr/share/lve/dbgovernor/mysqlgovernor.py --install"
echo "!!!Before making any changing with database make sure that you have reserve copy of users data!!!"
echo "Instruction: how to create whole database backup - http://docs.cloudlinux.com/index.html?backing_up_mysql.html"

%triggerpostun -- governor-mysql < 1.2
echo "Attempt to fix cPanel hooks..."
if [ -e /usr/share/lve/dbgovernor/mysqlgovernor.py ]; then
    /usr/share/lve/dbgovernor/mysqlgovernor.py --fix-cpanel-hooks
fi

%triggerin -- cl-MySQL55-client, cl-MySQL56-client, cl-MySQL57-client, cl-MySQL80-client, cl-MariaDB55, cl-MariaDB100, cl-MariaDB101, cl-MariaDB102, cl-MariaDB103, cl-MariaDB104, cl-MariaDB105, cl-Percona56-client, cl-MariaDB106, mysql-community-client, mariadb, Percona-Server-client-56
if [ -e /usr/sbin/cagefsctl ]; then
    if /usr/sbin/cagefsctl --check-cagefs-initialized ; then
        /usr/sbin/cagefsctl --wait-lock --force-update
    fi
fi

%files
%defattr(-,root,root)
%doc LICENSE.TXT

%config /etc/logrotate.d/*
%{_sbindir}/db_governor
%{_sbindir}/db_governor_test
%{_sbindir}/dbtop
%{_sbindir}/mysql_unfreeze
%{_sbindir}/dbctl
%{_libdir}/libgovernor.so
%{_libdir}/libgovernor.so.%{version}
%{_libdir}/libgov_test.so.%{version}
%config(noreplace) %{_sysconfdir}/container/mysql-governor.xml
%config(noreplace) %{_sysconfdir}/container/governor_package_limit.json
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
%{_unitdir}/db_governor.service
%{_unitdir}/governor_sentry_daemon.service
%{_unitdir}/var-lve-dbgovernor\x2dshm.mount
%else
%{_sysconfdir}/rc.d/init.d/*
%endif
/usr/share/lve/dbgovernor/*
%{_sysconfdir}/cron.d/lvedbgovernor-utils-cron
/var/lve/dbgovernor
/var/lve/dbgovernor-store
%dir %attr(0700, -, -) /usr/share/lve/dbgovernor/storage

%files devel
%{_includedir}/libgovernor.h

%changelog
* Tue Jun 11 2024 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-113
- CLOS-2653: Deprecated outdated mysql/mariadb/percona versions

* Tue Jun 04 2024 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-112
- CLOS-2705: Reverted adding of watchdog monitoring utility

* Thu May 13 2024 Sandro Kalatozishvili <skalatozishvili@cloudlinux.com> Timur Averianov <taverianov@cloudlinux.com> 1.2-111
- CLOS-2645: Corrected MariaDB version detection logic for DA config
- CLOS-2593, CLOS-2613: Added extended logging
- CLOS-2385: Added watchdog monitoring utility to governor package
- CLOS-2386: Implemented external Sentry logging mechanism
- CLOS-2594, CLOS-2641: Implemented logging from MySQL and uniform logging

* Tue Apr 30 2024 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-110
- CLOS-2322: Fixed issue with not applying limits after Governor service restart
- CLOS-2535: Governor threads logging added

* Thu Apr 18 2024 Alexandr Demeshko <ademeshko@cloudlinux.com> Timur Averianov <taverianov@cloudlinux.com> 1.2-109
- CLOS-2572: LVE busy in MySQL processes issue fixed
- CLOS-2506: Fixed MySQL community downloads URL

* Mon Mar 18 2024 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-108
- CLOS-2473: Implied --yes option in non-tty mode

* Tue Mar 05 2024 Dmitry Shibut <dshibut@cloudlinux.com> Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-107
- CLOS-2319: EOLed cl-MariaDB 10.3 removal result to server down
- CLOS-2471: Fixed wizzard installation

* Tue Feb 27 2024 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-106
- CLOS-2373: Backup confirmation added to governor script

* Tue Feb 20 2024 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-105
- CLOS-2322: Fixed DB limits not applying to users after a MySQL Governor service restart
- CLOS-2418: MySQL 8.0 community edition repo url changed

* Thu Feb 01 2024 Dmitry Shibut <dshibut@cloudlinux.com> 1.2-104
- CLOS-2253: Optimize governor_package_limitting.py for case 1 user - 1 package

* Tue Dec 12 2023 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-103
- CLOS-2276: MariaDB 10.11 support added for CL7 except cPanel

* Wed Dec 06 2023 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-102
- CLOS-2215: bad_users_list ownership fixed
- CLOS-1759: dbgovernor_map mysql charset changed to utf8mb
- CLOS-1730: Timeouts added to avoid repetive log messages

* Wed Nov 22 2023 Dmitry Shibut <dshibut@cloudlinux.com> 1.2-101
- CLOS-1848: Migrate MySQL Governor on Python 3.11

* Mon Nov 20 2023 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-100
- CLOS-2193: MariaDB 10.11 support restored

* Wed Nov 15 2023 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-99
- CLOS-2049: Governor dropin removed
- CLOS-2170: Add additional safeguards for detecting MySQL AUTO version with DirectAdmin
- CLOS-2173: Added mysqlclient21 installation for clMariaDB
- CLOS-2117: mysql-version-list option added
- MariaDB 10.11 support temporarily removed

* Wed Oct 18 2023 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-97
- CLOS-2081: map_hook fixed for CL6

* Wed Oct 11 2023 Sandro Kalatozishvili <skalatozishvili@cloudlinux.com> 1.2-96
- CLOS-2058: Fixed performance issue related to governor package limits synchronization
- CLOS-2077: Fixed KeyError exception for dbgovernor set_path_environ function

* Tue Sep 19 2023 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-95
- CLOS-1737: MariaDB 10.11 support added

* Wed Sep 13 2023 Sandro Kalatozishvili <skalatozishvili@cloudlinux.com> 1.2-94
- CLOS-1797: Fixed package limitting synchronization for all users

* Thu Aug 3 2023 Sandro Kalatozishvili <skalatozishvili@cloudlinux.com> 1.2-93
- CLOS-1724: Fixed max_user_connection setup in mariadb104 and above

* Thu Jun 15 2023 Aleksey Petryankin <apetryankin@cloudlinux.com>, Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-92
- MYSQLG-961: Loading mysql functions from libmariadb added
- MYSQLG-941: Fix libmysqlclient.so.18 and libmariadb.so.3 Provides tags in mariadb102..106
- MYSQLG-965: da_admin mysql account added into default ignore list

* Fri May 19 2023 Aleksey Petryankin <apetryankin@cloudlinux.com> 1.2-91
- MYSQLG-867: Prevent removing libmysqlclient.so.18 during mysqlgovernor.py --install

* Tue Apr 25 2023 Nikolay Petukhov <npetukhov@cloudlinux.com>, Aleksey Petryankin <apetryankin@cloudlinux.com> 1.2-90
- MYSQLG-929: Fixed systemd warning 'The unit file changed on disk'
- MYSQLG-935: Added _nowraps function to exclude forced unload from lve
- MYSQLG-863: Fix error with existing /etc/my.cnf.d.govprev

* Thu Mar 30 2023 Nikolay Petukhov <npetukhov@cloudlinux.com>, Aleksey Petryankin <apetryankin@cloudlinux.com> 1.2-89
- MYSQLG-900: Fixes in systemd dropin-files on cl7 and ubuntu platforms
- MYSQLG-820: Error reports have become more consistent in governor_package_limitting.py
- MYSQLG-919: Fix checking plesk reseller existence in governor_package_limitting.py

* Thu Mar 16 2023 Nikolay Petukhov <npetukhov@cloudlinux.com> 1.2-88
- MYSQLG-853: Moving part of the LVE patch functionality to a shared library

* Tue Feb 21 2023 Sergey Kozhekin <skozhekin@cloudlinux.com> 1.2-87
- MYSQLG-817: Implement ability to sync one user or one package in /usr/share/lve/dbgovernor/governor_package_limitting.py script
- MYSQLG-873: Fix governor mysql password issue on plesk
- MYSQLG-869: Added governor-mysql service status check when adding individual limit vectors after the first install.
- MYSQLG-882: try/except block has been added for all operations with json in governor-package-limits

* Tue Jan 17 2023 Sergey Kozhekin <skozhekin@cloudlinux.com> 1.2-86
- MYSQLG-861: Governor package utility is handling case with wrong json config

* Tue Jan 10 2023 Nikolay Petukhov <npetukhov@cloudlinux.com>, Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-85
- MYSQLG-854: Fixed error that caused to restart db_governor
- MYSQLG-854 Added locking for configuration file
- Fixed install of MariaDB10.4 on CL9

* Wed Jan 04 2023 Nikolay Petukhov <npetukhov@cloudlinux.com>, Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-84
- MYSQLG-858: fixed wrong restrictions of users with default limits

* Wed Dec 28 2022 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-83.1
- MYSQLG-849: Avoided killing slow queries in removing tmp table state
- MYSQLG-842: moved mysqld restart to post scriptlet

* Thu Dec 15 2022 Nikolay Petukhov <npetukhov@cloudlinux.com>, Sergey Kozhekin <skozhekin@cloudlinux.com>, Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-81
- MYSQLG-843: Improper CL comercial license changed to GPL-2
- MYSQLG-840: Adding and updating unit tests for Governor Package Limiting
- MYSQLG-812: Implemented advanced resource consumption calculation technique

* Wed Dec 14 2022 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-80.1
- MYSQLG-850: Stopped debug output of package limits utility

* Wed Nov 30 2022 Sergey Kozhekin <skozhekin@cloudlinux.com>, Aleksey Petryankin <apetryankin@cloudlinux.com>, Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-80
- LU-3586: implement dbctl wrapper
- MYSQLG-832: Implementation of individual limits logics in Governor Package limits

* Mon Nov 28 2022 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-79
- MYSQL-841: Removed debug message from dbupdate command output

* Fri Nov 04 2022 Alexandr Demeshko <ademeshko@cloudlinux.com>, Hasan Aliev <haliev@cloudlinux.com>, Nikolay Petukhov <npetukhov@cloudlinux.com>, Sergey Kozhekin <skozhekin@cloudlinux.com>  1.2-78
- MYSQLG-781: Kept original casting in slow query log
- MYSQLG-800: Removed mariadb107 from supported mysql types
- MYSQLG-788, MYSQLG-791, MYSQLG-796, MYSQLG-804, MYSQLG-806: Governor package limits enhancements
- MYSQLG-765: Fix for config file sections absence
- MYSQLG-816: Fix governor limits on reseller packages
- MYSQLG-778: CL9 related enhancements
- MYSQLG-818: Governor script always consider --yes command line argument

* Mon Sep 26 2022 Alexandr Demeshko <ademeshko@cloudlinux.com>, Hasan Aliev <haliev@cloudlinux.com> Nikolay Petukhov <npetukhov@cloudlinux.com> 1.2-77
- MYSQLG-734: Restrict logging enabled
- MYSQLG-756: Governor package limits utility added
- MYSQLG-757: Custom configuration files restored before starting mariadb service
- MYSQLG-725: Added governor script processing of real location of mysql socket and data dir
- MYSQLG-755: mysqlclient18 dependency added for cl-MariaDB106
- MYSQLG-733: cPanel case for MariaDB 10.7, 10.8, or 10.9 added

* Tue Aug 09 2022 Alexandr Demeshko <ademeshko@cloudlinux.com>, Hasan Aliev <haliev@cloudlinux.com>  1.2-76
- MYSQLG-726: MariaDB 10.6 support added
- MYSQLG-723: Optimized package downloading in --delete command

* Mon Jun 27 2022 Alexandr Demeshko <ademeshko@cloudlinux.com>  1.2-75
- MYSQLG-721: BAD list initialization error fixed

* Fri Jun 03 2022 Alexandr Demeshko <ademeshko@cloudlinux.com>  1.2-74
- MYSQLG-671, MYSQLG-654: LVE restriction bug fixed

* Fri Mar 25 2022 Alexandr Demeshko <ademeshko@cloudlinux.com>  1.2-73
- MYSQLG-674: Legacy alter user statement avoided for MariaDB 10.4+
- MYSQLG-675: Check for cagefs-skeleton initialization added

* Tue Mar 15 2022 Daria Kavchuk <dkavchuk@cloudlinux.com>, Alexandr Demeshko <ademeshko@cloudlinux.com>  1.2-72
- MYSQLG-664: install MariaDB105 during deletion procedure of cl-MariaDB104 on cPanel
- MYSQLG-665: mysqlclient18-compat installation avoided for MariaDB 10.4+
- MYSQLG-655: Wrong governor warnings removed from the log

* Fri Sep 10 2021 Daria Kavchuk <dkavchuk@cloudlinux.com>, Alexandr Demeshko <ademeshko@cloudlinux.com>  1.2-71
- MYSQLG-617: autoremediation for broken cPanel DB mapping during `--dbupdate` command
- MYSQLG-623: MariaDB 10.4+ mysql.users changed

* Thu Jul 15 2021 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-70
- MYSQLG-579: dbctl allowed usernames extended

* Tue Jun 22 2021 Alexandr Demeshko <ademeshko@cloudlinux.com>, Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-69
- MYSQLG-601: marked "all" mode as deprecated
- MYSQLG-600: mariadb105 install is allowed on cPanel staring from v.98

* Mon May 17 2021 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-68
- MYSQLG-595: systemd mount added for governor private bad users list
- MYSQLG-588: IO limit calculation fixed

* Thu Apr 29 2021 Sergey Kokhan <skokhan@cloudlinux.com> 1.2-67
- MYSQLG-585: Fix posttrans scriptlet causes governor service stopped after update on CL8

* Wed Apr 21 2021 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-66
- MYSQLG-568: Bad users list moved to private dir
- MYSQLG-576: Prohibit clients upgrade MySQL 8 to MariaDB

* Mon Apr 05 2021 Sergey Kokhan <skokhan@cloudlinux.com> 1.2-65
- MYSQLG-575: Fixed bug when users removed from bad users list after dbuser-map file updated

* Fri Mar 05 2021 Sergey Kokhan <skokhan@cloudlinux.com> 1.2-64
- MYSQLG-574: Fixed issue with --install-beta flag

* Mon Feb 22 2021 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-63
- MYSQLG-560: libmariadb support installed for all mysql and mariadb versions

* Mon Feb 8 2021 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-62
- MYSQLG-514: MariaDB 10.5 support added

* Thu Feb 04 2021 Sergey Kozhekin <skozhekin@cloudlinux.com>, Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-61
- MYSQLG-552: deletion procedure for cPanel enhanced
- MYSQLG-552: MD5 checksum for cl8 added to the "repo_md5" dictionary

* Thu Dec 10 2020 Sergey Kozhekin <skozhekin@cloudlinux.com> 1.2-60
- MYSQLG-546: restrict upgrading to maraidb10.4 and 10.5 on cPanel servers

* Tue Nov 03 2020 Sergey Kozhekin <skozhekin@cloudlinux.com> 1.2-59
- MYSQLG-526: MariaDB (mysql) upgrade failed due to permission error

* Thu Oct 15 2020 Sergey Kokhan <skokhan@cloudlinux.com> 1.2-58
- MYSQLG-529: Fixed issue when packages not downloaded

* Fri Aug 28 2020 Sergey Kokhan <skokhan@cloudlinux.com> 1.2-57
- MYSQLG-519: Added a link to the zendesk article in the error output
- MYSQLG-502: Added support for gradual rollout repos

* Wed Aug 12 2020 Alexandr Demeshko <ademeshko@cloudlinux.com> 1.2-56
- MYSQLG-489: Added check for uninited cagefs

* Mon Aug 03 2020 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-55
- MYSQLG-513: mysqld_exporter and MySQL-python excluded from the list of packages to remove

* Tue Jun 23 2020 Sergey Kokhan <skokhan@cloudlinux.com> 1.2-54
- MYSQLG-503: Added detect mysql 8.0 on cPanel

* Mon Feb 03 2020 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-53
- MYSQLG-468: added mariadb104 support
- MYSQLG-466: Allow duplicates when reading /etc/my.cnf

* Mon Jan 20 2020 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-52
- MYSQLG-458: migrated to Python 3.7

* Wed Jan 15 2020 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-51
- MYSQLG-452: CL8 modularity caching during install, mysql:8.0 as auto version

* Wed Dec 25 2019 Sergey Kokhan <skokhan@cloudlinux.com>, Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-50
- MYSQLG-451: install script fixes for CL8
- MYSQLG-419: setting fs.suid_dumpable value based on io permissions

* Mon Dec 09 2019 Sergey Kokhan <skokhan@cloudlinux.com>, Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-49
- MYSQLG-436: Add CL8 support for governor-mysql
- MYSQLG-430: removed cpapi usage; cldetect instead

* Tue Oct 29 2019 Rostyslav Tulchii <rtulchii@cloudlinux.com> 1.2-48
- MYSQLG-429: Optimized handling dbtop-clients

* Tue Sep 17 2019 Rostyslav Tulchii <rtulchii@cloudlinux.com>, Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-47
- MYSQLG-422: mysql version detection for DirectAdmin improved
- MYSQLG-421: Deleted one of cagefs force-update after governor installation

* Wed Jul 31 2019 Rostyslav Tulchii <rtulchii@cloudlinux.com> 1.2-46
- MYSQLG-410: handling of nontrivial cases with semaphores during the startup

* Tue Jul 23 2019 Rostyslav Tulchii <rtulchii@cloudlinux.com> 1.2-45
- MYSQLG-405: make governor update local.versions file properly on cPanel after uninstalling

* Fri Jun 28 2019 Rostyslav Tulchii <rtulchii@cloudlinux.com> 1.2-44
- MYSQLG-402: Fixed issue with max_user_connection restoration
- MYSQLG-388: Fixed issue on parsing params lve-mode

* Tue Apr 30 2019 Rostyslav Tulchii <rtulchii@cloudlinux.com> 1.2-43
- MYSQLG-380: improve restoring mechanism of max_user_connections directive

* Tue Apr 09 2019 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-42
- MYSQLG-387: fix --delete procedure
- MYSQLG-385: process CpuserNotInMap exception while dbgovernor_map

* Mon Mar 25 2019 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-41
- MYSQLG-383: added command execution timeout
- MYSQLG-329: full mariadb103 support for cPanel
- MYSQLG-379: fixed exceptions flow in dbgovernor_map py files
- MYSQLG-382: fixed dbgovernor_map for Plesk
- MYSQLG-373: updated governor removal for cPanel

* Thu Mar 14 2019 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-40
- Fix encoding for *map files

* Wed Mar 06 2019 Serhii Kokhan <skokhan@cloudlinux.com>, Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-39
- MYSQLG-377: options --wizard and --status added

* Tue Feb 19 2019 Aleksandr Povalyaev <apovalyaev@cloudlinux.com>, Daria Kavchuk <dkavchuk@cloudlinux.com>, Rostyslav Tulchii <rtulchii@cloudlinux.com> 1.2-38
- MYSQLG-364: added returning a non-zero value in case of error
- MYSQLG-368: fix current packages download procedure for DirectAdmin
- MYSQLG-366: download official mysql/mariadb packages on cPanel
- MYSQLG-365: db_governor service enabled for CloudLinux 7
- MYSQLG-363: added daemon-reload in postun scriptlet
- MYSQLG-361: added return codes for errors during installation
- MYSQLG-311: copyright updated
- MYSQLG-338: fix memory leak with init_lve/exit_lve
- MYSQLG-344: prevent reseting of max_user_connections when unfreezing
- MYSQLG-346: option for update credentials added
- MYSQLG-319: warn user about disable of protectbase plugin

* Tue Nov 20 2018 Aleksandr Povalyaev <apovalyaev@cloudlinux.com>, Serhii Kokhan <skokhan@cloudlinux.com>, Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-37
- mysql80, libmysqlclient.so.21 support
- MYSQLG-297, MySQLG-301: old auth procedure for mysql80
- MYSQLG-293: Added logrotate config for governor-mysql
- MYSQLG-306: fix error logging from --dbupdate
- MYSQLG-300: cagefs force-update after governor installation and delete procedure
- MYSQLG-302: Investigate why db_governor fails with error "Can't init BAD list"
- MYSQLG-326: Wrong handling of SQL line while logging slow mysql query

* Wed Jun 20 2018 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-36
- mariadb103 support
- MYSQLG-269: warnings in case of downgrade or switching mysql|mariadb
- MYSQLG-259: added 'assumeyes' for all yum commands

* Tue Apr 24 2018 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-35
- Fixed dbgovernor crash when username length is long

* Fri Apr 13 2018 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-34
- MYSQLG-251: fix error on choosing MySQL
- MYSQLG-250: fix broken symlinks

* Fri Feb 02 2018 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-33
- MYSQLG-239: dbuser-map for Plesk implemented

* Mon Jan 29 2018 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-32
- MYSQLG-243: mysqlgovernor.py able to set version and install in one turn

* Tue Jan 23 2018 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-31.1
- Added test version of governor's library

* Wed Jan 17 2018 Serhii Kokhan <skokhan@cloudlinux.com> 1.2-31
- MYSQLG-237: dbtop update interval fixed

* Fri Jan 12 2018 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-30
- MYSQLG-240: try to fix cPanel hooks after update from 1.1 governor version

* Tue Dec 05 2017 Daria Kavchuk <dkavchuk@cloudlinux.com> - 1.1-27
- MYSQLG-231: db_governor fails to start

* Mon Dec 04 2017 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-29
- MYSQLG-220: Fix restore of MariaDB and MySQL 5.7 official packages after governor deletion on cPanel

* Thu Nov 16 2017 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-28
- Fixed unlimit reading from config file

* Wed Nov 01 2017 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-27
- MYSQLG-221: Add installation of mysqlclient18 for MariaDB 10.2

* Fri Oct 20 2017 Daria Kavchuk <dkavchuk@cloudlinux.com> - 1.1-26
- MYSQLG-218: added MariaDB 10.2 support

* Tue Oct 17 2017 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.1-25
- MYSQLG-216: the cPanel's Service Manager stucks on the governor restart
- MYSQLG-217: The Governor is not starting with " Can't load mysql functions" error

* Mon Oct 16 2017 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-26
- MYSQLG-216: the cPanel's Service Manager stucks on the governor restart
- MYSQLG-217: The Governor is not starting with " Can't load mysql functions" error

* Mon Oct 02 2017 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.1-24
- MYSQLG-209: Add percona56 to Usage output of db-select-mysql

* Tue Sep 19 2017 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.1-23
- MYSQLG-205: fix code flow for IWorks object init

* Thu Sep 07 2017 Eugen Vodilov <evodilov@cloudlinux.com> 1.2-25
- MYSQLG-204: Perfomance fix for statistic enabled servers
- Fix build dependency on CL7 (broken glib-2.0 dependency to pcre-devel)

* Tue Aug 22 2017 Daria Kavchuk <dkavchuk@cloudlinux.com>, Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-24
- MYSQLG-197: Stop to delete mysqld.service for DirectAdmin in cl-MySQL packages

* Tue Aug 08 2017 Daria Kavchuk <dkavchuk@cloudlinux.com>, Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-23
- MYSQLG-199: disable mysql monitoring on cPanel while governor installing.
- MYSQLG-198: CageFS MySQL Vulnerability

* Mon Jun 19 2017 Daria Kavchuk <dkavchuk@cloudlinux.com>, Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-22
- MYSQLG-183: Missed file /etc/container/dbuser-map after installation of Governor
- MYSQLG-188: Add support MariaDB 10.2 with governor

* Tue Jun 06 2017 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.1-22
- Added Percona 5.6 support

* Fri May 26 2017 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-21
- MYSQLG-182: Make MySQL-governor work with EIG Percona
- MYSQLG-185: Add installation of mysqlclientXX when new_version=auto in _load_new_packages

* Tue May 16 2017 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-20
- Added Percona56 for Endurance support

* Mon May 08 2017 Alexey Berezhok <aberezhok@cloudlinux.com>, Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-19
- Spell fixes
- MYSQLG-178: store read write mysql limits as signed values

* Fri Apr 28 2017 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.2-17
- Added mysql_upgrade for MariaDB packages
- Fixed error in DirectAdmin installation

* Thu Mar 30 2017 Daria Kavchuk <dkavchuk@cloudlinux.com>, Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-18
- Added mysql_upgrade for MariaDB packages
- Fixed error in DirectAdmin installation
- Added xml escaping and prettyfying
- Added read duplicate of config for non user list

* Mon Mar 06 2017 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.1-21
- MYSQLG-154: Fix ""dbctl list"" show io limits equals to default when they are less then 1mb/s
- MYSQLG-159: add ability to specify units for io limits
- MYSQLG-157: Need to review the algoritm of set LVE=3 limits on MySQL install/update

* Mon Feb 27 2017 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-16
- Check log-error existings on installation of MySQL packages

* Fri Feb 10 2017 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-15
- Fixed restarting MariaDB services for CL7 on governor update

* Thu Feb 02 2017 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-14
- MYSQLG-152: Use default values for "script" parameters in governor's config in case when script="". Now governor report about error and stop to work.
- Fixed errors in source code.
- Code prettifying and formatting

* Thu Feb 02 2017 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.1-20
- MYSQLG-152: Use default values for "script" parameters in governor's config in case when script="". Now governor report about error and stop to work.

* Fri Jan 20 2017 Daria Kavchuk <dkavchuk@cloudlinux.com> 1.2-13
- Fixed errors in source code.
- Code prettifying and formatting

* Wed Dec 28 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-12
- Fixed Rpmdb checksum is invalid in mysql packages installation

* Mon Dec 26 2016 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.1-19
- MYSQLG-136: Add new behaviour for MySQL LVE enter for preventing crash MySQL on lve destroy
- MYSQLG-149: investigate the possibility to avoid httpd checks during "mysqlgovernor.py --dbupdate"

* Thu Dec 22 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-11
- MYSQLG-146: Remove original mysql packages correctly
- Fixed detection of MariaDB 10.1 after installing

* Mon Oct 31 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-10
- Fix DA MySQL connection parameters parsing

* Thu Sep 29 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-9
- Fix incorrect path to deprecated script in postupcp for cPanel
- Fixed restarting of mysql service (non governor packages)

* Mon Sep 26 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-8
- MYSQLG-134: Check if mysql is not in yum exclude list
- MYSQLG-140: Spelling error in mysqlgovernor.py script output

* Mon Sep 26 2016 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.1-18
- MYSQLG-134: Check if mysql is not in yum exclude list
- MYSQLG-140: Spelling error in mysqlgovernor.py script output

* Sat Sep 24 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-7
- Fixed my.cnf restoring on MySQL update or version change

* Thu Aug 25 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-6
- MYSQLG-124: Use set_old_limit before mysql process killed

* Thu Aug 25 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-5
- Fixed detecting of MySQL active processes for MySQL 5.7

* Fri Aug 19 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-4
- MYSQLG-136: Add new behaviour for MySQL LVE enter for preventing crash MySQL on lve destroy

* Mon Aug 15 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-3
- Fixed error on previous MySQL package detected

* Wed Jul 27 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.2-2
- Added save of statistics even if no cpu&io activity but was only cause changing

* Tue Jul 26 2016 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.1-17
- Force reinstall cloudlinux.versions on update

* Thu Jul 14 2016 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.1-16
- Fixed error in cloudlinux.version file for cPanel

* Mon Jul 11 2016 Alexey Berezhok <aberezhok@cloudlinux.com>, Mikhail Zhbankov <mzhbankov@cloudlinux.com> 1.2-1
- MYSQLG-130: Add uid to statistic file(end of each string)
- MYSQLG-126: Add automatic removal /var/run/mysql-governor-config.xml file with remove/downgrade
- MYSQLG-131: After update cl-MySQL(cl-MariaDB) cleint can't start mysql process because old process didn't stop
- MYSQLG-122: Reserch ability to remove unneeded files on governor's migration from one MySQL type to another
- MYSQLG-129: Set default user status restricted produces duplicate in dbctl list
- MYSQLG-132: after removin dbgovernor maria db is dead
- MYSQLG-128: Check ability to add a way to monitor db_governor via cpanel Service Manager (Chkservd).

* Fri Jun 03 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-15
- Added reload-daemon for CL7 on update
- Uncommented path to PID file in service for CL7

* Wed May 25 2016 Alexey Berezhok <aberezhok@cloudlinux.com>, Mikhail Zhbankov <mzhbankov@cloudlinux.com> 1.1-14
- Added creation of copy config file

* Tue Apr 26 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-13
- Remove ulimt from service file

* Mon Jan 04 2016 Alexey Berezhok <aberezhok@cloudlinux.com>, Mikhail Zhbankov <mzhbankov@cloudlinux.com> 1.1-12
- MYSQLG-105: cl-MySQL57-5.7.11-1 requirements are broken on CL6.i386
- MYSQLG-97: Add support by governor MySQL 5.7
- MYSQLG-103: fix dbctl list output for read and write limits
- MYSQLG-98: Make /dev/shm/governor_bad_users_list unreadable for users
- MYSQLG-104: fix governor restart on CL7 under systemd
- MYSQLG-108: Fix dbctl set command bug

* Mon Jan 04 2016 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-11
- MYSQLG-95: mysqlgovernor.py --dbupdate does not work (with conf parameter without =)

* Wed Nov 25 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-10
- Fixed garbage on dbtop exit on CL7

* Mon Nov 16 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-9
- Added local.version content analizing(cPanel)
- Added MariaDB for DA identification
- Fixed ISPManager Bussines identification

* Fri Nov 13 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-8
- Added NO_UBC one more place

* Mon Nov 09 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-7
- MYSQLG-85: added installation mode with MySQL/MariaDB version confirmation

* Tue Nov 03 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-6
- MYSQLG-82: fixed bugs reported by coverity

* Thu Oct 08 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-5
- Adde LVE_NO_UBC on enter

* Mon Sep 14 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-4
- Added is_in_lve support
- Fixed install-beta for CloudLinux 7 detection error
- Added fixing of mysqld service for CloudLinux 7
- rerun ldconfig for fixing endless loop

* Thu Aug 27 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-3
- Grammatical fixes

* Wed Aug 05 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-2
- Fixed installation script for auto mode CL7

* Mon Aug 03 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.1-1
- Fixed installation script (disabled cloudlinux-updates-testing)

* Fri Jul 10 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-96
- Restart governor service on package update

* Thu Jul 02 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-95
- Fixed MariaDB detect for cPanel
- Fixed MariaDB package restoring on governor uninstall

* Thu Jun 04 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-94
- Optimized dbgovernor_map script for cPanel

* Tue May 26 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-93
- Fixed error on CloudLinux 7 + cPanel installation

* Mon May 25 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-92
- Use DirectAdmin without custombuild (Sander Hoentjen <shoentjen@antagonist.nl>)
- Fixed stats hash table corruption on lve-mode switching (with dbctl)

* Mon Mar 30 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-91
- Fixed memory leak in dbtop
- Added patch for MariaDB 5.5.41 for CL7

* Mon Feb 16 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-90
- Removing MariaDB-common in db-governor installation for preventing conflict

* Wed Feb 11 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-89
- Fixed MySQL installation for OTHER panel

* Mon Feb 09 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-88
- Fixed MySQL stopping on version update

* Tue Jan 27 2015 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.0-87.cl7
- CL7 build

* Fri Jan 23 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-87
- CloudLinux7 adaptation

* Thu Jan 15 2015 Alexey Berezhok <alexey.berezhok@cloudlinux.com> - 1.0-86.cl7
- Cl7 build

* Tue Jan 13 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-86
- Added fix of dbuser-map file reading

* Mon Jan 12 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-85
- Added logging of dbuser-map file reading

* Fri Jan 09 2015 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-84
- Added fix for MariaDB 10.1-devel package

* Thu Dec 25 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-83
- Fixed conflict with compat-MySQL51-shared

* Thu Dec 25 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-82
- Fixed conflict with compat-MySQL50-shared

* Thu Dec 25 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-81
- Preparing MySQL install script to release

* Thu Dec 18 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-80
- Added fix for MariaDB 10.0-devel package
- Added detection mysql55w

* Thu Dec 18 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-79
- Added fix for MariaDB 10.0-devel package

* Tue Nov 04 2014 Pavel Shkatula <shpp@cloudlinux.com> 1.0-78
- Added support MariaDB 10.1
- ##

* Tue Aug 26 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-77
- Fixed error with iolimit for CL5
- Added reseting of statistics on restrict

* Tue Aug 26 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-76
- Fixed dbuser map file for DA error

* Tue Aug 19 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-75
- Added --force command for deleting Percona packages

* Tue Aug 19 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-74
- Ask before Percona packages delete

* Tue Aug 19 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-73
- read socket option from mysql.conf, if exists

* Thu Aug 14 2014 Pavel Shkatula <shpp@cloudlinux.com> 1.0-72
- Added MariaDB 10.0 support

* Mon Aug 04 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-71
- Added logging before restrict

* Fri Jul 18 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-68
- Percona removing

* Tue Jul 15 2014 Pavel Shkatula <shpp@cloudlinux.com> 1.0-67
- Clean Percona packages before governor installation

* Fri Jul 04 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-66
- Catch the case where a user has no uid in DA dbuser-map

* Thu Jul 03 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-65
- removed duplicate usernames from DA dbuser-map

* Thu Jul 03 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-64
- fix username to be username instead of dbname and make file write atomic

* Thu Jul 03 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-63
- Fixes in dbctl list header
- Fixes in DA dbuser-map generator
- AbUser mode as default

* Wed Jul 02 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-62
- Fixed DA dbuser-map creation
- Switched MySQL installation from production repo

* Fri Jun 20 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-61
- Fixed MySQL5.6 installation for cPanel 11.44

* Fri May 30 2014 Pavel Shkatula <shpp@cloudlinux.com> 1.0-60
- Not created file statistic if no statistic on period

* Mon May 26 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-59
- Fixed dbuser-map builder script for cPanel 11.43

* Thu May 08 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-58
- Added default account dbuser for cPanel

* Tue Apr 29 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-57
- Fixed MySQL-python installation

* Mon Apr 28 2014 Alexey Berezhok <aberezhok@cloudlinux.com> , Pavel Shkatula <shpp@cloudlinux.com> 1.0-56
- MYSQLG-57: Add support new lvectl
- MYSQLG-56: Need additional check on success open of configure file
- MYSQLG-54: Add removing MariaDB-common package 
- MYSQLG-55: On mysqlgovernor --install on DA appears message: ImportError: No module named MySQLdb
- Added mysql_export fucntions

* Wed Apr 16 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-55
- Switch MySQL installation from cloudlinux-updates-testing
- Added all mode in DirectAdmin

* Fri Apr 04 2014 Alexey Berezhok <aberezhok@cloudlinux.com>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-54
- Moved governor to new MySQL repos

* Fri Mar 21 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-53
- Fixed: KNA-700-53569 - support of MySQL56 in cPanel

* Fri Mar 14 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-52
- Fixed: MYSQLG-52 - dbctl delete issue

* Tue Mar 11 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-51
- Updated MariaDB up to 5.5.34-22

* Thu Jan 30 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-50
- Fix path to perl (for cPanel 11.42.0 installation)

* Wed Jan 15 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-49
- Update MySQL up to 5.1.72, 5.5.34, 5.6.15 and MariaDB 5.5.34

* Mon Jan 13 2014 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-48
- Fixes in libgovernor.so changed select to poll wich can be cause of stack corruption in MySQL
- Added autochek of libgovernor changing

* Mon Dec 30 2013 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-47
- Fixed MariaDB test repository name

* Thu Dec 26 2013 Alexey Berezhok <aberezhok@cloudlinux.com>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-46
- Added memory management in bad user list like mysql
- Optimized add user to bad list algorithm
- Fixed lost user on delete from bad list

* Wed Dec 11 2013 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-45
- Added reconnect to database on execution errors

* Tue Dec 10 2013 Alexey Berezhok <aberezhok@cloudlinux.com> 1.0-44
- Fixed error bad users list creation (cause of mysql crash)
- Added gcc -stack-protector for more detail crash info

* Fri Nov 29 2013 Alexey Berezhok <aberezhok@cloudlinux.com>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-43
- Fixed duplicate user name in account on reread usermap file
- Optimaze cooperation of dbuser-map and separator parameter
- Added debug_user parameter to config for debugging some user statistic calculation

* Tue Nov 26 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-42
- Added PATH to governor's cron task

* Fri Nov 22 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-41
- Fixed governor crash on KILL QUERY sending
- Optimize FLUSH PRIVILEGES sending

* Tue Nov 12 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-40
- Added installation of mysqlclient from new repo

* Wed Nov 06 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-39
- Fixed governor redelete BAD user

* Wed Nov 06 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-38
- Fixed bug dbctl restrict

* Thu Oct 31 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-37
- Added no connection limit mode(user_max_connections=0)

* Thu Oct 24 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-36
- Optimized commands system of mysql installation

* Thu Oct 17 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-35
- Fixed path to perl in dbuser-map utility

* Fri Oct 04 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-34
- Fixes in mysql other install script
- Fixed interval unit for kill query

* Fri Oct 04 2013 Alexey Berezhok <alexey_com@ukr.net>  1.0-33
- Fixes in mysql cpanel install script

* Tue Sep 24 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com>  1.0-31
- Added db_governor --version
- Decreased dbuser-map interval rescanning to 5 min

* Wed Sep 18 2013 Alexey Berezhok <alexey_com@ukr.net>  1.0-30
- Fixed dbctl list output

* Fri Sep 13 2013 Alexey Berezhok <alexey_com@ukr.net>  1.0-29
- Fix in db-select-mysql script for mysql56 support

* Thu Sep 12 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com>  1.0-28
- Added MySQL5.6 support
- Added logging slow query killing
- Fixed dbctl list segfault

* Wed Sep 04 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-27
- Fixed crash governor on killing queries more than 9K

* Thu Aug 29 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-26
- Added new restrict mode support

* Wed Aug 28 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-25
- Removed state checking on query killing

* Tue Aug 27 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-24
- Added support governor's plugin for MariaDB
- Added governor's plugin for MariaDB

* Thu Aug 08 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-23
- Added make source command

* Tue Aug 06 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-22
- Added set slow query kill time per account

* Mon Jul 29 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-21
- Fixed error messages when governor stopped
- Fixed dbtop delay on start

* Fri Jul 26 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-20
- Aded killing slow quieries

* Tue Jul 23 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-19
- Unified dbusrer-map

* Tue Jul 23 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-18
- Added wget requires
- Added acount name from dbusrer-map

* Mon Jul 22 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-17
- Added lve mode - off/single(on)/abusers/all

* Mon Jul 15 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-16
- Added SEPARATE MODE on/off

* Mon Jul 15 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-15
- Fixed Plesk conflict on mysqlgovernor.py --install with mysqlclient

* Mon Jul 15 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-14
- Fixed Plesk installation

* Fri Jul 12 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-13
- Added removing mysql on mysqlgovernor.py --install

* Fri Jul 12 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-12
- Disabled AutoReq

* Thu Jul 11 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-11
- Added separate LVE for each user
- Added usermap file
- Added cPanel hooks for file creation
- Fixed syntax check in dbctl

* Thu Jul 04 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-10
- Fixed Plesk installation error
- Added MySQL 5.5.32 support

* Tue Jun 25 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-9
- Added MariaDB 5.5.31

* Fri Jun 21 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-8
- Added SHOW FULL PROCESSLIST instead SHOW PROCESSLIST
- Added supporting fixing mysqls

* Wed Jun 12 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-7
- Fixed dbctl unrestricted-all command
- Fixed dbctl restrict command
- Added symlink /etc/init.d/mysqld creation on /etc/init.d/mysql
- Added check type of mysql from file on mysqlclient install
- Added support of mariadb 5.5.30-17

* Tue Jun 11 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-6
- Fixed version MySQL for cPanel
- Added "Database backup" instruction

* Fri Jun 07 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-5
- Fixed db-update for Plesk

* Fri May 31 2013 Alexey Berezhok <alexey_com@ukr.net> 1.0-4
- Added db-update script
- Added al-php mysql update on database type changing
- Removed killuser mode in governor

* Mon May 20 2013 Pavel Shkatula <shpp@cloudlinux.com> 1.0-3
- Fixed dbctl list and big numbers issue

* Fri May 17 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-2
- Fixed cPanel install script (changing from MariaDB to MySQL)

* Fri May 17 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 1.0-1
- Added MariaDB instalation
- Added select MySQL server script

* Mon Apr 15 2013 Alexey Berezhok <alexey_com@ukr.net> 0.9-15
- Added set fs_suid_dumpable on package install or update

* Mon Apr 15 2013 Alexey Berezhok <alexey_com@ukr.net> 0.9-14
- Removed empty statistics saving to history (fix)

* Mon Apr 15 2013 Alexey Berezhok <alexey_com@ukr.net> 0.9-13
- Removed empty statistics saving to history

* Fri Apr 05 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.9-12
- Added installation governor on non CL servers
- Removed lve requires
- Added MariaDB patch

* Mon Mar 18 2013 Alexey Berezhok <alexey_com@ukr.net> 0.9-11
- Fixed IO calculations

* Mon Mar 18 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.9-10
- Fixed dbtop garbage
- Fixed cl-MySQL-server missed on install

* Fri Mar 15 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.9-9
- Fixed dbtop last line error
- Fixed empty password error
- Fixed new lve-stats dependency

* Tue Mar 12 2013 Alexey Berezhok <alexey_com@ukr.net> 0.9-8
- Added mysql support 5.5.30, 5.1.68, 5.0.96, 5.1.67
- Fixed mysql crash (removed lve_exit)
- Fixed mysql hang up (added own trylock)
- Fixed rewrite config on the fly crash
- Fixed "PROCESSLIST" error for mysql 5.0

* Tue Feb 19 2013 Alexey Berezhok <alexey_com@ukr.net> 0.9-7
- Added postupcp hook for upgrade cPanel from 11.34 to 11.36

* Fri Feb 15 2013 Alexey Berezhok <alexey_com@ukr.net> 0.9-6
- Fixed bug in mysqldisabler script on cPanel (<11.36)

* Fri Feb 15 2013 Alexey Berezhok <alexey_com@ukr.net> 0.9-5
- Added installation on cPanel 11.36 (fix)

* Tue Feb 12 2013 Alexey Berezhok <alexey_com@ukr.net> 0.9-4
- Added installation on cPanel 11.36

* Thu Jan 24 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.9-3
- Fixed header of dbctl list
- Show values less then 1Mb/s in dbctl list

* Fri Jan 18 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.9-2
- Added logging queries on restrict
- Update MySQL vesrion 5.1.66, 5.5.28

* Mon Jan 14 2013 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.9-1
- Added new put in lve algorithm
- Added lve_enter_pid wrapper
- Added support of new MySQL with new algorithm of work (cPanel 5.5, 5.1, 5.0 and standart CL5 & CL6 mysql 5.0 and 5.1)

* Mon Dec 10 2012 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.8-40
- Fixed dbctl negative read/write limits

* Wed Dec 05 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-39
- Added lve-stats 0.9-13 require

* Tue Dec 04 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-38
- Changed max_sim_connections to average_connections

* Mon Dec 03 2012 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.8-37
- Added /vr/lve/dbgovernor directory creation

* Fri Nov 30 2012 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.8-36
- Added CAUSE history field saving
- Enabled statistics by default
- Disabled killuser by default
- Disabled mysql-debuginfo installation(for cPanel)
- Enabled force mysql installation(for cPanel)
- Fixed segfault in dbctl
- Fixed trouble with g_hash_table_remove_all

* Mon Nov 26 2012 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.8-35
- Added statistics collection(lve-stats part)

* Wed Nov 21 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-34
- Fixed error on mysql 5.5 installtion on i386

* Wed Nov 21 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-33
- Change mysql-governor.xml access mask to 600

* Mon Nov 19 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-32
- Rename "watch" command to "monitor"

* Mon Nov 19 2012 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.8-31
- Added statistics collection(governor part)
- Added restore screen and exit on CTRL-C - dbtop
- Added coredump creation on governor crash
- Added directory for future statistics storage

* Wed Nov 14 2012 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.8-30
- Added unresrict user on ignore
- Added dbctl watch command for disable ignoring
- Fixed level format error

* Mon Nov 12 2012 Alexey Berezhok <alexey_com@ukr.net>, Pavel Shkatula <shpp@cloudlinux.com> 0.8-29
- Added dbctl utility
- Added dbtop -c mode
- Added dbtop crash dump tracing
- Added killuser config flag

* Thu Nov 01 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-28
- Fixed is_in_lve in mysql

* Tue Oct 30 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-27
- Added check cpu, read, write before adding to counter

* Mon Oct 29 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-26
- Fixed governors resource usage calculation(end of request)

* Mon Oct 29 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-25
- Fixed governors resource usage calculation

* Fri Oct 26 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-24
- Fixed governors statistics calculation
- Show user load even when user is restricted
- Fixed dbtop header

* Thu Oct 25 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-23
- Added support fixed MySQL (5.5.27, 5.0.95, 5.1.61, 5.0.92, 5.1.63)

* Fri Oct 19 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-22
- Added support MySQL (5.5.27, 5.0.95, 5.1.61, 5.0.92)
- Fixed "Unrecognized option" under CL5

* Thu Oct 11 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-21
- Added new MySQL installation (5.1.63-14)

* Mon Oct 08 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-20
- Added new MySQL installation (5.1.63-12)

* Mon Oct 08 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-19
- Error on Inside LVE

* Thu Oct 04 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-18
- Change liblve.so to liblve.so.0

* Thu Oct 04 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-17
- Added new MySQL installation(5.1.63-11)

* Wed Oct 03 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-16
- Decreased mutex lock on info send(to daemon)
- Added new MySQL installation(5.1.63-10)

* Mon Oct 01 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-15
- Added new MySQL installation(5.1.63-9)

* Thu Sep 27 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-14
- Decreased time of lock in MySQL

* Wed Sep 26 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-13
- Removed kill_connection on unrestrict
- Changed mysql+LVE algorithm

* Mon Sep 24 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-12
- Added kill_connection on unrestrict

* Mon Sep 24 2012 Alexey Berezhok <alexey_com@ukr.net>,  Pavel Shkatula <shpp@cloudlinux.com> 0.8-11
- Changed algorithm of thread locking (MySQL part)
- Fixed error with lost TID cleaning
- Added userstat cleaning for MySQL 5.1
- Added mysql stoping before installation for MySQL 5.5

* Mon Sep 17 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-10
- Fixed error in install script

* Mon Sep 17 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-9
- Move calculation to separate thread
- Close semaphore on error
- Added limiting connection per user on restrict

* Fri Sep 14 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-8
- Fixed bug in LVE setting creation(on install)

* Thu Sep 13 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-7
- Optimization of work
- Added LVE support
- Added two mode of unrestrict mode for mysql_unfreeze (old and new), added option - help
- Added new mysql 5.1, 5.0, 5.5 support (with LVE patches)
- Added new mode of dbtop sorting (by time to end restrict, and by restrict level)
- Changed dafault config limits
- Added usage save-all-parameters on VE container creation

* Fri Sep 07 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-6
- Fixed error in DA, Plesk installation processes

* Thu Sep 06 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-5
- Added MySQL 5.5 support
- Added support of ISPManager, Plesk, IWorx
- Renamed install-mysql.py to mysqlgovernor.py

* Tue Sep 04 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-4
- Fixed bug in DA installator
- Fixed segfault bug on i686 arch

* Fri Aug 31 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-3
- Fixed memory leak
- Optimized algorithm of TID saving
- Added support 5.0 mysql for cPanel
- Fixed calculation of Resource Usage once a second
- Added commands clean-mysql and clean-mysql-delete
- Added DA mysql (5.1 and 5.0) support

* Thu Aug 23 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-2
- Fixed mysql - governor deadlock
- Changed output format of dbtop
- Changed default limits for cpu and periods

* Fri Aug 17 2012 Alexey Berezhok <alexey_com@ukr.net> 0.8-1
- Changed package name
- Changed analytic algorithm
- Added library for mysql extension
- Changed configuration list
- Removed mysql_connector

* Tue Jul 31 2012 Alexey Berezhok <alexey_com@ukr.net> 0.7-11
- Fixed freeze connector on users refresh
- Increased CHECKTICKS detalization

* Wed Jul 25 2012 Alexey Berezhok <alexey_com@ukr.net> 0.7-10
- Fixed error with freeze governor
- Fixed error with hang up threads of dbtop
- Disable --install-beta

* Tue Jul 24 2012 Alexey Berezhok <alexey_com@ukr.net> 0.7-8
- Added debuginfo

* Thu Jul 19 2012 Alexey Berezhok <alexey_com@ukr.net> 0.7-7
- Added support MySQL 5.1.63-2

* Wed Jun 27 2012 Alexey Berezhok <alexey_com@ukr.net> 0.7-6
- Fixed bug with mysql 5.5 detection. Added beta mysql installation

* Thu Jun 21 2012 Alexey Berezhok <alexey_com@ukr.net> 0.7-5
- Restore workin of old-hook utility for cPanel broken in 0.7-1 version

* Thu Jun 21 2012 Alexey Berezhok <alexey_com@ukr.net> 0.7-4
- Added information on installation. Added governor restarting on cpanel utility

* Thu Jun 21 2012 Alexey Berezhok <alexey_com@ukr.net> 0.7-3
- Fixed package distributive name

* Thu Jun 21 2012 Alexey Berezhok <alexey_com@ukr.net> 0.7-2
- Fixed dependency bug in package

* Tue Jun 19 2012 Alexey Berezhok <alexey_com@ukr.net> 0.7-1
- Added mysql install utility for cPanel, DA, Plesk, iWorx, ISPManager

* Tue Jun 12 2012 Alexey Berezhok <alexey_com@ukr.net> 0.6-5
- Fixed bug with mutex locking in connector
- Reorganized procedure of information exchange between governor and connector
- Fixed test mode
- Fixed bug in restriction algorithm

* Mon May 14 2012 Alexey Berezhok <alexey_com@ukr.net> 0.6-4
- Fixed bug with no limiting in i386 arch

* Fri Nov 04 2011 Alexey Berezhok <alexey_com@ukr.net> 0.6-2
- Fix in spec

* Tue Oct 04 2011 Alexey Berezhok <alexey_com@ukr.net> 0.6-1
- Added triggers for restrict and slow query
- Added debug info mode for slow query
- Added connection checking

* Tue Sep 06 2011 Alexey Berezhok <alexey_com@ukr.net> 0.5-10
- Added mysql 5.5 support

* Fri Aug 26 2011 Alexey Berezhok <alexey_com@ukr.net> 0.5-9
- Fixed mysql identification

* Thu Aug 11 2011 Alexey Berezhok <alexey_com@ukr.net> 0.5-8
- Segfault mysql_connector fixed

* Thu Aug 04 2011 Alexey Berezhok <alexey_com@ukr.net> 0.5-7
- Minor fixes
- Added mysql real users list caching
- Added user refresh interval into config file(default 5 minutes)

* Tue Jul 19 2011 Alexey Berezhok <alexey_com@ukr.net> 0.5-6
- Added SHOW PROCESSLIST info into restrict log

* Mon Jul 18 2011 Alexey Berezhok <alexey_com@ukr.net> 0.5-5
- Fixed error with query info output into restrict log

* Wed Jul 13 2011 Alexey Berezhok <alexey_com@ukr.net> 0.5-4
- Added check from selfblocking mysql user
- Review service script

* Thu Jul 07 2011 Alexey Berezhok <alexey_com@ukr.net> 0.5-3
- Change path to logs and socket, added loadavg info into training log

* Wed Jul 06 2011 Alexey Berezhok <alexey_com@ukr.net> 0.5-2
- Added attribute format for restrict log

* Tue Jul 05 2011 Alexey Berezhok <alexey_com@ukr.net> 0.5-1
- Added separate training log
- Changed request to DB (without temporary tables)
- Another small fixes

* Thu Jun 23 2011 Alexey Berezhok <alexey_com@ukr.net> 0.4-7
- Change restrict log format

* Wed Jun 22 2011 Alexey Berezhok <alexey_com@ukr.net> 0.4-6
- Up all default limits in config file

* Thu Jun 16 2011 Alexey Berezhok <alexey_com@ukr.net> 0.4-5
- Fix error in pre hook

* Thu Jun 16 2011 Alexey Berezhok <alexey_com@ukr.net> 0.4-4
- Fix eroor in dependencies

* Thu Jun 16 2011 Alexey Berezhok <alexey_com@ukr.net> 0.4-3
- Remove training info from restrict log to error

* Wed Jun 15 2011 Alexey Berezhok <alexey_com@ukr.net> 0.4-2
- Add auto stop and auto kill db-governors processes on update

* Fri Jun 10 2011 Alexey Berezhok <alexey_com@ukr.net> 0.4-1
- New functionality

* Thu Mar 24 2011 Alexey Berezhok <alexey_com@ukr.net> 0.3-11
- Changed strncpy to strlcpy
- Added debugmode

* Wed Mar 23 2011 Alexey Berezhok <alexey_com@ukr.net> 0.3-10
- Removed strange users form dbtop
- Added log for restriction event

* Thu Feb 24 2011 Alexey Berezhok <alexey_com@ukr.net> 0.3-9
- Change mysql-governor.xml. Remove connected_time.

* Tue Feb 22 2011 Alexey Berezhok <alexey_com@ukr.net> 0.3-8
- Fix cpu_time freezing
- Removed timer from connector that freeze governor statistic

* Mon Dec 06 2010 Alexey Berezhok <alexey_com@ukr.net> 0.3-7
- Add sorting by username
- Fix bug with newline when terminal resized

* Fri Dec 03 2010 Alexey Berezhok <alexey_com@ukr.net> 0.3-6
- Fixed bug with one info string under i386 system

* Thu Dec 02 2010 Alexey Berezhok <alexey_com@ukr.net> 0.3-5
- Change NaN to Ovf. Remove color scheme for usually item string

* Fri Nov 19 2010 Alexey Berezhok <alexey_com@ukr.net> 0.3-4
- Add toggle color mode and two-color mode by one key. Remove command help and colorize

* Wed Nov 17 2010 Alexey Berezhok <alexey_com@ukr.net> 0.3-3
- Add color mode for dbtop, add output all parameters(1,2,3,4 - screens), Ctrl+C - exit, merge CAUSE and TIMEOUT field

* Tue Nov 16 2010 Alexey Berezhok <alexey_com@ukr.net> 0.3-2
- Add dbtop-help, view sorted column, add cause of restrict, add correct view after resizing

* Fri Nov 12 2010 Alexey Berezhok <alexey_com@ukr.net> 0.3-1
- Add new dbtop view and sort, add suport mysql command KILL CONNECTION|QUERY 'user_name', add check mysql version

* Thu Nov 04 2010 Alexey Berezhok <alexey_com@ukr.net> 0.2-1                                                                                                
- db_governor opens two db connections: for reading, for sending command

* Mon Nov 01 2010 Alexey Berezhok <alexey_com@ukr.net> 0.2-0.1
- Add dynamic loading mysql client's library

* Wed Oct 27 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.4
- Add detail log info. Add analyzing testmode parameter (report interval). Output max values info into log file in test mode

* Mon Sep 27 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.4
- Add notification on zero default limit

* Mon Sep 20 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.4
- Add reading timeout from cfg. dbtop crashed when terminal resized, dbtop displayed number in format -0.000

* Thu Sep 16 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.4
- Remove README from /var/log/db_governor

* Wed Sep 15 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.4
- Add client section analizing in ~/.my.cnf

* Tue Sep 14 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.4
- Add client section analizing in my.cnf

* Mon Sep 13 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.4
- Killconnection was divided on killconnection and killquery

* Fri Aug 27 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.4
- Package is divided into two parts connector and manager

* Thu Aug 26 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.3
- Add c-parameter - kill connections type

* Fri Jul 09 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.2
- New init.d script. Add test statistics.

* Mon Jun 21 2010 Alexey Berezhok <alexey_com@ukr.net> 0.1-0.1
- Initial Package

