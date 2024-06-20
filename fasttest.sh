#!/bin/bash

set -xe

cd /home/gerrit/governor-mysql
rm -rf governor-mysql-1.2.tar.bz2
rm -rf governor-mysql-1.2
rsync -av --exclude='.git' --exclude=bin --exclude=CMakeCache . governor-mysql-1.2/
tar czvf governor-mysql-1.2.tar.bz2 governor-mysql-1.2
rm -rf governor-mysql-1.2
cp governor-mysql-1.2.tar.bz2 /root/rpmbuild/SOURCES/
rpmbuild -bb db_governor.spec
#yum reinstall -y /root/rpmbuild/RPMS/noarch/governor-mysql-lvepatch-1.2-114.el8.cloudlinux.noarch.rpm
cd -

#exit

# .patch -> mysql-...modified/
cd /home/gerrit/mysql-5.0
rm -rf mysql-8.0.37.modified
tar xzfp mysql_8.0.37.orig.tar.gz
mv mysql-8.0.37 mysql-8.0.37.modified
patch -p1 -Z -d mysql-8.0.37.modified < cloudlinux_lve_8_0_37.patch
cd -

# build MySQL
cd /home/gerrit/mysql-5.0
# mysql-...modified/ -> .patch:
#(diff -rupN mysql-8.0.37.orig mysql-8.0.37.modified > debian/patches/cloudlinux_lve_8_0_37.patch || true)
rm -rf /root/rpmbuild/SOURCES/lve-patch
mkdir -p /root/rpmbuild/SOURCES/lve-patch
cp *.patch 	/root/rpmbuild/SOURCES/
cp -a debian/source/lve-patch/* /root/rpmbuild/SOURCES/lve-patch/
cp mysql_8.0.37.orig.tar.gz /root/rpmbuild/SOURCES/
cp boost_1_77_0.tar.bz2 /root/rpmbuild/SOURCES/
rpmbuild -bb mysql.spec
cd -

yum reinstall -y /root/rpmbuild/RPMS/x86_64/governor-mysql-1.2-114.el8.cloudlinux.x86_64.rpm
yum reinstall -y /root/rpmbuild/RPMS/x86_64/cl-MySQL80-server-8.0.37-1.el8.cloudlinux.x86_64.rpm

pytest --noconftest --exitfirst ../QA/c-projects/governor_pytest/tst_extended_logging.py

exit







./build.sh

systemctl stop mysqld
cp lib/libgovernor.so /usr/lib64/libgovernor.so.1.2
rm -f /var/log/mysqld.log
rm -f /var/log/dbgovernor-mysqld.log
systemctl start mysqld
sleep 1

systemctl stop db_governor
cp bin/db_governor /usr/sbin/
rm -f /var/log/dbgovernor-error.log
rm -f /var/lve/dbgovernor/log-*.flag
echo > /var/lve/dbgovernor/log-all.flag
systemctl start db_governor
sleep 1

systemctl restart mysqld

cat /var/log/dbgovernor-error.log
cat /var/log/dbgovernor-mysqld.log
cat /var/log/mysqld.log
../QA/c-projects/governor_manualtest/test.py -m -a 1
bin/dbtop -c


with_sha2 = 'with caching_sha2_password' if re.match(r"\b8\.0\.(37|38|39)\b", get_version()) else ''
