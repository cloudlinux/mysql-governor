#!/bin/bash

set -xe

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
#bin/dbtop -c
