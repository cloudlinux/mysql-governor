#!/bin/bash

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <minutes>"
	exit 1
fi
minutes=$1

# Protect against disk bloating by Sentry-related files.

# This can happen under the two simultaneous conditions:
# 1) Producer (C code in db_governor and mysqld+libgovernor.so) is creating many small *.txt files with log messages for Sentry.
#    Normally, those files are periodically scanned by sentry_daemon.py, which sends them to Sentry and then deletes.
# 2) Consumer (sentry_daemon.py) is not working properly, or doesn't have capacity to delete the files as fast.
#
# Here we delete all *.txt files older than N minutes.
# We do this periodically in a cron job.
# N should be greater than sentry_daemon.py scan period - otherwise we are constantly deleting files in the middle of daemon scan period, before the daemon sees them.
#
# Note that files other than *.txt, are temporary and owned by C code. They are renamed to *.txt immediately after writing.
# Our cleanup shouldn't interfere with that process.

depot="/var/lve/dbgovernor/logging/sentry-depot/"
mask="*.txt"

find "$depot"  -type f  -name "$mask"  -mmin +"$minutes"  -print  -delete | wc -l | xargs -I {} echo "deleted {} files older than $minutes minutes from $depot"
