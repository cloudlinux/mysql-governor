/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

// Mutex structure, shared between Governor and patched MySQL

#pragma once

#include <sys/types.h>

typedef struct __governor_mutex
{
	pid_t key; 				// thread_id
	int is_in_lve;
	int is_in_mutex;		// mutex_lock count
	int unused_put_in_lve;	// see long comment below about governor_setlve_mysql_thread_info()
	int critical;
	int was_in_lve;
} governor_mutex;

/*
The only use of "put_in_lve" member was observed in this function,
defined in MysQL/MariaDB patches but never called, at least since 2016:

void governor_setlve_mysql_thread_info(pid_t thread_id)
{
	pid_t *buf = NULL;
	mysql_mutex *mm = nullptr;
	pthread_mutex_lock(&mtx_mysql_lve_mutex_governor_ptr);
	if (mysql_lve_mutex_governor)
	{
		buf = (pid_t *)((intptr_t)thread_id);
		mm = (mysql_mutex *) my_hash_search(mysql_lve_mutex_governor, (uchar *) buf, sizeof(buf));
		if (mm)
		{
			if (!mm->is_in_lve)
				mm->put_in_lve = 1;
		}
	}
	pthread_mutex_unlock(&mtx_mysql_lve_mutex_governor_ptr);
}

Looked like an unfinished or abandoned idea.
It was used in tests, though, but it's only written and printed there, and no decisions are taken based on its value.

Member renamed "put_in_lve" -> "unused_put_in_lve", instead of deleting - for cl-MySQL/Governor bidirectional binary compatibility.
Function definition removed from MySQL patches.
*/

