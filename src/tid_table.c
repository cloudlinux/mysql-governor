/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#include "tid_table.h"
#include "dbgovernor_string_functions.h"
#include "calc_stats.h"

#define SEC2NANO 1000000000

static GHashTable *threads_list = NULL;
static GHashTable *user_counters_list = NULL;
static GList *bad_tid_list = NULL;

pthread_mutex_t mtx_tid = PTHREAD_MUTEX_INITIALIZER;

void
add_tid_to_bad_list (pid_t pid)
{
	if (!bad_tid_list)
	{
		bad_tid_list = g_list_alloc ();
	}
	pid_t *ptr = malloc (sizeof (pid_t));
	if (ptr)
	{
		*ptr = pid;
		bad_tid_list = g_list_append (bad_tid_list, ptr);
	}
}

void
remove_tid_data_inner (pid_t * pid, void *data)
{
	if (pid)
		remove_tid_data (*pid);
}

void
remove_tid_bad_from_list (void)
{
	g_list_foreach (bad_tid_list, (GFunc) remove_tid_data_inner, NULL);
}

void
free_commands_bad (pid_t * cmd, GDestroyNotify free_func)
{
	if (cmd)
	{
		free_func (cmd);
	}
}

void
g_list_free_full_tid_bad_my (GList * list, GDestroyNotify free_func)
{
	if (list)
		g_list_foreach (list, (GFunc) free_commands_bad, (void *) free_func);
	g_list_free (list);
}

void
remove_tid_bad_list (void)
{
	if (bad_tid_list)
	{
		g_list_free_full_tid_bad_my (bad_tid_list, free);
		bad_tid_list = NULL;
	}
}

//Work with tid->username

void
free_tid (gpointer ti)
{
	free (ti);
}

void
free_tid_key (gpointer ti)
{
	free (ti);
}

int
init_tid_table (void)
{
	threads_list = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL,
						free_tid);
	if (!threads_list)
		return -1;
	user_counters_list = g_hash_table_new_full (g_str_hash, g_str_equal,
							free_tid_key, free_tid);
	if (!user_counters_list)
		return -1;
	return 0;
}

void
free_tid_table (void)
{
	if (threads_list)
	{
		pthread_mutex_lock (&mtx_tid);
		//g_hash_table_foreach(threads_list, (GHFunc) free_tid, NULL);
		//g_hash_table_unref(threads_list);
		g_hash_table_destroy (threads_list);
		g_hash_table_destroy (user_counters_list);
		pthread_mutex_unlock (&mtx_tid);
	}
}

#define LOAD_NEW_TID_STATS(x) (tbl->x<new_data->x)?new_data->x:tbl->x;

void
add_new_tid_data (client_data * tbl, int fd)
{
	pthread_mutex_lock (&mtx_tid);
	tid_table *item = g_hash_table_lookup (threads_list,
						GINT_TO_POINTER (tbl->tid));
	if (!item)
	{
		tid_table *new_data = malloc (sizeof (tid_table));
		if (new_data)
		{
			memset (new_data->username, 0, USERNAMEMAXLEN * sizeof (char));
			strlcpy (new_data->username, tbl->username, USERNAMEMAXLEN);
			new_data->cpu = tbl->cpu;
			new_data->read = tbl->read;
			new_data->write = tbl->write;
			new_data->pid = tbl->pid;
			new_data->fd = fd;
			//struct timespec cur_tm;
			//clock_gettime(CLOCK_REALTIME, &cur_tm);
			new_data->update_time = tbl->update_time;
			new_data->nanoseconds = tbl->nanoseconds;
#ifdef TEST
			//printf("save %d time %f\n", tbl->tid, tbl->update_time + (double) tbl->nanoseconds / (double) SEC2NANO);
#endif
			g_hash_table_insert (threads_list, GINT_TO_POINTER (tbl->tid),
					new_data);
		}
	}
	else
	{
		tid_table *new_data = item;
		memset (new_data->username, 0, USERNAMEMAXLEN * sizeof (char));
		strlcpy (new_data->username, tbl->username, USERNAMEMAXLEN);
		new_data->cpu = LOAD_NEW_TID_STATS (cpu);
		new_data->read = LOAD_NEW_TID_STATS (read);
		new_data->write = LOAD_NEW_TID_STATS (write);
		new_data->pid = tbl->pid;
		new_data->fd = fd;
		//struct timespec cur_tm;
		//clock_gettime(CLOCK_REALTIME, &cur_tm);
		new_data->update_time = tbl->update_time;
		new_data->nanoseconds = tbl->nanoseconds;
#ifdef TEST
		//printf("save %d time %f\n", tbl->tid, tbl->update_time + (double) tbl->nanoseconds / (double) SEC2NANO);
#endif
		//g_hash_table_replace(threads_list, tmp_key, new_data);
	}
	pthread_mutex_unlock (&mtx_tid);
}

void
add_new_tid_data2 (pid_t tid, tid_table * tbl)
{
	pthread_mutex_lock (&mtx_tid);
	tid_table *item = g_hash_table_lookup (threads_list, GINT_TO_POINTER (tid));
	if (!item)
	{
		tid_table *new_data = malloc (sizeof (tid_table));
		if (new_data)
		{
			strlcpy (new_data->username, tbl->username, USERNAMEMAXLEN);
			new_data->cpu = tbl->cpu;
			new_data->read = tbl->read;
			new_data->write = tbl->write;
			new_data->pid = tbl->pid;
			struct timespec cur_tm;
			clock_gettime (CLOCK_REALTIME, &cur_tm);
			new_data->update_time = cur_tm.tv_sec;
			new_data->nanoseconds = cur_tm.tv_nsec;
			new_data->fd = tbl->fd;
			g_hash_table_insert (threads_list, GINT_TO_POINTER (tid), new_data);
		}
	}
	else
	{
		tid_table *new_data = item;
		strlcpy (new_data->username, tbl->username, USERNAMEMAXLEN);
		new_data->cpu = LOAD_NEW_TID_STATS (cpu);
		new_data->read = LOAD_NEW_TID_STATS (read);
		new_data->write = LOAD_NEW_TID_STATS (write);
		new_data->pid = tbl->pid;
		struct timespec cur_tm;
		clock_gettime (CLOCK_REALTIME, &cur_tm);
		new_data->update_time = cur_tm.tv_sec;
		new_data->nanoseconds = cur_tm.tv_nsec;
		new_data->fd = tbl->fd;
		//g_hash_table_replace(threads_list, tmp_key, new_data);
	}
	pthread_mutex_unlock (&mtx_tid);
}

void
add_new_begin_tid_data (client_data * tbl, int fd)
{
	pthread_mutex_lock (&mtx_tid);
	tid_table *item = g_hash_table_lookup (threads_list, GINT_TO_POINTER (tbl->tid));

	//thread already registered
	if (item)
	{
		//This thread was used by another user
		if (strncmp(tbl->username, item->username, USERNAMEMAXLEN))
		{
#ifdef TEST
			printf("!!! Thread changed user TIDs:%d/%d cnt:%d Usernames '%s'->'%s'\n", tbl->tid, item->tid, item->cnt, item->username, tbl->username);
#endif
			double cpu = item->cpu_end;
			//use rusage
			if ((-1 != item->stime_begin.tv_sec) && (-1 != item->utime_begin.tv_sec))
			{
				cpu = calc_cpu_from_rusage(item);
				item->cpu = 0;
			}
			calc_stats_difference_inner_add_to_counters (cpu, item->read_end, item->write_end, item);
			g_hash_table_remove (threads_list, GINT_TO_POINTER (tbl->tid));
		}
		//update begin info
		else
		{
			item->type = tbl->type;
			pthread_mutex_unlock (&mtx_tid);
			return;
		}
	}

	//new thread
	tid_table *new_data = malloc (sizeof (tid_table));
	if (!new_data)
	{
		pthread_mutex_unlock (&mtx_tid);
		return;
	}

	memset (new_data->username, 0, USERNAMEMAXLEN * sizeof (char));
	strlcpy (new_data->username, tbl->username, USERNAMEMAXLEN);
	new_data->fd = fd;
	new_data->cpu = tbl->cpu;
	new_data->read = tbl->read;
	new_data->write = tbl->write;
	new_data->pid = tbl->pid;
	new_data->update_time = tbl->update_time;
	new_data->nanoseconds = tbl->nanoseconds;

	//improved accuracy
	new_data->type = tbl->type;
	new_data->cnt = 0;
	new_data->tid = tbl->tid;
	new_data->cpu_end = tbl->cpu;
	new_data->read_end = tbl->read;
	new_data->write_end = tbl->write;
	new_data->update_time_end = tbl->update_time;
	new_data->nanoseconds_end = tbl->nanoseconds;
	new_data->utime_begin = tbl->utime;
	new_data->stime_begin = tbl->stime;
	new_data->utime_end = tbl->utime;
	new_data->stime_end = tbl->stime;

	g_hash_table_insert (threads_list, GINT_TO_POINTER (tbl->tid), new_data);

	pthread_mutex_unlock (&mtx_tid);
}

#define LOAD_NEW_END_TID_STATS(x) (tbl->x<new_data->x ## _end)?new_data->x ## _end:tbl->x;
void
add_new_end_tid_data (client_data * tbl)
{
	pthread_mutex_lock (&mtx_tid);
	tid_table *item = g_hash_table_lookup (threads_list, GINT_TO_POINTER (tbl->tid));
	if (!item)
	{
		pthread_mutex_unlock (&mtx_tid);
		return;
	}

	tid_table *new_data = item;
	new_data->type = tbl->type;
	new_data->cnt++;
	new_data->cpu_end = LOAD_NEW_END_TID_STATS (cpu);
	new_data->read_end = LOAD_NEW_END_TID_STATS (read);
	new_data->write_end = LOAD_NEW_END_TID_STATS (write);
	new_data->update_time_end = tbl->update_time;
	new_data->nanoseconds_end = tbl->nanoseconds;
	new_data->utime_end = tbl->utime;
	new_data->stime_end = tbl->stime;

	pthread_mutex_unlock (&mtx_tid);
}

tid_table *
get_tid_data (pid_t tid, tid_table * buf)
{
	pthread_mutex_lock (&mtx_tid);
	tid_table *item = g_hash_table_lookup (threads_list, GINT_TO_POINTER (tid));
	if (item)
	{
		memcpy (buf, item, sizeof (tid_table));
	}
	pthread_mutex_unlock (&mtx_tid);
	return item;
}

void
remove_tid_data (pid_t tid)
{
	pthread_mutex_lock (&mtx_tid);
	//tid_table *item = g_hash_table_lookup(threads_list, GINT_TO_POINTER(tid));
	//if (item) {
	g_hash_table_remove (threads_list, GINT_TO_POINTER (tid));
	//}
	pthread_mutex_unlock (&mtx_tid);
	//return item;
}

void
func_remove (gpointer key, tid_table * item, gpointer fd)
{
	if (!item)
		return;
	int *ifd = (int *) fd;
	if (item->fd == *ifd)
	{
		g_return_if_fail (threads_list != NULL);
		g_hash_table_remove (threads_list, key);
	}
}

void
remove_tid_data_by_fd (int fd)
{
	pthread_mutex_lock (&mtx_tid);
	g_hash_table_foreach (threads_list, (GHFunc) func_remove, (gpointer) & fd);
	pthread_mutex_unlock (&mtx_tid);
}

void
process_tid_data (GHFunc func, gpointer user_data)
{
	pthread_mutex_lock (&mtx_tid);
	g_hash_table_foreach (threads_list, func, user_data);
	pthread_mutex_unlock (&mtx_tid);
	remove_tid_bad_from_list ();
	remove_tid_bad_list ();
}

void increment_counters(const char *username, double cpu, long long read, long long write, double tm)
{
	Stat_counters *item = g_hash_table_lookup(user_counters_list, username);
	if (item)
	{
		item->s.cpu += cpu;
		item->s.read += read;
		item->s.write += write;
#ifdef TEST
		//printf("increment counter %s, %f c %f, r %ld, w %ld\n", username, item->tm, item->s.cpu, item->s.read, item->s.write);
#endif
	}
	else
	{
		item = malloc (sizeof (Stat_counters));
		if (item)
		{
			char *user_nm = malloc (USERNAMEMAXLEN * sizeof (char));
			strlcpy (user_nm, username, USERNAMEMAXLEN);
			item->s.cpu = (double) cpu;
			item->s.read = read;
			item->s.write = write;
			//struct timespec cur_tm;
			//clock_gettime(CLOCK_REALTIME, &cur_tm);
			//double new_tm = cur_tm.tv_sec
			//              + (double) cur_tm.tv_nsec / (double) SEC2NANO;
			item->tm = tm;
#ifdef TEST
			//printf("Create counter %s, %f c %ld, r %ld, w %ld\n", username, item->tm, cpu, read, write);
#endif
			g_hash_table_insert (user_counters_list, user_nm, item);
		}
	}
}

void reset_counters(const char *username)
{
	Stat_counters *item = g_hash_table_lookup (user_counters_list, username);
	if (item)
	{
		item->s.cpu = 0;
		item->s.read = 0;
		item->s.write = 0;
		struct timespec cur_tm;
		clock_gettime (CLOCK_REALTIME, &cur_tm);
		double new_tm = cur_tm.tv_sec + (double) cur_tm.tv_nsec / (double) SEC2NANO;
		item->tm = new_tm;
#ifdef TEST
		//printf("Reset counter %s, %f\n", username, item->tm);
#endif
	}
}

GHashTable *
get_counters_table (void)
{
	return user_counters_list;
}

long
get_tid_size (void)
{
	pthread_mutex_lock (&mtx_tid);
	if (threads_list)
	{
		long tmp = g_hash_table_size (threads_list);
		pthread_mutex_unlock (&mtx_tid);
		return tmp;
	}
	pthread_mutex_unlock (&mtx_tid);
	return 0;
}

void
func_calc_threads (gpointer key, tid_table * item, gpointer CntUserThreads)
{
	if (!item)
		return;

	cnt_user_threads *CntUserThreads__ = (cnt_user_threads *) CntUserThreads;
	if (strcmp (item->username, CntUserThreads__->username) == 0)
	{
		CntUserThreads__->max_simultaneous_requests++;
	}
}

int
get_cnt_threads (const char *username)
{
	cnt_user_threads CntUserThreads;

	strncpy (CntUserThreads.username, username, USERNAMEMAXLEN - 1);
	CntUserThreads.max_simultaneous_requests = 0;

	pthread_mutex_lock (&mtx_tid);
	g_hash_table_foreach (threads_list, (GHFunc) func_calc_threads,
				(gpointer) & CntUserThreads);
	pthread_mutex_unlock (&mtx_tid);

	return CntUserThreads.max_simultaneous_requests;
}

void
lock_tid_data (void)
{
	pthread_mutex_lock (&mtx_tid);
}

void
unlock_tid_data (void)
{
	pthread_mutex_unlock (&mtx_tid);
}

#ifdef TEST
void
print_tid_data_item (gpointer key, tid_table * item, gpointer user_data)
{
	pid_t kkey = GPOINTER_TO_INT (key);
	printf ("User %s TID %d FD %d\n", item->username, kkey, item->fd);
}

void
print_tid_data (void)
{
	printf ("----------------------------Head-------------------------\n");
	pthread_mutex_lock (&mtx_tid);
	g_hash_table_foreach (threads_list, print_tid_data_item, NULL);
	pthread_mutex_unlock (&mtx_tid);
	printf ("----------------------------Tail-------------------------\n");
}
#endif
