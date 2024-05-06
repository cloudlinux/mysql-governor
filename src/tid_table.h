/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef TID_TABLE_H_
#define TID_TABLE_H_

#include <sys/time.h>
#include "data.h"

typedef struct __cnt_user_threads
{
	char username[USERNAMEMAXLEN];
	int max_simultaneous_requests;
} cnt_user_threads;

typedef struct __tid_table
{
	char username[USERNAMEMAXLEN];
	long long cpu;
	long long read;
	long long write;
	time_t update_time;
	long naoseconds;
	pid_t pid;
	int fd;
	//improved accuracy
	int type;
	unsigned int cnt;
	pid_t tid;
	long long cpu_end;
	long long read_end;
	long long write_end;
	time_t update_time_end;
	long nanoseconds_end;
	struct timeval utime_begin;
	struct timeval stime_begin;
	struct timeval utime_end;
	struct timeval stime_end;
} tid_table;

typedef struct __Stat_counters
{
	Stats s;
	double tm;
} Stat_counters;

void free_tid (gpointer ti);
void free_tid_key (gpointer ti);
int init_tid_table (void);
void free_tid_table (void);
void add_new_tid_data (client_data * tbl, int fd);
void add_new_begin_tid_data (client_data * tbl, int fd);
void add_new_end_tid_data (client_data * tbl);
tid_table *get_tid_data (pid_t tid, tid_table * buf);
void remove_tid_data (pid_t tid);
void proceed_tid_data (GHFunc func, gpointer user_data);
void add_new_tid_data2 (pid_t tid, tid_table * tbl);
void remove_tid_data_by_fd (int fd);
void reset_counters (char *username);
void increment_counters (char *username, double cpu, long long read,
			 long long write, double tm);
GHashTable *get_counters_table (void);
void add_tid_to_bad_list (pid_t pid);
long get_tid_size (void);
void unlock_tid_data (void);
void lock_tid_data (void);

int get_cnt_threads (const char *username);
#ifdef TEST
void print_tid_data (void);
#endif


#endif /* TID_TABLE_H_ */
