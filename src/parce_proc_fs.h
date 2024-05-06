/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef PARCE_PROC_FS_H_
#define PARCE_PROC_FS_H_

#include <stdint.h>

#define _PATH_SIZE 4096

enum TRY_FILE_TO_BUFFER
{
	TRY_FILE_TO_BUFFER_OK_IOSTAT = 0,
	TRY_FILE_TO_BUFFER_OPEN_IOSTAT = -1,
	TRY_FILE_TO_BUFFER_READ_IOSTAT = -2
};

typedef struct _dbgov_iostat
{
	long long rchar;
	long long wchar;
	long long read_bytes;
	long long write_bytes;
	long long cancelled_write_bytes;
} dbgov_iostat;

typedef struct _dbgov_cpu
{
	uint64_t flags;
	uint64_t total;
	uint64_t user;
	uint64_t nice;
	uint64_t sys;
	uint64_t idle;
	uint64_t iowait;
	uint64_t irq;
	uint64_t softirq;
	uint64_t frequency;
} dbgov_cpu;

typedef struct _dbgov_proc_time
{
	uint64_t rtime;
	uint64_t utime;
	uint64_t stime;
	uint64_t cutime;
	uint64_t cstime;
	uint64_t timeout;
	uint64_t it_real_value;
	uint64_t frequency;
} dbgov_proc_time;

typedef struct _dbgov_mem
{
	uint64_t flags;
	uint64_t total;
	uint64_t used;
	uint64_t free;
	uint64_t shared;
	uint64_t buffer;
	uint64_t cached;
	uint64_t user;
	uint64_t locked;
} dbgov_mem;

typedef struct _dbgov_proc_mem
{
	uint64_t size;
	uint64_t vsize;
	uint64_t resident;
	uint64_t share;
	uint64_t rss;
	uint64_t rss_rlim;
} dbgov_proc_mem;

int get_io_stat (dbgov_iostat * info, pid_t pid, pid_t tid);
void io_stat_reset (dbgov_iostat * info);
int dbgov_init (void);
void get_cpu (dbgov_cpu * buf);
int get_proc_time (dbgov_proc_time * buf, pid_t pid, pid_t tid);
void get_mem (dbgov_mem * buf);
void get_proc_mem (dbgov_proc_mem * buf, pid_t pid, pid_t tid);
long get_cpu_num (void);

#endif /* PARCE_PROC_FS_H_ */
 