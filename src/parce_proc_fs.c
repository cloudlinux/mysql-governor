/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/time.h>

#include "parce_proc_fs.h"

#define FILENAME        "/proc/stat"
#define LINUX_VERSION_CODE(x,y,z)   (0x10000*(x) + 0x100*(y) + z)

unsigned long os_version_code;
long smp_num_cpus = 1;

static int
file_exists (char *fileName)
{
	struct stat buf;
	int i = stat (fileName, &buf);
	if (i < 0)
		return 0;
	else
	{
		if (S_ISDIR (buf.st_mode))
		{
			return 1;
		}
		else
		{
			return 0;
		}
	}
}

static inline char *
next_token (const char *p)
{
	while (isspace (*p))
		p++;
	return (char *) p;
}

static char *
skip_token (const char *p)
{
	p = next_token (p);
	while (*p && !isspace (*p))
		p++;
	p = next_token (p);
	return (char *) p;
}

static int
has_sysfs (void)
{
	static int init;
	static int sysfs;

	if (!init)
	{
		sysfs = file_exists ("/sys");
		init = 1;
	}

	return sysfs;
}

static int
set_linux_version (void)
{
	struct utsname uts;
	unsigned x = 0, y = 0, z = 0;

	if (uname (&uts) == -1)
		return -1;
	sscanf (uts.release, "%u.%u.%u", &x, &y, &z);
	if (LINUX_VERSION_CODE (x, y, z) >= LINUX_VERSION_CODE (2, 6, 0)
		&& !has_sysfs ())
		return -1;

	os_version_code = LINUX_VERSION_CODE (x, y, z);
	return 0;
}

static int
try_file_to_buffer (char *buffer, const char *format, ...)
{
	char path[_PATH_SIZE];
	int fd;
	ssize_t len;
	va_list pa;

	va_start (pa, format);

	vsnprintf (path, sizeof path, format, pa);

	va_end (pa);

	buffer[0] = '\0';

	if ((fd = open (path, O_RDONLY)) < 0)
		return TRY_FILE_TO_BUFFER_OPEN_IOSTAT;

	len = read (fd, buffer, BUFSIZ - 1);
	close (fd);

	if (len < 0)
		return TRY_FILE_TO_BUFFER_READ_IOSTAT;

	buffer[len] = '\0';

	return TRY_FILE_TO_BUFFER_OK_IOSTAT;
}

static unsigned long long get_scaled_iostat(const char *buffer, const char *key)
{
	unsigned long long value = 0;
	const char *ptr = strstr(buffer, key);
	if (ptr)
	{
		ptr += strlen(key);
		char *next;
		value = strtoull(ptr, &next, 0);
		if (strchr(next, 'k'))
			value *= 1024;
		else if (strchr (next, 'M'))
			value *= 1024 * 1024;
	}
	else
	{
		//g_warning ("Could not read key '%s' in buffer '%s'", key, buffer);
	}
	return value;
}

int
get_io_stat (dbgov_iostat * info, pid_t pid, pid_t tid)
{
	char buffer[BUFSIZ];
	io_stat_reset (info);
	int res = try_file_to_buffer (buffer, "/proc/%d/task/%d/io", pid, tid);
	if (res == TRY_FILE_TO_BUFFER_OK_IOSTAT)
	{
		info->rchar = get_scaled_iostat (buffer, "rchar:");
		info->wchar = get_scaled_iostat (buffer, "wchar:");
		info->read_bytes = get_scaled_iostat (buffer, "read_bytes:");
		info->write_bytes = get_scaled_iostat (buffer, "write_bytes:");
		info->cancelled_write_bytes =
		get_scaled_iostat (buffer, "cancelled_write_bytes:");
		if (info->cancelled_write_bytes <= info->write_bytes)
		{
			info->write_bytes = info->write_bytes - info->cancelled_write_bytes;
		}
		else
		{
			info->write_bytes = 0;
		}
	}
	else
	{
		return -2;
	}
	return 0;
}

void
io_stat_reset (dbgov_iostat * info)
{
	memset (info, 0, sizeof (dbgov_iostat));
}

void
get_cpu (dbgov_cpu * buf)
{
	char buffer[BUFSIZ], *p;

	memset (buf, 0, sizeof (dbgov_cpu));

	int res = try_file_to_buffer (buffer, FILENAME);
	if (res == TRY_FILE_TO_BUFFER_OK_IOSTAT)
	{
		p = skip_token (buffer);
		buf->user = strtoull (p, &p, 0);
		buf->nice = strtoull (p, &p, 0);
		buf->sys = strtoull (p, &p, 0);
		buf->idle = strtoull (p, &p, 0);
		buf->total = buf->user + buf->nice + buf->sys + buf->idle;

		/* 2.6 kernel */
		if (os_version_code >= LINUX_VERSION_CODE (2, 6, 0))
		{
			buf->iowait = strtoull (p, &p, 0);
			buf->irq = strtoull (p, &p, 0);
			buf->softirq = strtoull (p, &p, 0);

			buf->total += buf->iowait + buf->irq + buf->softirq;
		}

		buf->frequency = 100;
	}
}

int
dbgov_init (void)
{
	smp_num_cpus = sysconf (_SC_NPROCESSORS_ONLN);
	if (smp_num_cpus < 1)
		smp_num_cpus = 1;
	return set_linux_version ();
}

static inline char *
proc_stat_after_cmd (char *p)
{
	p = strrchr (p, ')');
	if (p)
		*p++ = '\0';
	return p;
}

static inline char *
skip_multiple_token (const char *p, size_t count)
{
	while (count--)
		p = skip_token (p);

	return (char *) p;
}

int
get_proc_time (dbgov_proc_time * buf, pid_t pid, pid_t tid)
{
	char buffer[BUFSIZ], *p;
	memset (buf, 0, sizeof (dbgov_proc_time));

	int res = try_file_to_buffer (buffer, "/proc/%d/task/%d/stat", pid, tid);
	if (res == TRY_FILE_TO_BUFFER_OK_IOSTAT)
	{
		p = proc_stat_after_cmd (buffer);
		if (!p)
		return -1;

		p = skip_multiple_token (p, 11);

		buf->utime = strtoull (p, &p, 0);
		buf->stime = strtoull (p, &p, 0);
		buf->rtime = buf->utime + buf->stime;
		buf->cutime = strtoull (p, &p, 0);
		buf->cstime = strtoull (p, &p, 0);
		p = skip_multiple_token (p, 3);
		buf->it_real_value = strtoull (p, &p, 0);
		buf->frequency = 100;
	}
	else
	{
		return -2;
	}
	return 0;
}

#define FILENAMEMEM        "/proc/meminfo"

void
get_mem (dbgov_mem * buf)
{
	char buffer[BUFSIZ];
	memset (buf, 0, sizeof *buf);

	int res = try_file_to_buffer (buffer, FILENAMEMEM);
	if (res == TRY_FILE_TO_BUFFER_OK_IOSTAT)
	{
		buf->total = get_scaled_iostat (buffer, "MemTotal:");
		buf->free = get_scaled_iostat (buffer, "MemFree:");
		buf->used = buf->total - buf->free;
		buf->shared = 0;
		buf->buffer = get_scaled_iostat (buffer, "Buffers:");
		buf->cached = get_scaled_iostat (buffer, "Cached:");

		buf->user = buf->total - buf->free - buf->cached - buf->buffer;
	}
}

static size_t
get_page_size (void)
{
	static size_t pagesize = 0;

	if (!pagesize)
	{
		pagesize = getpagesize ();
	}

	return pagesize;
}

void
get_proc_mem (dbgov_proc_mem * buf, pid_t pid, pid_t tid)
{
	char buffer[BUFSIZ], *p;
	const size_t pagesize = get_page_size ();
	memset (buf, 0, sizeof (dbgov_proc_mem));

	int res = try_file_to_buffer (buffer, "/proc/%d/task/%d/stat", pid, tid);
	if (res == TRY_FILE_TO_BUFFER_OK_IOSTAT)
	{
		p = proc_stat_after_cmd (buffer);
		if (!p)
			return;

		p = skip_multiple_token (p, 20);

		buf->vsize = strtoull (p, &p, 0);
		buf->rss = strtoull (p, &p, 0);
		buf->rss_rlim = strtoull (p, &p, 0);

		int res =
			try_file_to_buffer (buffer, "/proc/%d/task/%d/statm", pid, tid);
		if (res == TRY_FILE_TO_BUFFER_OK_IOSTAT)
		{
			buf->size = strtoull (buffer, &p, 0);
			buf->resident = strtoull (p, &p, 0);
			buf->share = strtoull (p, &p, 0);
		}
		buf->size *= pagesize;
		buf->resident *= pagesize;
		buf->share *= pagesize;
		buf->rss *= pagesize;
	}
}

long
get_cpu_num (void)
{
	return smp_num_cpus;
}
