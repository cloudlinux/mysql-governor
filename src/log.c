/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "data.h"
#include "governor_config.h"
#include "dbgovernor_string_functions.h"
#include "version.h"
#include "log.h"

#define SENTRY_FLAG_DISABLED		PATH_TO_GOVERNOR_PRIVATE_DIR "/sentry-disabled.flag"
#define SENTRY_FLAG_FORCE_4_ERR		PATH_TO_GOVERNOR_PRIVATE_DIR "/sentry-force-4-err.flag"
#define SENTRY_FLAG_FORCE_4_ALL		PATH_TO_GOVERNOR_PRIVATE_DIR "/sentry-force-4-all.flag"

#define _L_MASK_ALL		((1 << LOG_TAG_BITS) - 1)
#define _L_NO_SENTRY	(1 << LOG_TAG_BITS)		// not an actual tag, but a flag used internally to avoid infinite recursion, by disabling Sentry for LOG()s that tell about passing LOG() to Sentry

static FILE *log = NULL, *restrict_log = NULL, *slow_queries_log = NULL;

int open_log(const char *path)
{
	if ((log = fopen(path, "a")) == NULL)
		return errno;
	setlinebuf(log);	// it's better than fflush() each time, especially for many threads, because the pair 'fputs()/fwrite()/f...() + fflush()' locks the internal stdio mutex TWICE
	return 0;
}

int open_restrict_log(const char *path)
{
	if ((restrict_log = fopen(path, "a")) == NULL)
		return errno;
	return 0;
}

int open_slow_queries_log(const char *path)
{
	if ((slow_queries_log = fopen(path, "a")) == NULL)
		return errno;
	return 0;
}

int close_log()
{
	if (log && fclose(log))
	{
		log = NULL;
		return errno;
	}
	log = NULL;
	return 0;
}

int close_restrict_log()
{
	if (restrict_log && fclose(restrict_log))
	{
		restrict_log = NULL;
		return errno;
	}
	restrict_log = NULL;
	return 0;
}

int close_slow_queries_log()
{
	if (slow_queries_log && fclose(slow_queries_log))
	{
		slow_queries_log = NULL;
		return errno;
	}
	slow_queries_log = NULL;
	return 0;
}

// let's cache PID and TID for a thread, the APIs are not very cheap. Nginx does smth similar for its logging.
static pid_t fast_pid()
{
	static __thread pid_t pid = 0;	// let's cache it for a thread, API is not cheap. Nginx does smth similar for its logging.
	if (!pid)
		pid = getpid();
	return pid;
}

static pid_t fast_tid()
{
	static __thread pid_t tid = 0;	// let's cache it for a thread, API is not cheap. Nginx does smth similar for its logging.
	if (!tid)
		tid = gettid_p();
	return tid;
}

static int format_log_msg(char *buf, size_t bufSz, bool error, bool pid_tid, bool nano_time, const char *tags, const char *src_file, int src_line, const char *src_func, const Stats *limits, const char *fmt, va_list args)
{
	char *p = buf;
	size_t pSz = bufSz;
	int rc = 0;
	#define INC_P \
		do {\
			if (rc < 0 || rc >= (int)pSz)\
				return -1;\
			p += rc;\
			pSz -= rc;\
		} while (0)

	char timestamp[0x100];
	struct timespec ts;
	struct tm timeinfo;
	if (!clock_gettime(CLOCK_REALTIME, &ts) && localtime_r(&ts.tv_sec, &timeinfo) && strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo) > 0)
	{
		if (nano_time)
		{
			char ns[0x10] = "";
			snprintf(ns, sizeof(ns), ".%09ld", (long)ts.tv_nsec);
			strcat(timestamp, ns);
		}
	} else
		strcpy(timestamp, "unknown time");
	rc = snprintf(p, pSz, "[%s]", timestamp);
	INC_P;
	if (pid_tid)
	{
		rc = snprintf(p, pSz, " [%lu:%lu]", (unsigned long)fast_pid(), (unsigned long)fast_tid());
		INC_P;
	}
	if (!pSz)
		return -1;
	*p++ = error ? '!' : ' ';
	pSz--;
	if (src_file && src_line != -1 && src_func)
	{
		// According to man 3 basename, GNU version of basename is selected by defining _GNU_SOURCE + not including libgen.h
		rc = snprintf(p, pSz, "[%s:%d:%s] ", basename(src_file), src_line, src_func);
		INC_P;
	}
	if (tags)
	{
		rc = snprintf(p, pSz, "[%s] ", tags);
		INC_P;
	}

	rc = fmt ? vsnprintf(p, pSz, fmt, args) : snprintf(p, pSz, "format error");
	INC_P;
	bool msgNonEmpty = rc > 0;

	if (limits)
	{
		if (msgNonEmpty)
		{
			rc = snprintf(p, pSz, ", ");
			INC_P;
		}
		rc = snprintf(p, pSz, "cpu = %f, read = %lld, write = %lld", limits->cpu, limits->read, limits->write);
		INC_P;
	}

	if (pSz < 2)
		return -1;
	*p++ = '\n';
	size_t msgLen = p - buf;	// without NULL terminator
	*p++ = '\0';
	return msgLen;
}

int write_log_simple(FILE *f, const Stats *limits, const char *fmt, ...)
{
	if (!f)
		return -1;
	char msg[0x1000];
	va_list args;
	va_start(args, fmt);
	int msgLen = format_log_msg(msg, sizeof(msg), false, false, false, NULL, NULL, -1, NULL, limits, fmt, args);
	va_end(args);	// don't ever return from function before va_end() - undefined behaviour!
	if (msgLen <= 0)	// '\n' is always added, so msgLen should never be zero
		return -1;
	if (fwrite(msg, msgLen, 1, f) != 1 || fflush(f))		// TODO: consider setlinebuf() to avoid frequent fflush()
		return errno;
	return 0;
}

FILE *get_log()
{
	return log;
}

FILE *get_restrict_log()
{
	return restrict_log;
}

FILE *get_slow_queries_log()
{
	return slow_queries_log;
}

static const char *tag_names[] =	// in uppercase
{
	#define DEFINE_LOG_TAG(tag)	#tag,
	#include "log_tags.h"
	#undef DEFINE_LOG_TAG
};

// 'buf' isn't used in case of a single tag (and, naturally, 'delim' as well)
static const char *concat_tag_names(unsigned tags, const char *delim, bool lowerCase, char *buf, size_t bufSz)
{
	*buf = '\0';			// let's prepare right away to return an empty string
	char *p = NULL;			// we set it to 'buf' when we begin actual concatenation
	size_t delimLen = 0;	// same, needed only for actual concatenation
	int i;
	for (i=0; i < LOG_TAG_BITS; i++)
	{
		if (!tags)
			break;
		unsigned tag = 1 << i;
		if (!(tags & tag))
			continue;
		tags &= ~tag;		// forget it
		const char *s_tag = tag_names[i];
		if (!p && !tags)	// no tags so far (otherwise we'd start concatenation and set 'p') and no more tags
			return s_tag;	// return the only one, no need to concatenate
		if (!p)				// prepare for actual concatenation, if not yet
		{
			p = buf;
			delimLen = strlen(delim);	// very short usually
		}
		size_t len = strlen(s_tag);
		if (delimLen+len+1 > bufSz)		// delim + tag + '\0' don't fit
			return buf;					// only what we got so far
		if (p > buf)					// before any tag except the first, add a delimiter
		{
			memcpy(p, delim, delimLen);	// we don't add '\0' here, as we're sure we shall add it with 's_tag' below
			p += delimLen;
			bufSz -= delimLen;
		}
		memcpy(p, s_tag, len + 1);		// tag + '\0'
		bufSz -= len + 1;
		if (lowerCase)
		{
			char *pp;
			for (pp=p; pp < p + len; pp++)
				*pp = tolower((unsigned char)*pp);	// <ctype.h> is freakish about signed chars
		}
		p += len;	// add only real characters, point to current '\0'
	}
	return buf;
}

unsigned log_enabled_tags = 0;		// bitmask of enabled tags
unsigned log_verbosity_level = 1;
static const char *log_sentry_depot = NULL;
unsigned log_sentry_tags = 0;		// bitmask of tags that are duplicated to Sentry
static char log_mysql_version[0x100] = "";

#if !(__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9))	// only since gcc 4.9 we have a warning and have to suppress it. In earlier gcc we get warnings about our #pragmas suppressing that warning.
	#define SUPPRESS_DATE_TIME_WARNING
#endif

#ifdef SUPPRESS_DATE_TIME_WARNING
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wdate-time"
#endif // SUPPRESS_DATE_TIME_WARNING

void init_log_ex(bool enable_all_tags, const char *sentry_depot)
{
	log_enabled_tags = _L_MASK_ALWAYS_ENABLED;
	if (enable_all_tags)	// in debug mode, enable all tags
		log_enabled_tags = _L_MASK_ALL;
	else									// otherwise, check file-flags to enable corresponding tags
	{
		// calculate file-flags prefix
		static const int flag_max_size = 256;
		size_t blen = strlen(PATH_TO_GOVERNOR_PRIVATE_DIR);
		char fname[blen + flag_max_size];
		char *ptr = fname + blen;
		memcpy(fname, PATH_TO_GOVERNOR_PRIVATE_DIR, blen);	// without NULL
		int i;
		for (i=-1; i < LOG_TAG_BITS; i++)
		{
			unsigned tag = 0;
			const char *s_tag = NULL;
			int all = i==-1;
			if (all)
			{
				tag = _L_MASK_ALL;
				s_tag = "all";
			} else
			{
				tag = 1 << i;
				s_tag = tag_names[i];
			}
			size_t l_tag = strlen(s_tag);
			strcpy(ptr, "/log-");
			char *p_tag = ptr + strlen(ptr), *pp;
			strcpy(p_tag, s_tag);
			for (pp=p_tag; pp < p_tag + l_tag; pp++)
				*pp = tolower((unsigned char)*pp);	// <ctype.h> is freakish about signed chars
			strcat(ptr, ".flag");
			struct stat st;
			if (!stat(fname, &st))
			{
				log_enabled_tags |= tag;
				if (all)
					break;
			}
		}
	}
	log_sentry_depot = sentry_depot;
	log_sentry_tags = L_ERRSENTRY;
	struct stat st;
	if		(!stat(SENTRY_FLAG_DISABLED, &st))
		log_sentry_tags = 0;
	else if	(!stat(SENTRY_FLAG_FORCE_4_ALL, &st))
		log_sentry_tags = _L_MASK_ALL;
	else if	(!stat(SENTRY_FLAG_FORCE_4_ERR, &st))
		log_sentry_tags = _L_MASK_ERRORS;
	log_sentry_tags &= log_enabled_tags;
	// TODO: possibly we'll need configurable log_verbosity_level, for now it's constant
	char s_tags_ena_buf[0x1000] = "", s_tags_sen_buf[0x1000] = "", s_tags_dis_buf[0x1000] = "";	// three different buffers
	LOG(L_LIFE, "Logging enabled tags: [%s]; Sentry-reported tags: [%s]; verbosity level: %d; disabled tags: [%s]; Governor version: %s, built at %s %s",
		concat_tag_names( log_enabled_tags, ",", false, s_tags_ena_buf, sizeof(s_tags_ena_buf)),
		concat_tag_names( log_sentry_tags,  ",", false, s_tags_sen_buf, sizeof(s_tags_sen_buf)),
		log_verbosity_level,
		concat_tag_names(~log_enabled_tags, ",", true,  s_tags_dis_buf, sizeof(s_tags_dis_buf)),
		GOVERNOR_CUR_VER, __DATE__, __TIME__);
}

#ifdef SUPPRESS_DATE_TIME_WARNING
	#pragma GCC diagnostic pop
#endif // SUPPRESS_DATE_TIME_WARNING

void set_log_ex_mysql_version(const char *ver)
{
	strlcpy(log_mysql_version, ver, sizeof(log_mysql_version));
	char *p;
	for (p = log_mysql_version; *p; p++)
		if (!isalnum((unsigned char)*p) && !strchr("-.", *p))	// who knows what they can put there, and we use inside a file name
			*p = '-';
}

int write_log_ex(unsigned tags, unsigned level, const char *src_file, int src_line, const char *src_func, const char *fmt, ...)
{
	if (!((tags & log_enabled_tags) && level <= log_verbosity_level))
		return 0;
	if (!log)
		return -1;
	char s_tags_buf[0x1000] = "";
	const char *s_tags = concat_tag_names(tags, ":", false, s_tags_buf, sizeof(s_tags_buf));
#if 0  // TODO: when we have different levels indeed, we'll decide how to print them
	char lev[0x10];
	sprintf(lev, ":lev.%d", level);
#endif
	char msg[0x1000];
	va_list args;
	va_start(args, fmt);
	int msgLen = format_log_msg(msg, sizeof(msg), !!(tags & _L_MASK_ERRORS), true, true, s_tags, src_file, src_line, src_func, NULL, fmt, args);
	va_end(args);	// don't ever return from function before va_end() - undefined behaviour!
	if (msgLen <= 0)	// '\n' is always added, so msgLen should never be zero
		return -1;
	if (fwrite(msg, msgLen, 1, log) != 1)
		return errno;
	if ((tags & log_sentry_tags) && !(tags & _L_NO_SENTRY))
	{
		if (!log_sentry_depot)
		{
			LOG(L_ERR|_L_NO_SENTRY, "not sent to Sentry: no depot directory set up");
			return -1;
		}
		static __thread char path[PATH_MAX] = "";
		static __thread size_t pathLen = 0, offsFmtAddr = 0;
		static const char ext[] = SENTRY_DEPOT_EXT;
		static const char *uidFmt = "%016llx.%010lu";
		static const int uidLen = 16+1+10;	// 16 hex digits of 64-bit address of source file literal + 1 dot + 10 dec digits of line number
		if (!*path)
		{
			char *p = path;
			size_t pSz = sizeof(path);
			int rc = snprintf(p, pSz, "%s/%s-mysql.%lu.%lu.", log_sentry_depot, log_mysql_version, (unsigned long)fast_pid(), (unsigned long)fast_tid());
			INC_P;
			offsFmtAddr = p - path;
			rc = snprintf(p, pSz, uidFmt, (unsigned long long)0, (unsigned long)0);	// placeholder for error UID
			if (rc != uidLen)
				return -1;	// should never happpen. indeed, here we're just missing assert(), absent from our coding style
			INC_P;
			strncat(p, ext, pSz - 1);
			rc = sizeof(ext) - 1;
			INC_P;
			pathLen = p - path;
		}
		snprintf(path + offsFmtAddr, uidLen+1, uidFmt, (unsigned long long)(uintptr_t)src_file, (unsigned long)src_line);	// uintptr_t is to emphasize the use of address as an integer - it serves as a file UID throughout the code
		path[offsFmtAddr + uidLen] = ext[0];	// restore leading dot of extension, overwritten with NULL terminator by the above snprintf()
		struct stat st;
		if (!stat(path, &st))
			LOG(L_INFO|_L_NO_SENTRY, "not sent to Sentry: '%s' not consumed by watchdog yet", path);		// waiting for python watchdog to send it and remove the file
		else
		{
			char pathTmp[sizeof(path)];
			size_t pathTmpLen = pathLen - (sizeof(ext)-1);
			memcpy(pathTmp, path, pathTmpLen);
			pathTmp[pathTmpLen] = '\0';
			bool written = false;
			int fd = open(pathTmp, O_CREAT|O_EXCL|O_WRONLY, 0666);
			if (fd < 0)
				LOG(L_ERR|_L_NO_SENTRY, "failed to create '%s', errno=%d", pathTmp, errno);	// we can use L_ERR freely - we're already handling a severe error, otherwise we wouldn't send it to Sentry
			else
			{
				if (write(fd, msg, msgLen) != msgLen)
					LOG(L_ERR|_L_NO_SENTRY, "failed to write '%s', errno=%d", pathTmp, errno);
				else
					written = true;
				close(fd);
			}
			if (written && rename(pathTmp, path))	// supposed to be atomic
				LOG(L_ERR|_L_NO_SENTRY, "failed to rename '%s'->'%s', errno=%d", pathTmp, path, errno);
		}
	}
	return 0;
}

