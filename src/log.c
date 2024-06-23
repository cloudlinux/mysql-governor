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
#include "version.h"
#include "log.h"

#ifndef GOVERNOR_SENTRY_TIMEOUT
#define GOVERNOR_SENTRY_TIMEOUT 5
#endif

#ifndef GOVERNOR_SENTRY_MESSAGE_MAX
#define GOVERNOR_SENTRY_MESSAGE_MAX 1024
#endif

#define SENTRY_DISABLED_FLAG "/usr/share/lve/dbgovernor/sentry-disabled.flag"
#define SENTRY_DAEMON_SOCK "/var/run/db-governor-sentry.sock"
#define SENTRY_DAEMON_SOCK_LEN 32

// All the functions return 0 on success and errno otherwise

int
sentry_log(cl_sentry_level_t level, const char* message, size_t len)
{
	if (message == NULL || message[0] == '\0') return -1;
	else if (!access(SENTRY_DISABLED_FLAG, F_OK)) return 0;
	else if (access(SENTRY_DAEMON_SOCK, F_OK) == -1) return -1;

	size_t message_len = len ? len : strnlen(message, GOVERNOR_SENTRY_MESSAGE_MAX);
	if (!message_len) return -1;

	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) return -1;

	// Set socket timeout
	struct timeval timeout;
	timeout.tv_sec = GOVERNOR_SENTRY_TIMEOUT;
	timeout.tv_usec = 0;

	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		close(sock);
		return -1;
	}

	struct sockaddr_un server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sun_family = AF_UNIX;

	int bytes = snprintf(server_address.sun_path,
			sizeof(server_address.sun_path), "%.*s",
			SENTRY_DAEMON_SOCK_LEN, SENTRY_DAEMON_SOCK);
	if (bytes <= 0) return -1;

	if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
	{
		close(sock);
		return -1;
	}

	const char *level_prefix = level == CL_SENTRY_ERROR ? "ERROR:" : "DEBUG:";
	size_t message_size = message_len + strlen(level_prefix) + 1;
	char *message_with_level = malloc(message_size);

	if (message_with_level == NULL)
	{
		shutdown(sock, SHUT_RDWR);
		close(sock);
		return -1;
	}

	bytes = snprintf(message_with_level, message_size, "%s%s", level_prefix, message);
	if (bytes > 0) bytes = send(sock, message_with_level, bytes, 0);

	free(message_with_level);
	shutdown(sock, SHUT_RDWR);
	close(sock);

	return bytes;
}

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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdate-time"

void init_log_ex(bool enable_all_tags)
{
	log_enabled_tags = ALWAYS_ENABLED_LOG_TAGS;
	if (enable_all_tags)	// in debug mode, enable all tags
		log_enabled_tags = (1 << LOG_TAG_BITS) - 1;
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
				tag = (1 << LOG_TAG_BITS) - 1;
				s_tag = "all";
			} else
			{
				tag = 1 << i;
				s_tag = tag_names[i];
			}
			size_t l_tag = strlen(s_tag);
			strcpy(ptr, "log-");
			char *p_tag = ptr + strlen(ptr), *pp;
			strcpy(p_tag, s_tag);
			for (pp=p_tag; pp < p_tag + l_tag; pp++)
				*pp = tolower((unsigned char)*pp);	// <ctype.h> is freakish about signed chars
			strcat(ptr, ".flag");
			struct stat flag_stat;
			if (!stat(fname, &flag_stat))
			{
				log_enabled_tags |= tag;
				if (all)
					break;
			}
		}
	}
	// TODO: possibly we'll need configurable log_verbosity_level, for now it's constant
	char s_tags_ena_buf[0x1000] = "", s_tags_dis_buf[0x1000] = "";	// two different buffers
	LOG(L_LIFE, "Logging enabled tags: [%s]; verbosity level: %d; disabled tags: [%s]; Governor version: %s, built at %s %s",
		concat_tag_names( log_enabled_tags, ",", false, s_tags_ena_buf, sizeof(s_tags_ena_buf)),
		log_verbosity_level,
		concat_tag_names(~log_enabled_tags, ",", true,  s_tags_dis_buf, sizeof(s_tags_dis_buf)),
		GOVERNOR_CUR_VER, __DATE__, __TIME__);
}

#pragma GCC diagnostic pop

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
	int msgLen = format_log_msg(msg, sizeof(msg), !!(tags & L_ERR), true, true, s_tags, src_file, src_line, src_func, NULL, fmt, args);
	va_end(args);	// don't ever return from function before va_end() - undefined behaviour!
	if (msgLen <= 0)	// '\n' is always added, so msgLen should never be zero
		return -1;
	if (fwrite(msg, msgLen, 1, log) != 1)
		return errno;
	return 0;
}

