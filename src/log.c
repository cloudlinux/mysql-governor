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

//#include <unistd.h>
//#include <string.h>
#include <sys/un.h>
#include <sys/socket.h>


#include "data.h"
#include "governor_config.h"
#include "log.h"

#define SENTRY_LOG_TAG "governor"

#ifndef GOVERNOR_SENTRY_TIMEOUT
#define GOVERNOR_SENTRY_TIMEOUT 5
#endif

#ifndef GOVERNOR_SENTRY_MESSAGE_MAX
#define GOVERNOR_SENTRY_MESSAGE_MAX 1024
#endif

// All the functions return 0 on success and errno otherwise

static int
external_sentry_log(cl_sentry_level_t level, const char* message, size_t len, const char* socket_path)
{
	if (message == NULL || socket_path == NULL) return -1;
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

	strncpy(server_address.sun_path, socket_path, sizeof(server_address.sun_path) - 1);
	server_address.sun_path[sizeof(server_address.sun_path) - 1] = '\0';

	if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
	{
		close(sock);
		return -1;
	}

	const char *level_prefix = level == CL_SENTRY_ERROR ? "ERROR:" : "INFO:";
	size_t message_size = message_len + strlen(level_prefix) + 1;
	char *message_with_level = malloc(message_size);

	if (message_with_level == NULL)
	{
		shutdown(sock, SHUT_RDWR);
		close(sock);
		return -1;
	}

	int bytes = snprintf(message_with_level, message_size, "%s%s", level_prefix, message);
	if (bytes > 0) bytes = send(sock, message_with_level, bytes, 0);

	shutdown(sock, SHUT_RDWR);
	close(sock);

	return bytes;
}

void
sentry_log(cl_sentry_level_t level, const char *message, size_t len)
{
	struct governor_config data_cfg;
	get_config_data(&data_cfg);

	if (data_cfg.sentry_mode == SENTRY_MODE_NATIVE)
	{
		/*
		// S.K. >> Will be uncommented after Sentry native release for all platforms
		sentry_level_t log_level = (level == CL_SENTRY_ERROR) ?
						SENTRY_LEVEL_ERROR : SENTRY_LEVEL_INFO;

		if (data_cfg.sentry_dsn != NULL) // Chech if DSN is set
			cl_sentry_message(log_level, SENTRY_LOG_TAG, message);
		*/
	}
	else if (data_cfg.sentry_mode == SENTRY_MODE_EXTERNAL)
	{
		if (data_cfg.sentry_sock != NULL) // Chech if daemon socket is set
			external_sentry_log(level, message, len, data_cfg.sentry_sock);
	}
}

static FILE *log = NULL, *restrict_log = NULL, *slow_queries_log = NULL;

int open_log(const char *path)
{
	if ((log = fopen(path, "a")) == NULL)
		return errno;
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

static int write_log_impl(FILE *f, const char *tags, bool error, const char *src_file, int src_line, const char *src_func, const Stats *limits, const char *fmt, va_list args)
{
	if (f == NULL)
		return -1;

	bool verbose = src_file && src_line != -1 && src_func;

	char s[0x1000], *p = s;
	size_t pSz = sizeof(s);
	int rc = 0;
	#define INC_P \
		do {\
			if (rc < 0 || rc >= pSz)\
				return EIO;\
			p += rc;\
			pSz -= rc;\
		} while (0)

	char timestamp[0x100];
	struct timespec ts;
	struct tm timeinfo;
	if (!clock_gettime(CLOCK_REALTIME, &ts) && localtime_r(&ts.tv_sec, &timeinfo) && strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo) > 0)
	{
		if (verbose)
		{
			char ns[0x10] = "";
			snprintf(ns, sizeof(ns), ".%09lld", (long long)ts.tv_nsec);
			strcat(timestamp, ns);
		}
	} else
		strcpy(timestamp, "unknown time");
	rc = snprintf(p, pSz, "[%s]", timestamp);
	INC_P;
	if (verbose)
	{
		rc = snprintf(p, pSz, " [%ld:%ld]", (long)getpid(), (long)gettid_p());
		INC_P;
	}
	rc = snprintf(p, pSz, error ? "!" : " ");
	INC_P;
	if (verbose)
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
		rc = snprintf(p, pSz, "cpu = %f, read = %ld, write = %ld", limits->cpu, limits->read, limits->write);
		INC_P;
	}

	if (pSz < 2)
		return EIO;
	strncpy(p, "\n", pSz);

	rc = fputs(s, f);
	if (rc < 0)
		return EIO;
	if (fflush(f))
		return errno;

	return 0;
}

int write_log_simple(FILE *f, const Stats *limits, const char *fmt, ...)
{
	if (!f)
		return -1;
	va_list args;
	va_start(args, fmt);
	int rc = write_log_impl(f, NULL, false, NULL, -1, NULL, limits, fmt, args);
	va_end(args);
	return rc;
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

static const char *tag_names[] =
{
	#define DEFINE_LOG_TAG(tag)	#tag,
	#include "log_tags.h"
	#undef DEFINE_LOG_TAG
};

// tag name in uppercase, or NULL if no such tag defined
static const char *get_tag_name(unsigned tag)
{
	int i;
	for (i=0; i < EXTLOG_TAG_BITS; i++)
		if (tag == (1 << i))
			return tag_names[i];
	return NULL;
}

static void concat_tag_names(unsigned tags, const char *delim, int lowerCase, char *dst, size_t dstSz)
{
	char *p = dst;
	*p = '\0';
	size_t delimLen = strlen(delim);
	int i;
	for (i=0; i < EXTLOG_TAG_BITS; i++)
	{
		unsigned tag = 1 << i;
		if (tags & tag)
		{
			if (p > dst)	// before any tag except first, add delimiter
			{
				memcpy(p, delim, delimLen);
				p += delimLen;
			}
			const char *s_tag = get_tag_name(tag);
			if (!s_tag)
				s_tag = "unknown";
			size_t len = strlen(s_tag);
			memcpy(p, s_tag, len + 1);
			if (lowerCase)
			{
				char *pp;
				for (pp=p; pp < p + len; pp++)
					*pp = tolower((unsigned char)*pp);
			}
			p += len;
		}
	}
}

unsigned log_enabled_tags = 0;		// bitmask of enabled tags
unsigned log_verbosity_level = 1;

void init_log_ex(bool enable_all_tags)
{
	log_enabled_tags = L_ERR | L_IMPORTANT | L_LIFE;

	if (enable_all_tags)	// in debug mode, enable all tags
		log_enabled_tags = (1 << EXTLOG_TAG_BITS) - 1;
	else									// otherwise, check file-flags to enable corresponding tags
	{
		// calculate file-flags prefix
		static const int flag_max_size = 256;
		size_t blen = strlen(PATH_TO_GOVERNOR_PRIVATE_DIR);
		char fname[blen + flag_max_size];
		char *ptr = fname + blen;
		memcpy(fname, PATH_TO_GOVERNOR_PRIVATE_DIR, blen);	// without NULL
		int i;
		for (i=-1; i < EXTLOG_TAG_BITS; i++)
		{
			unsigned tag = 0;
			const char *s_tag = NULL;
			int all = i==-1;
			if (all)
			{
				tag = (1 << EXTLOG_TAG_BITS) - 1;
				s_tag = "all";
			} else
			{
				tag = 1 << i;
				s_tag = get_tag_name(tag);
			}
			size_t l_tag = strlen(s_tag);
			strcpy(ptr, "log-");
			char *p_tag = ptr + strlen(ptr), *pp;
			strcpy(p_tag, s_tag);
			for (pp=p_tag; pp < p_tag + l_tag; pp++)
				*pp = tolower((unsigned char)*pp);
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

	char	s_tags_ena[0x1000] = "",
			s_tags_dis[0x1000] = "";
	concat_tag_names( log_enabled_tags, ",", 0, s_tags_ena, sizeof s_tags_ena);
	concat_tag_names(~log_enabled_tags, ",", 1, s_tags_dis, sizeof s_tags_dis);
	LOG(L_LIFE, "Logging enabled tags: [%s]; verbosity level: %d; disabled tags: [%s]", s_tags_ena, log_verbosity_level, s_tags_dis);
}

int write_log_ex(unsigned tags, unsigned level, const char *src_file, int src_line, const char *src_func, const char *fmt, ...)
{
	if (!((tags & log_enabled_tags) && level <= log_verbosity_level))
		return 0;
	char s_tags[0x1000] = "";
	concat_tag_names(tags, ":", 0, s_tags, sizeof s_tags);
#if 0  // TODO: when we have different levels indeed, we'll decide how to print them
	char lev[0x10];
	sprintf(lev, ":lev.%d", level);
	strcat(s_tags, lev);
#endif
	va_list args;
	va_start(args, fmt);
	int rc = write_log_impl(log, s_tags, !!(tags & L_ERR), src_file, src_line, src_func, NULL, fmt, args);
	va_end(args);
	return rc;
}

