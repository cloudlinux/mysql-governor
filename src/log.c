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

#include "data.h"
#include "governor_config.h"
#include "log.h"

static char *mode_type_enum_to_str[] = { "TEST_MODE", "PRODUCTION_MODE",
	"DEBUG_MODE", "ERROR_MODE", "RESTRICT_MODE", "NORESTRICT_MODE",
	"IGNORE_MODE"
};

#define SENTRY_LOG_TAG "governor"

#ifndef GOVERNOR_SENTRY_TIMEOUT
#define GOVERNOR_SENTRY_TIMEOUT 5
#endif

#ifndef GOVERNOR_SENTRY_MESSAGE_MAX
#define GOVERNOR_SENTRY_MESSAGE_MAX 1024
#endif

static FILE *log = NULL, *restrict_log = NULL, *slow_queries_log = NULL;

void print_stats_cfg (FILE * f, stats_limit_cfg * s);
void print_stats_easy (FILE * f, stats_limit * s);

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

int
open_log (const char *log_file)
{
	if ((log = fopen (log_file, "a")) == NULL)
		return errno;
	return 0;
}

int
open_restrict_log (const char *log_file)
{
	if ((restrict_log = fopen (log_file, "a")) == NULL)
		return errno;
	return 0;
}

int
open_slow_queries_log (const char *log_file)
{
	if ((slow_queries_log = fopen (log_file, "a")) == NULL)
		return errno;
	return 0;
}

int
close_log (void)
{
	if (log && fclose (log))
	{
		log = NULL;
		return errno;
	}
	log = NULL;
	return 0;
}

int
close_restrict_log (void)
{
	if (restrict_log && fclose (restrict_log))
	{
		restrict_log = NULL;
		return errno;
	}
	restrict_log = NULL;
	return 0;
}

int
close_slow_queries_log (void)
{
	if (slow_queries_log && fclose (slow_queries_log))
	{
		slow_queries_log = NULL;
		return errno;
	}
	slow_queries_log = NULL;
	return 0;
}

static int
do_write_log (FILE *f, int show_pid_tid, const char *tags, const char *src_file, int src_line, const char *src_func, MODE_TYPE mode, Stats *limits, char *fmt, va_list args)
{
	if (f == NULL)
		return -1;

	char s[0x1000], *p = 0;
	size_t pSz = 0;
	char timestamp[128];
	time_t rawtime;
	struct tm timeinfo;
	int rc;
	struct governor_config data_cfg;
	get_config_data(&data_cfg);

	time(&rawtime);
	if (!localtime_r(&rawtime, &timeinfo) || strftime(timestamp, sizeof(timestamp), "%c", &timeinfo) <= 0)
		strcpy(timestamp, "unknown time");

	p = s;
	pSz = sizeof(s);

	rc = snprintf(p, pSz, "[%s] ", timestamp);
	if (rc < 0 || rc >= pSz)
		return EIO;
	p += rc;
	pSz -= rc;

	if (show_pid_tid)
	{
		rc = snprintf(p, pSz, "[%ld:%ld] ", (long)getpid(), (long)gettid_p());
		if (rc < 0 || rc >= pSz)
			return EIO;
		p += rc;
		pSz -= rc;
	}

	if (mode == DEBUG_MODE)
	{
		// According to man 3 basename,
		// GNU version of basename is selected by defining _GNU_SOURCE + not including libgen.h
		rc = snprintf(p, pSz, "[%s:%d:%s] ", basename(src_file), src_line, src_func);
		if (rc < 0 || rc >= pSz)
			return EIO;
		p += rc;
		pSz -= rc;
	}

	if (tags)
	{
		rc = snprintf(p, pSz, "[%s] ", tags);
		if (rc < 0 || rc >= pSz)
			return EIO;
		p += rc;
		pSz -= rc;
	}

	if (fmt)
		rc = vsnprintf(p, pSz, fmt, args);
	else
		rc = snprintf(p, pSz, "format error");
	if (rc < 0 || rc >= pSz)
		return EIO;
	p += rc;
	pSz -= rc;

	if (limits && (data_cfg.restrict_format > 0))
	{
		rc = snprintf(p, pSz, "cpu = %f, read = %ld, write = %ld", limits->cpu, limits->read, limits->write);
		if (rc < 0 || rc >= pSz)
			return EIO;
		p += rc;
		pSz -= rc;
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

int
write_log (FILE *f, int show_pid_tid, const char *src_file, int src_line, const char *src_func, MODE_TYPE mode, Stats *limits, char *fmt, ...)
{
	if (f == NULL)
		return -1;
	va_list args;
	va_start(args, fmt);
	int rc = do_write_log(f, show_pid_tid, NULL, src_file, src_line, src_func, mode, limits, fmt, args);
	va_end(args);
	return rc;
}

static void
print_long (FILE * f, long val)
{
	fprintf (f, "= %ld, ", val);
}

static void
print_long_last (FILE * f, long val)
{
	fprintf (f, "= %ld", val);
}

void
print_stats (FILE * f, stats_limit_cfg * s)
{
	print_stats_cfg (f, s);
}

static void
print_long_cfg (FILE * f, T_LONG val)
{
	fprintf (f, "current = %ld", val._current);
	if (val._short >= 0)
		fprintf (f, ", short = %ld", val._short);
	if (val._mid >= 0)
		fprintf (f, ", mid = %ld", val._mid);
	if (val._long >= 0)
		fprintf (f, ", long = %ld", val._long);
	fprintf (f, "\n");
}

static void
print_double (FILE * f, double val)
{
	fprintf (f, "= %f, ", val);
}

void
print_stats_easy (FILE * f, stats_limit * s)
{
	fprintf (f, "cpu ");
	print_double (f, s->cpu);
	fprintf (f, "read ");
	print_long (f, s->read);
	fprintf (f, "write ");
	print_long_last (f, s->write);
}

FILE *
get_log (void)
{
	return log;
}

FILE *
get_restrict_log (void)
{
	return restrict_log;
}

FILE *
get_slow_queries_log (void)
{
	return slow_queries_log;
}

void
print_stats_cfg (FILE * f, stats_limit_cfg * s)
{
	fprintf (f, "cpu ");
	print_long_cfg (f, s->cpu);
	fprintf (f, "read ");
	print_long_cfg (f, s->read);
	fprintf (f, "write ");
	print_long_cfg (f, s->write);
}

static void
print_account_limits (gpointer key, gpointer value, gpointer user_data)
{
	fprintf (log, "%s -- ", (char *) key);
	print_stats (log, value);
	fprintf (log, "\n");
}

void
print_config (void *icfg)
{
	struct governor_config *cfg = (struct governor_config *) icfg;
	if ((cfg->log_mode == DEBUG_MODE) && (log != NULL))
	{
		fprintf (log, "db_login %s\n", cfg->db_login);
		fprintf (log, "db_password %s\n", cfg->db_password);
		fprintf (log, "host %s\n", cfg->host);
		fprintf (log, "log %s\n", cfg->log);
		fprintf (log, "log_mode %s\n", mode_type_enum_to_str[cfg->log_mode]);
		fprintf (log, "restrict_log %s\n", cfg->restrict_log);
		fprintf (log, "separator %c\n", cfg->separator);
		fprintf (log, "level1 %u, level2 %u, level3 %u, level4 %u\n",
			cfg->level1, cfg->level2, cfg->level3, cfg->level4);
		fprintf (log, "timeout %u\n", cfg->timeout);
		fprintf (log, "interval_short %u\n", cfg->interval_short);
		fprintf (log, "interval_mid %u\n", cfg->interval_mid);
		fprintf (log, "interval_long %u\n", cfg->interval_long);
		fprintf (log, "restrict log format %u\n", cfg->restrict_format);

		fprintf (log, "\ndefault\n");
		print_stats_cfg (log, &cfg->default_limit);

		g_hash_table_foreach (cfg->account_limits,
			(GHFunc) print_account_limits, "");
		fprintf (log, "\n");
	}
}


/*
	Extended logging section:
*/

static const char *extlog_tag_names[] =
{
	#define DEFINE_EXTLOG_TAG(tag)	#tag,
	#include "log_tags.h"
	#undef DEFINE_EXTLOG_TAG
};

// tag name in uppercase, or NULL if no such tag defined
static const char *extlog_tag_name(unsigned tag)
{
	int i;
	for (i=0; i < EXTLOG_TAG_BITS; i++)
		if (tag == (1 << i))
			return extlog_tag_names[i];
	return NULL;
}

static void extlog_concat_tag_names(unsigned tags, const char *delim, int lowerCase, char *dst, size_t dstSz)
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
			const char *s_tag = extlog_tag_name(tag);
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


// Set of extended logging flags - the subsystem logging is enabled if corresponding bit is set
unsigned extlog_enabled_tags = 0;		// bitmask of enabled tags
unsigned extlog_verbosity_level = 1;	// minimum level of extlog() verbosity to be printed

// initialize extlog_enabled_tags
void extlog_init(void)
{
	extlog_enabled_tags = 0;

	struct governor_config data_cfg;
	get_config_data(&data_cfg);

	if (data_cfg.log_mode == DEBUG_MODE)	// in debug mode, enable all tags
		extlog_enabled_tags = (1 << EXTLOG_TAG_BITS) - 1;
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
				s_tag = extlog_tag_name(tag);
			}
			size_t l_tag = strlen(s_tag);
			strcpy(ptr, "extlog-");
			char *p_tag = ptr + strlen(ptr), *pp;
			strcpy(p_tag, s_tag);
			for (pp=p_tag; pp < p_tag + l_tag; pp++)
				*pp = tolower((unsigned char)*pp);
			strcat(ptr, ".flag");
			struct stat flag_stat;
			if (!stat(fname, &flag_stat))
			{
				extlog_enabled_tags |= tag;
				if (all)
					break;
			}
		}
	}

	// TODO: possibly we'll need configurable extlog_verbosity_level, for now it's constant

	char
		s_tags_ena[0x1000] = "",
		s_tags_dis[0x1000] = "";
	extlog_concat_tag_names( extlog_enabled_tags, ",", 0, s_tags_ena, sizeof s_tags_ena);
	extlog_concat_tag_names(~extlog_enabled_tags, ",", 1, s_tags_dis, sizeof s_tags_dis);

	WRITE_LOG(NULL, 0, "Extended logging enabled tags: [%s]; verbosity level: %d; disabled tags: [%s]", data_cfg.log_mode, s_tags_ena, extlog_verbosity_level, s_tags_dis);
}

int extlog(unsigned tags, unsigned level, const char *src_file, int src_line, const char *src_func, char *fmt, ...)
{
	if (!((tags & extlog_enabled_tags) && level <= extlog_verbosity_level))
		return 0;

	char s_tags[0x1000] = "";
	extlog_concat_tag_names(tags, ":", 0, s_tags, sizeof s_tags);
#if 0  // TODO: when we have different levels indeed, we'll decide how to print them
	char lev[0x10];
	sprintf(lev, ":lev.%d", level);
	strcat(s_tags, lev);
#endif

	va_list args;
	va_start(args, fmt);
	int rc = do_write_log(log, 1, s_tags, src_file, src_line, src_func, DEBUG_MODE, NULL, fmt, args);
	va_end(args);
	return rc;
}

