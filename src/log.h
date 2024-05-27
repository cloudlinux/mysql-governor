/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef __LOG_H__
#define __LOG_H__

#include "data.h"
#include <stdio.h>

// All the functions return 0 on success and errno otherwise

int write_log_simple(FILE *f, const Stats *limits, const char *fmt, ...);

int open_log(const char *path);
int close_log();
FILE *get_log();

int open_restrict_log(const char *path);
int close_restrict_log();
FILE *get_restrict_log();

#define LOG_RESTRICT(fmt, ...) \
	do {\
		FILE *f = get_restrict_log();\
		if (f)\
			write_log_simple(f, NULL, fmt, ##__VA_ARGS__); \
	} while(0)

#define LOG_RESTRICT_LIMITS(limits, fmt, ...) \
	do {\
		FILE *f = get_restrict_log();\
		if (f)\
			write_log_simple(f, data_cfg.restrict_format > 0 ? (limits) : NULL, fmt, ##__VA_ARGS__); \
	} while(0)

int open_slow_queries_log(const char *path);
int close_slow_queries_log();
FILE *get_slow_queries_log();

#define LOG_SLOW_QUERIES(fmt, ...) \
	do {\
		FILE *f = get_slow_queries_log();\
		if (f)\
			write_log_simple(f, NULL, fmt, ##__VA_ARGS__); \
	} while(0)


enum _log_tag_bitnums
{
	#define DEFINE_LOG_TAG(tag)	_log_tag_bitnum_##tag,
	#include "log_tags.h"
	#undef DEFINE_LOG_TAG
	EXTLOG_TAG_BITS
};

// Log tags
// are bit flags to be OR-ed and passed to "LOG(tags, ...)".
// They are named "L_<TAG>", and occupy EXTLOG_TAG_BITS lower bits.

enum
{
	#define DEFINE_LOG_TAG(tag)	L_##tag = 1 << _log_tag_bitnum_##tag,
	#include "log_tags.h"
	#undef DEFINE_LOG_TAG
};

extern unsigned log_enabled_tags;
extern unsigned log_verbosity_level;

typedef enum {
	CL_SENTRY_DEBUG,
	CL_SENTRY_ERROR
} cl_sentry_level_t;

void init_log_ex(bool enable_all_tags);	// initialize logging tags, verbosity, etc.

// ACHTUNG: IF YOU CHANGE THE SIGNATURE, CHANGE IT ALSO IN ALL MYSQL PATCHES!!!
int write_log_ex(unsigned tags, unsigned level, const char *src_file, int src_line, const char *src_func, const char *fmt, ...);

// Usage: LOG(L_MON|L_FRZ, "blabla %d", 235)
#define LOG(tags, fmt, ...) do { \
		if (((tags) & log_enabled_tags) /*&& (level) <= log_verbosity_level*/)\
			write_log_ex(tags, 1, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__);\
	}\
	while (0)

// Sentry logging
int sentry_log(cl_sentry_level_t level, const char *message, size_t len);

#endif
