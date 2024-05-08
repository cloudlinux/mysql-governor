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
#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <sys/socket.h>
//#include <cl-sentry.h> // S.K. >> Will be uncommented after Sentry native release for all platforms

// All the functions return 0 on success and errno otherwise

int open_log (const char *log_file);
int close_log (void);
int write_log (FILE *f, int show_pid_tid, const char *src_file, int src_line, const char *src_func, MODE_TYPE mode, Stats *limit, char *fmt, ...);

FILE *get_log (void);
FILE *get_restrict_log (void);
FILE *get_slow_queries_log (void);

#ifdef LIBGOVERNOR
	// Symbols implementing WRITE_LOG() are undefined in "libgovernor.so".
	// Thus, we prohibit WRITE_LOG() use to avoid run-time failures
	// deep inside calls to functions of "libgovernor.so" (loaded via dlopen(..., RTLD_LAZY) from the patched mysql),
	// due to unresolved symbols.
	#define WRITE_LOG(stats, type, fmt, mode, ...)  error: WRITE_LOG() not supported for libgovernor.so
#else // LIBGOVERNOR
	#define WRITE_LOG(stats, type, fmt, mode, ...) do { \
	if (type==0) \
		write_log(get_log(),				1, __FILE__, __LINE__, __FUNCTION__, mode, stats, fmt, ##__VA_ARGS__); \
	else if (type==1) \
		write_log(get_restrict_log(),		0, __FILE__, __LINE__, __FUNCTION__, mode, stats, fmt, ##__VA_ARGS__); \
	else if (type==2) \
		write_log(get_slow_queries_log(),	0, __FILE__, __LINE__, __FUNCTION__, mode, stats, fmt, ##__VA_ARGS__); \
	else\
		write_log(get_log(),				0, __FILE__, __LINE__, __FUNCTION__, mode, stats, "!!! INVALID LOG TYPE=" #type); \
	} while(0)
#endif // LIBGOVERNOR

//WRITE_LOG(NULL,  0, "test %s", cfg->mode, "Hello"); write to error_log
//WRITE_LOG(stat1, 1, "test %s", cfg->mode, "Hello"); write to restrict log
//WRITE_LOG(stat1, 2, "test %s", cfg->mode, "Hello"); write to slow queries log


int open_restrict_log (const char *log_file);
int close_restrict_log (void);

int open_slow_queries_log (const char *log_file);
int close_slow_queries_log (void);

void print_config (void *icfg);


/*
	Extended logging section
*/

enum _extlog_tag_bitnums
{
	#define DEFINE_EXTLOG_TAG(tag)	el_bitnum_##tag,
	#include "log_tags.h"
	#undef DEFINE_EXTLOG_TAG
	EXTLOG_TAG_BITS
};

// Extended logging tags
// are bit flags to be OR-ed and passed to "EXTLOG(tags, ...)".
// They are named "EL_<TAG>", and occupy EXTLOG_TAG_BITS lower bits.

enum
{
	#define DEFINE_EXTLOG_TAG(tag)	EL_##tag = 1 << el_bitnum_##tag,
	#include "log_tags.h"
	#undef DEFINE_EXTLOG_TAG
};

typedef enum {
	CL_SENTRY_INFO,
	CL_SENTRY_ERROR
} cl_sentry_level_t;

extern unsigned extlog_enabled_tags;
extern unsigned extlog_verbosity_level;

// Initialize Extending Logging
void extlog_init(void);

int extlog(unsigned tags, unsigned level, const char *src_file, int src_line, const char *src_func, char *fmt, ...);

// Sentry logging
void sentry_log(cl_sentry_level_t level, const char *message, size_t len);

// Usage: EXTLOG(EL_MONITOR|EL_FREEZE, 1, "blabla %d", 235)
#ifdef LIBGOVERNOR
	// "extlog..." symbols, implementing EXTLOG(), are undefined in "libgovernor.so".
	// Thus, we prohibit EXTLOG() use to avoid failing dlopen("libgovernor.so") due to unresolved symbols.
	#define EXTLOG(tags, level, fmt, ...)  error: EXTLOG() not supported for libgovernor.so	// let it be just some syntax error. we can't use c99 _Pragma() since it can be unavailbale on some older platforms
#else // LIBGOVERNOR
	#define EXTLOG(tags, level, fmt, ...) do { \
		if (((tags) & extlog_enabled_tags) && (level) <= extlog_verbosity_level)\
			extlog(tags, level, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__);\
	} while(0)
#endif // LIBGOVERNOR

#endif
