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
#include "log_defs.h"
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

extern unsigned log_enabled_tags;
extern unsigned log_verbosity_level;

void init_log_ex(bool enable_all_tags, const char *sentry_depot);	// initialize logging tags, verbosity, etc.
void set_log_ex_mysql_version(const char *ver);	// Initialize MySQL version, to use as Sentry tag. Becomes available in db_governor since MySQL version check. Not available in MySQL for now.

t_write_log_ex write_log_ex;	// declare logging function through a typedef

// Usage: LOG(L_MON|L_FRZ, "blabla %d", 235)
#define LOG(tags, fmt, ...) do { \
		if (((tags) & log_enabled_tags) /*&& (level) <= log_verbosity_level*/)\
			write_log_ex(tags, 1, __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__);\
	}\
	while (0)

#endif
