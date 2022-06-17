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

// All the functions return 0 on success and errno otherwise

int open_log (const char *log_file);
int close_log (void);
int write_log (const char *error_file, int error_line,
	       const char *error_string, MODE_TYPE mode);
char *prepare_output (char *buffer, size_t size, char *fmt, ...);

FILE *get_log (void);
FILE *get_restrict_log (void);
FILE *get_slow_queries_log (void);

#define WRITE_LOG(stats, type, buffer, size, message, mode, ...) if (type==0) \
	write_log(__FILE__, __LINE__, prepare_output(buffer, size, message, ##__VA_ARGS__), mode); \
else if (type==1) \
	write_restrict_log (prepare_output(buffer, size, message, ##__VA_ARGS__), stats); \
else if (type==2&&get_slow_queries_log())  \
	write_slow_queries_log (prepare_output(buffer, size, message, ##__VA_ARGS__));

//WRITE_LOG(NULL, 0, buffer, 2048, cfg->mode, "test %s", "Hello"); write to error_log
//WRITE_LOG(stat1, 1, buffer, 2048, cfg->mode, "test %s", "Hello"); write to restrict log
//WRITE_LOG(stat1, 2, buffer, 2048, cfg->mode, "test %s", "Hello"); write to slow queries log


int open_restrict_log (const char *log_file);
int close_restrict_log (void);
int write_restrict_log (const char *error_string, Stats * limits);

int
write_restrict_log_second_line (const char *error_string, int need_end_line);

int open_slow_queries_log (const char *log_file);
int close_slow_queries_log (void);
int write_slow_queries_log (const char *error_string);

void print_config (void *icfg);

#endif
