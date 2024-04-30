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

int open_log (const char *log_file);
int close_log (void);
int write_log (FILE *f, const char *error_file, int error_line, MODE_TYPE mode, Stats *limit, char *fmt, ...);

FILE *get_log (void);
FILE *get_restrict_log (void);
FILE *get_slow_queries_log (void);

#define WRITE_LOG(stats, type, fmt, mode, ...) do { \
if (type==0) \
	write_log(get_log(), __FILE__, __LINE__, mode, stats, fmt, ##__VA_ARGS__); \
else if (type==1) \
	write_log(get_restrict_log(), __FILE__, __LINE__, mode, stats, fmt, ##__VA_ARGS__); \
else if (type==2)  \
	write_log(get_slow_queries_log(), __FILE__, __LINE__, mode, stats, fmt, ##__VA_ARGS__); \
} while(0)

//WRITE_LOG(NULL, 0, cfg->mode, "test %s", "Hello"); write to error_log
//WRITE_LOG(stat1, 1, cfg->mode, "test %s", "Hello"); write to restrict log
//WRITE_LOG(stat1, 2, cfg->mode, "test %s", "Hello"); write to slow queries log


int open_restrict_log (const char *log_file);
int close_restrict_log (void);

int open_slow_queries_log (const char *log_file);
int close_slow_queries_log (void);

void print_config (void *icfg);


/*
    Extended logging sectiom
*/

// Set of extended logging flags
#define EXTLOG_USER_FREEZE 0x01

// Initialize Extending Logging flags
void extlog_init(void);

#define EXT_LOG(extlog_mode, fmt, ...) do { \
        extlog(extlog_mode, __FILE__, __LINE__, fmt, ##__VA_ARGS__); \
} while(0)

#define FREEZE_EXT_LOG(fmt, ...) do { \
        EXT_LOG(EXTLOG_USER_FREEZE, fmt, ##__VA_ARGS__); \
} while(0)

int extlog(unsigned extlog_mode, const char *error_file, int error_line, char *fmt, ...);

#endif
