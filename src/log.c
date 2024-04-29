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

static FILE *log = NULL, *restrict_log = NULL, *slow_queries_log = NULL;

void print_stats_cfg (FILE * f, stats_limit_cfg * s);
void print_stats_easy (FILE * f, stats_limit * s);

// All the functions return 0 on success and errno otherwise

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

int
write_log (FILE *f, const char *error_file, int error_line, MODE_TYPE mode, Stats *limits, char *fmt, ...)
{
  if (f == NULL)
    return -1;

  char current_date[128];
  time_t rawtime;
  struct tm timeinfo;
  int rc;
  va_list args;
  struct governor_config data_cfg;
  get_config_data (&data_cfg);

  time (&rawtime);
  if (!localtime_r (&rawtime, &timeinfo))
    return EINVAL;
  strftime (current_date, 128, "%c", &timeinfo);

  // According to man 3 basename,
  // GNU version of basename is selected by defining _GNU_SOURCE + not including libgen.h
  if (mode == DEBUG_MODE)
    rc = fprintf (f, "[%s] %s:%d ", current_date, basename(error_file), error_line);
  else if (mode == EXTLOG_MODE)
    rc = fprintf (f, "[%d:%d] [%s] %s:%d ", (int)getpid(), (int)gettid_p(), current_date, basename(error_file), error_line);
  else
    rc = fprintf (f, "[%s] ", current_date);

  if (rc < 0)
    return rc;

  if (fmt)
    {
      va_start (args, fmt);
      rc = vfprintf (f, fmt, args);
      va_end (args);
    }
  else
    {
      rc = fprintf (f, "format error");
    }

  if (rc < 0)
    return EIO;

  if (limits && (data_cfg.restrict_format > 0))
    print_stats_easy (f, limits);

  rc = fprintf (f, "\n");
  if (rc < 0)
    return EIO;

  if (fflush (f))
    return errno;

  return 0;
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
    Extended logging sectiom
*/
// Set of extended logging flags - the subsystem logging is enabled if corresponding bit is set
static unsigned extlog_flags;

typedef struct _extlog_files_t {
	const char *fname;
	unsigned flag;
} extlog_files_t;

// Switching particular extended logging - mapping between flags and file-flags
static extlog_files_t extlog_flags_by_files[] = {
	{ "extlog-freeze.flag", EXTLOG_USER_FREEZE },
	{ NULL, 0 }
};

// initialize extlog_flags by extlog_flags_by_files
void extlog_init(void)
{
	extlog_files_t *cur;
	static const int flag_max_size = 256;
	size_t blen = strlen(PATH_TO_GOVERNOR_PRIVATE_DIR);
	char fname[blen + flag_max_size];
	char *ptr = fname + blen;
	struct stat flag_stat;

	extlog_flags = 0;
	memcpy(fname, PATH_TO_GOVERNOR_PRIVATE_DIR, blen); //without NULL
	for (cur = extlog_flags_by_files; cur->fname != NULL; ++cur)
	{
		strncpy(ptr, cur->fname, flag_max_size);
		if (!stat(fname, &flag_stat))
			extlog_flags |= cur->flag;
	}
}

#define EXT_LOG(extlog_mode, fmt, ...) do { \
	extlog(extlog_mode, __FILE__, __LINE__, fmt, ##__VA_ARGS__); \
} while(0)

#define FREEZE_EXT_LOG(fmt, ...) do { \
	EXT_LOG(EXTLOG_USER_FREEZE, fmt, ##__VA_ARGS__); \
} while(0)

int extlog(unsigned extlog_mode, const char *error_file, int error_line, char *fmt, ...)
{
	int rc;
	if (!(extlog_flags & extlog_mode))
		return 0;

	va_list args;
	va_start (args, fmt);
	rc = write_log(restrict_log, error_file, error_line, EXTLOG_MODE, NULL, fmt, args);
	va_end (args);
	return rc;
}
