/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "data.h"
#include "governor_config.h"
#include "log.h"

static char *mode_type_enum_to_str[] = { "TEST_MODE", "PRODUCTION_MODE",
  "DEBUG_MODE", "ERROR_MODE", "RESTRICT_MODE", "NORESTRICT_MODE",
  "IGNORE_MODE"
};

static FILE *log = NULL, *restrict_log = NULL, *slow_queries_log = NULL;

void print_stats_cfg (FILE * f, stats_limit_cfg * s);

char *
prepare_output (char *buffer, size_t size, char *fmt, ...)
{
  char internal_buf[_DBGOVERNOR_BUFFER_2048];
  va_list args;
  if (fmt)
    {
      va_start (args, fmt);
      vsnprintf (internal_buf, size, fmt, args);
      va_end (args);
      snprintf (buffer, size, "%s", internal_buf);
    }
  else
    {
      snprintf (buffer, size, "unknown error");
    }
  return buffer;
}

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
write_log (const char *error_file, int error_line, const char *error_string,
	   MODE_TYPE mode)
{
  if (log == NULL)
    return -1;
  char current_date[128];
  time_t rawtime;
  struct tm timeinfo;
  int rc;

  time (&rawtime);
  if (!localtime_r (&rawtime, &timeinfo))
    return EINVAL;
  strftime (current_date, 128, "%c", &timeinfo);

  if (mode == DEBUG_MODE)
    rc = fprintf (log, "[%s] %s:%d %s\n", current_date, error_file,
		  error_line, error_string);
  else
    rc = fprintf (log, "[%s] %s\n", current_date, error_string);

  if (rc < 0)
    return EIO;

  if (fflush (log))
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

int
write_restrict_log (const char *error_string, Stats * limits)
{
  if (restrict_log == NULL)
    return -1;

  char current_date[128];
  time_t rawtime;
  struct tm timeinfo;
  int rc;
  struct governor_config data_cfg;
  get_config_data (&data_cfg);

  time (&rawtime);
  if (!localtime_r (&rawtime, &timeinfo))
    return EINVAL;
  strftime (current_date, 128, "%c", &timeinfo);

  rc = fprintf (restrict_log, "[%s] %s  ", current_date, error_string);

  if (rc < 0)
    return EIO;

  if (limits && (data_cfg.restrict_format > 0))
    print_stats_easy (restrict_log, limits);

  fprintf (restrict_log, "\n");

  if (fflush (restrict_log))
    return errno;

  return 0;
}

int
write_slow_queries_log (const char *error_string)
{
  char current_date[128];
  time_t rawtime;
  struct tm timeinfo;
  int rc;
  struct governor_config data_cfg;
  get_config_data (&data_cfg);

  time (&rawtime);
  if (!localtime_r (&rawtime, &timeinfo))
    return EINVAL;
  strftime (current_date, 128, "%c", &timeinfo);

  rc = fprintf (slow_queries_log, "[%s] %s  ", current_date, error_string);

  if (rc < 0)
    return EIO;

  fprintf (slow_queries_log, "\n");

  if (fflush (slow_queries_log))
    return errno;

  return 0;
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

int
write_restrict_log_second_line (const char *error_string, int need_end_line)
{
  int rc;

  rc = fprintf (restrict_log, "%s", error_string);

  if (rc < 0)
    return EIO;

  if (need_end_line)
    fprintf (restrict_log, "\n");

  if (fflush (restrict_log))
    return errno;

  return 0;
}
