/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Shkatula Pavel <shpp@cloudlinux.com>
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <glib.h>
#include <pthread.h>

#include "log.h"
#include "governor_config.h"
#include "mysql_connector_common.h"
#include "dlload.h"
#include "slow_queries.h"
#include "calc_stats.h"

#define DELTA_TIME 15
#define MAX_QUERY_OUTPUT_LEN 600

extern M_mysql_store_result;
extern M_mysql_num_rows;
extern M_mysql_free_result;
extern M_mysql_fetch_lengths;
extern M_mysql_fetch_row;
extern M_my_init;
extern M_load_defaults;
extern M_mysql_init;
extern M_mysql_real_connect;
extern M_mysql_options;
extern M_mysql_query;
extern M_mysql_close;
extern M_mysql_error;
extern M_mysql_real_escape_string;
extern M_mysql_ping;

/* 
  MYSQLG-849 - it seems that MySQL contains a bug, and killed QUERY request in this state can stuck for days 
  That's why we exclude this state from state_to_kill and include it into state_to_no_kill
*/
static const char *state_to_kill[] = {
  "Copying to tmp table",
  "Copying to group table",
  "Copying to tmp table on disk",
/*  "removing tmp table", */
  "Sending data",
  "Sorting for group",
  "Sorting for order",
  NULL
};

static const char *state_to_no_kill[] = {
  "removing tmp table",
  NULL
};

static int
is_request_in_state_to_kill (char *s)
{
    int i;
    for (i=0; state_to_kill[i] != NULL; ++i)
        if (!strncmp (s, state_to_kill[i], _DBGOVERNOR_BUFFER_256)) return 1;
    return 0;
}

static int
is_request_in_state_to_no_kill (char *s)
{
    int i;
    for (i=0; state_to_no_kill[i] != NULL; ++i)
        if (!strncmp (s, state_to_no_kill[i], _DBGOVERNOR_BUFFER_256)) return 1;
    return 0;
}

void *
parse_slow_query (void *data)
{
  char buffer[_DBGOVERNOR_BUFFER_8192];
  char sql_buffer[_DBGOVERNOR_BUFFER_8192];
  char log_buffer[_DBGOVERNOR_BUFFER_8192];
  struct governor_config data_cfg;

  MYSQL **mysql_do_kill_internal = get_mysql_connect ();
  MYSQL_RES *res;
  MYSQL_ROW row;
  unsigned long *lengths;
  unsigned long counts;

  const char f_str[] = "SELECT";
  const size_t f_str_sz = sizeof(f_str);
  char Id[_DBGOVERNOR_BUFFER_2048];
  char Time[_DBGOVERNOR_BUFFER_2048];
  char Info[_DBGOVERNOR_BUFFER_2048];
  char User[USERNAMEMAXLEN];
  char State[_DBGOVERNOR_BUFFER_256];

  get_config_data (&data_cfg);

  while (1)
    {
#ifdef TEST
      //printf( "slow_time=%d\n", slow_time );
#endif
      if (*mysql_do_kill_internal == NULL)
	{
	  sleep (DELTA_TIME);
	  continue;
	}
      snprintf (sql_buffer, _DBGOVERNOR_BUFFER_8192,
		QUERY_GET_PROCESSLIST_INFO);
      if (db_mysql_exec_query
	  (sql_buffer, mysql_do_kill_internal, data_cfg.log_mode))
	{
#ifdef TEST
	  //printf( "db_mysql_exec_query ERROR\n" );
#endif
	  WRITE_LOG (NULL, 0, "Get show processlist failed", data_cfg.log_mode);
	}
      else
	{
#ifdef TEST
	  //printf( "db_mysql_exec_query OK\n" );
#endif
	  res = (*_mysql_store_result) (*mysql_do_kill_internal);
	  counts = (*_mysql_num_rows) (res);

	  if (counts > 0)
	    {
#ifdef TEST
	      //printf( "counts > 0\n" );
#endif
	      while ((row = (*_mysql_fetch_row) (res)))
		{

		  lengths = (*_mysql_fetch_lengths) (res);
#ifdef TEST
/*
            printf( "is ROW\n" );
            printf( "row[ 0 ]=%s\n", row[ 0 ] );
            printf( "row[ 5 ]=%s\n", row[ 5 ] );
            printf( "row[ 7 ]=%s\n", buffer );
*/
#endif
		  db_mysql_get_string (buffer, row[0], lengths[0],
				       _DBGOVERNOR_BUFFER_8192);
		  strncpy (Id, buffer, _DBGOVERNOR_BUFFER_2048 - 1);
		  db_mysql_get_string (buffer, row[1], lengths[1],
				       _DBGOVERNOR_BUFFER_8192);
		  strncpy (User, buffer, USERNAMEMAXLEN - 1);
		  db_mysql_get_string (buffer, row[5], lengths[5],
				       _DBGOVERNOR_BUFFER_8192);
		  strncpy (Time, buffer, _DBGOVERNOR_BUFFER_2048 - 1);
		  db_mysql_get_string (buffer, row[6], lengths[6],
				       _DBGOVERNOR_BUFFER_8192);
		  strncpy (State, buffer, _DBGOVERNOR_BUFFER_256 - 1);
		  db_mysql_get_string (buffer, row[7], lengths[7],
				       _DBGOVERNOR_BUFFER_8192);
		  strncpy (Info, buffer, _DBGOVERNOR_BUFFER_2048 - 1);
		  long slow_time = is_user_ignored (User);
		  if (slow_time > 0 &&
		      strncasecmp (f_str, Info, f_str_sz - 1) == 0
		      /*&& is_request_in_state_to_kill(State) */
		      && ! is_request_in_state_to_no_kill(State)
		  )
		    {
#ifdef TEST
/*
              printf( "is SELECT\n" );
              printf( "Id=%d, Time=%d,  slow_time=%d\n", atoi( Id ), atoi( Time ), slow_time );
*/
#endif
		      if (atoi (Time) > slow_time)
			{
#ifdef TEST
			  //printf( "Time > slow_time\n" );
#endif
			  kill_query_by_id (atoi (Id), data_cfg.log_mode,
					    mysql_do_kill_internal);

			  char Info_[_DBGOVERNOR_BUFFER_2048];
			  strncpy (Info_, Info, MAX_QUERY_OUTPUT_LEN);
                          Info_[MAX_QUERY_OUTPUT_LEN] = 0;
			  snprintf (log_buffer, sizeof log_buffer, "Query killed - %s : %s",
				   User, Info_);
			  WRITE_LOG (NULL, 2, "%s", data_cfg.log_mode, log_buffer);
			}
		    }

		}
	    }
	  (*_mysql_free_result) (res);
	}
      sleep (DELTA_TIME);
    }
}
