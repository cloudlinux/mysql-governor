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
#include "dbgovernor_string_functions.h"

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
  See MYSQLG-849
*/
static const char *state_to_no_kill[] =
{
	"removing tmp table",
	NULL
};

static int
is_request_in_state_to_no_kill (char *s)
{
	int i;
	for (i=0; state_to_no_kill[i]; ++i)
		if (!strncmp(s, state_to_no_kill[i], _DBGOVERNOR_BUFFER_256))
			return 1;
	return 0;
}

void *parse_slow_query(void *data)
{
	LOG(L_LIFE|L_SLOW, "thread begin");

	struct governor_config data_cfg;
	get_config_data(&data_cfg);

	MYSQL **mysql_do_kill_internal = get_mysql_connect();

	while (1)
	{
		if (*mysql_do_kill_internal == NULL)
		{
			sleep(DELTA_TIME);
			continue;
		}
		if (db_mysql_exec_query(QUERY_GET_PROCESSLIST_INFO, mysql_do_kill_internal))
			LOG(L_ERR|L_SLOW|L_MYSQL, "'show processlist' failed");
		else
		{
			LOG(L_SLOW|L_MYSQL, "processlist obtained");

			MYSQL_RES *res = (*_mysql_store_result)(*mysql_do_kill_internal);
			unsigned long rowCount = (*_mysql_num_rows)(res);

			if (rowCount > 0)
			{
				LOG(L_SLOW, "processlist row count > 0");

				MYSQL_ROW row;
				while ((row = (*_mysql_fetch_row)(res)))
				{
					const unsigned long *lengths = (*_mysql_fetch_lengths)(res);

					char
						Id[_DBGOVERNOR_BUFFER_2048],
						Time[_DBGOVERNOR_BUFFER_2048],
						Info[_DBGOVERNOR_BUFFER_2048],
						User[USERNAMEMAXLEN],
						State[_DBGOVERNOR_BUFFER_256];

					#define FETCH_ROW(n, dst)	db_mysql_get_string(dst, row[n], lengths[n], sizeof(dst));
					FETCH_ROW(0, Id)
					FETCH_ROW(1, User)
					FETCH_ROW(5, Time)
					FETCH_ROW(6, State)
					FETCH_ROW(7, Info)
					#undef FETCH_ROW

					LOG(L_SLOW, "processlist row: Id=%s, User=%s, Time=%s, State=%s, Info=%s", Id, User, Time, State, Info);

					static const char select_str[] = "SELECT";
					long slow_time = is_user_ignored(User);
					if (slow_time > 0 &&
						strncasecmp(select_str, Info, sizeof(select_str)-1) == 0
						&& !is_request_in_state_to_no_kill(State)
						)
					{
						LOG(L_SLOW, "is SELECT; Id=%d, Time=%d, slow_time=%d", atoi(Id), atoi(Time), slow_time);
						if (atoi(Time) > slow_time)
						{
							LOG(L_SLOW, "Time > slow_time");
							kill_query_by_id(atoi(Id), mysql_do_kill_internal);

							char info_short[MAX_QUERY_OUTPUT_LEN];
							strlcpy(info_short, Info, sizeof(info_short));
							LOG_SLOW_QUERIES("Query killed - %s : %s", User, info_short);
						}
					}
				}
			}
			(*_mysql_free_result) (res);
		}
		sleep (DELTA_TIME);
	}
	LOG(L_LIFE|L_SLOW, "thread end");
	return NULL;
}
