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
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include <sys/select.h>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>
#include <limits.h>
#include <errno.h>

#include <pthread.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "log.h"
#include "dlload.h"
#include "mysql_connector_common.h"
#include "wrappers.h"
#include "governor_config.h"
#include "dbgovernor_string_functions.h"

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

extern char *unix_socket_address;

static char work_user[USERNAMEMAXLEN];

int is_plugin_version = 0;
static int is_mariadb_104plus = 0;

//Pointer to DB connection that read statistic
MYSQL *mysql_send_governor = NULL;
//Pointer to DB connection that send command
MYSQL *mysql_do_command = NULL;
MYSQL *mysql_do_kill = NULL;
/*
 * Для корректного реконнекта необходимы параметры соединения, на случай, если авто
 * реконнект не сработает
 */
char	global_user_name[_DBGOVERNOR_BUFFER_128],
		global_host[_DBGOVERNOR_BUFFER_512],
		global_user_password[_DBGOVERNOR_BUFFER_256],
		global_db_name[_DBGOVERNOR_BUFFER_512];

int
db_connect_common (MYSQL ** internal_db, const char *host,
		const char *user_name, const char *user_password,
		const char *db_name, int argc,
		char *argv[], int save_global)
{
	const char *groups_client[] = { "client", "mysqld", "dbgovernor", NULL };
	//const char *groups_server[] = { "mysqld", "client", NULL };
	int option_index = 0;
	char c;
	char *hst __attribute__((unused)) = NULL;
	char *user = NULL;
	char *password = NULL;
	my_bool reconnect = 1;

	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	//Prepare local options name for default access with name and password from my.cnf, .my.cnf
	struct option long_options[] =
	{
		{"host",		optional_argument, NULL, 'r'},
		{"user",		optional_argument, NULL, 'g'},
		{"password",	optional_argument, NULL, 'j'},
		{"pass",		optional_argument, NULL, 'i'},
		{"socket",		optional_argument, NULL, 'S'},
		{0, 0, 0, 0}
	};

	if (*internal_db != NULL)
	{
		//Already connected
		LOG(L_ERR|L_MYSQL, "Connection already exists");
		return -1;
	}

	if (_my_init)
		(*_my_init)();

	*internal_db = (*_mysql_init)(NULL);
	if (*internal_db == NULL)
	{
		LOG(L_ERR|L_MYSQL, "Can't init mysql structure");
		return -1;
	}

	/*
	* Здесь мы читаем my.cnf и .my.cnf
	* Это читает сам mysql, это его родное API
	*/
	if(_load_defaults)
	{
		(*_load_defaults) ("my", groups_client, &argc, &argv);
		opterr = 0;
		optind = 0;
		//Parse argc, argv modified by _load_defaults
		while ((c = getopt_long (argc, argv, ":S:u:p:h:s:m:l:c:", long_options,
			&option_index)) != EOF)
		{
			switch (c)
			{
				case 'S':
					unix_socket_address = optarg;
					break;
				case 'r':
					hst = optarg;
					break;
				case 'g':
					user = optarg;
					break;
				case 'j':
					password = optarg;
					break;
				case 'i':
					password = optarg;
					break;
				default:
					continue;
			}
		}
	} else
	{
		if ((*_mysql_options)(*internal_db, MYSQL_READ_DEFAULT_GROUP, "client"))
		{
			if ((*_mysql_options)(*internal_db, MYSQL_READ_DEFAULT_GROUP, "mysqld"))
			{
				(*_mysql_options)(*internal_db, MYSQL_READ_DEFAULT_GROUP, "dbgovernor");
			}
		}
	}

	LOG(L_IMPORTANT|L_MYSQL, "Try to connect with options from dbgovernor config file");
	strlcpy (work_user, "", USERNAMEMAXLEN);
	if (user_name)
		strlcpy (work_user, user_name, USERNAMEMAXLEN);
	(*_mysql_options) (*internal_db, MYSQL_OPT_RECONNECT, &reconnect);
	//Try to connect with options from goernor's config
	if (!(*_mysql_real_connect) (*internal_db, host, user_name, user_password,
					db_name, 0, unix_socket_address, 0))
	{
		//Previous attempt failed, try with data from my.cnf, .my.cnf
		LOG(L_IMPORTANT|L_MYSQL, "Try to connect with no password under root");
		//Error again, stop to try
		LOG(L_ERR|L_MYSQL, "connect failed: %s", db_getlasterror(*internal_db));
		//Try to connect again
		if (user)
		strlcpy (work_user, user, USERNAMEMAXLEN);
		(*_mysql_options) (*internal_db, MYSQL_OPT_RECONNECT, &reconnect);
		if (!(*_mysql_real_connect) (*internal_db, host, user, password,
					db_name, 0, unix_socket_address, 0))
		{
			//Error again, stop to try
			LOG(L_ERR|L_MYSQL, "connect failed: %s", db_getlasterror(*internal_db));

			LOG(L_IMPORTANT|L_MYSQL, "Try to connect with no password, no host, no user under root");
			(*_mysql_options) (*internal_db, MYSQL_OPT_RECONNECT, &reconnect);
			if (!_load_defaults)
			{
				if ((*_mysql_options)(*internal_db, MYSQL_READ_DEFAULT_GROUP, "client"))
				{
					if ((*_mysql_options)(*internal_db, MYSQL_READ_DEFAULT_GROUP, "mysqld"))
					{
						(*_mysql_options)(*internal_db, MYSQL_READ_DEFAULT_GROUP, "dbgovernor");
					}
				}
			}
			if (!(*_mysql_real_connect) (*internal_db, NULL, NULL, NULL,
									NULL, 0, unix_socket_address, 0))
			{
				//Error again, stop to try
				LOG(L_ERR|L_MYSQL, "connect failed: %s", db_getlasterror(*internal_db));
				return -1;
			}
		}
		else
		{
		//Сохраним праматеры с которыми успешно соединились
			if (save_global)
			{
				strlcpy (global_user_name, (user ? user : ""),
					_DBGOVERNOR_BUFFER_128);
				strlcpy (global_host, (host ? host : ""),
					_DBGOVERNOR_BUFFER_512);
				strlcpy (global_user_password, (password ? password : ""),
					_DBGOVERNOR_BUFFER_256);
				strlcpy (global_db_name, (db_name ? db_name : ""),
					_DBGOVERNOR_BUFFER_512);
			}
		}
	}
	else
	{
		//Сохраним праматеры с которыми успешно соединились
		if (save_global)
		{
			strlcpy (global_user_name, (user_name ? user_name : ""),
				_DBGOVERNOR_BUFFER_128);
			strlcpy (global_host, (host ? host : ""), _DBGOVERNOR_BUFFER_512);
			strlcpy (global_user_password, (user_password ? user_password : ""),
				_DBGOVERNOR_BUFFER_256);
			strlcpy (global_db_name, (db_name ? db_name : ""),
				_DBGOVERNOR_BUFFER_512);
		}
	}
	return 0;
}

static int
local_reconnect(MYSQL ** mysql_internal)
{
	char *unm = NULL;
	char *upwd = NULL;
	(*_mysql_close) (*mysql_internal);
	*mysql_internal = NULL;

	*mysql_internal = (*_mysql_init) (NULL);
	if (*mysql_internal == NULL)
	{
		LOG(L_ERR|L_MYSQL, "can't init mysql structure");
		return -1;
	}

	if (global_user_name[0])
		unm = global_user_name;
	if (global_user_password[0])
		upwd = global_user_password;
	my_bool reconnect = 1;
	//Авторекоонет - подключить
	(*_mysql_options) (*mysql_internal, MYSQL_OPT_RECONNECT, &reconnect);
	//Еще разок соединимся
	if (!(*_mysql_real_connect) (*mysql_internal, global_host, unm, upwd,
					global_db_name, 0, unix_socket_address, 0))
	{
		(*_mysql_options) (*mysql_internal, MYSQL_OPT_RECONNECT, &reconnect);
		if (!_load_defaults)
		{
			if ((*_mysql_options)(*mysql_internal, MYSQL_READ_DEFAULT_GROUP, "client"))
			{
				if ((*_mysql_options)(*mysql_internal, MYSQL_READ_DEFAULT_GROUP, "mysqld"))
				{
					(*_mysql_options)(*mysql_internal, MYSQL_READ_DEFAULT_GROUP, "dbgovernor");
				}
			}
		}
		if (!(*_mysql_real_connect) (*mysql_internal, NULL, NULL, NULL,
								NULL, 0, unix_socket_address, 0))
		{
			//Error again, stop trying
			LOG(L_ERR|L_MYSQL, "connect failed: %s", db_getlasterror(*mysql_internal));
			return -1;
		}
	}
	return 0;
}

//Exec query, if error occurred - try again EXEC_QUERY_TRIES times
int
db_mysql_exec_query(const char *query, MYSQL ** mysql_internal)
{
	LOG(L_MYSQL, "executing '%s'", query);

	//Проверим наличие соединения, а вдруг пропало
	if ((*_mysql_ping) (*mysql_internal))
	{
		//База действительно ушла прочь, что даже реконнект не помог
		LOG(L_MYSQL, "ping failed, trying local_reconnect()");
		if (local_reconnect(mysql_internal) < 0)
		{
			LOG(L_MYSQL, "local_reconnect() failed");
			return -1;
		}
	}

	int execution_counters = EXEC_QUERY_TRIES;
	while ((*_mysql_query) (*mysql_internal, query))
	{
		execution_counters--;
		if (execution_counters == 1)
			local_reconnect(mysql_internal);	// try to reconnect
		if (execution_counters == 0)
		{
			LOG(L_ERR|L_MYSQL, "connect failed, attempts exhausted: %s", db_getlasterror(*mysql_internal));
			return -1;
		}
	}
	return 0;
}

void
db_close_kill (void)
{
	if (mysql_do_kill != NULL)
	{
		(*_mysql_close) (mysql_do_kill);
		mysql_do_kill = NULL;
	}
}

void
db_close_command (void)
{
	if (mysql_do_command != NULL)
	{
		(*_mysql_close) (mysql_do_command);
		mysql_do_command = NULL;
	}
}

void
db_close_send (void)
{
	if (mysql_send_governor != NULL)
	{
		(*_mysql_close) (mysql_send_governor);
		mysql_send_governor = NULL;
	}
}

//Close all databases connections
int
db_close (void)
{
	db_close_kill ();
	db_close_command ();
	db_close_send ();
	return 0;
}

//Unfreeze all accounts.
void
unfreeze_all()
{
	char sql_buffer[_DBGOVERNOR_BUFFER_8192];
	if (is_mariadb_104plus)
		snprintf (sql_buffer, _DBGOVERNOR_BUFFER_2048 - 1,
			MARIADB104_USER_CONN_LIMIT_UNFREEZE, (unsigned long) -1);
	else
		snprintf (sql_buffer, _DBGOVERNOR_BUFFER_2048 - 1,
			QUERY_USER_CONN_LIMIT_UNFREEZE, (unsigned long) -1);

	if (db_mysql_exec_query(sql_buffer, &mysql_do_command))
		return;
	flush_user_priv();
}

//Unfreeze all accounts.
void
unfreeze_lve()
{
	if (is_mariadb_104plus)
	{
		if (db_mysql_exec_query(MARIADB104_USER_CONN_LIMIT_UNFREEZE_LVE, &mysql_do_command))
			return;
	} else
	{
		if (db_mysql_exec_query(QUERY_USER_CONN_LIMIT_UNFREEZE_LVE, &mysql_do_command))
			return;
	}
	flush_user_priv();
}

//Unfreeze daily
void
unfreeze_daily()
{
	if (mysql_do_command == NULL)
		return;
	char buffer[_DBGOVERNOR_BUFFER_2048];
	if (is_mariadb_104plus)
		snprintf(buffer, _DBGOVERNOR_BUFFER_2048 - 1,
				MARIADB104_USER_CONN_LIMIT_UNFREEZE_DAILY, (unsigned long) -1);
	else
		snprintf(buffer, _DBGOVERNOR_BUFFER_2048 - 1,
				QUERY_USER_CONN_LIMIT_UNFREEZE_DAILY, (unsigned long) -1);
	if (db_mysql_exec_query(buffer, &mysql_do_command))
		return;
	flush_user_priv();
}

//Get long from string
long
db_mysql_get_integer (char *result, unsigned long length)
{
	int index = 0;
	long result_number = 0;
	while (index < length)
	{
		if ((result[index] >= '0') && (result[index] <= '9'))
			result_number = result_number * 10 + (result[index++] - '0');
		else
			break;
	}
	return result_number;
}

//Get double from string
double
db_mysql_get_float (char *result, unsigned long length)
{
	int index = 0;
	double result_number = 0;
	double after_point_mul = 1;
	short after_point = 0;
	while (index < length)
	{
		if (result[index] == 0)
			break;
		if (after_point)
		{
			after_point_mul *= 0.1;
		}
		if ((result[index] == '.') || (result[index] == ','))
			after_point = 1;
		if ((result[index] >= '0') && (result[index] <= '9'))
		{
			if (after_point)
				result_number += (result[index] - '0') * after_point_mul;
			else
				result_number = result_number * 10 + (result[index] - '0');
		}
		index++;
	}
	return result_number;
}

//Get ranged string from string. NULL at end safety
void
db_mysql_get_string (char *buffer, char *result, unsigned long length,
		unsigned long max_bufer_len)
{
	unsigned long nlen = 0;
	if (max_bufer_len < length)
		nlen = max_bufer_len - 1;
	else
		nlen = length;
	memcpy (buffer, result, nlen);
	buffer[nlen] = 0;
}

//Get last DB error
char *
db_getlasterror (MYSQL * mysql_internal)
{
	if (mysql_internal != NULL)
		return (char *) (*_mysql_error) (mysql_internal);
	else
		return NULL;
}

void
update_user_limit_no_flush(const char *user_name, unsigned int limit)
{
	if (mysql_do_command == NULL)
		return;
	char user_name_alloc[USERNAMEMAXLEN * 2];
	(*_mysql_real_escape_string) (mysql_do_command, user_name_alloc, user_name, strlen (user_name));
	char sql_buffer[_DBGOVERNOR_BUFFER_8192];
	if (is_mariadb_104plus)
		snprintf(sql_buffer, _DBGOVERNOR_BUFFER_8192 - 1, MARIADB104_USER_CONN_LIMIT,	(unsigned long) limit, user_name_alloc);
	else
		snprintf(sql_buffer, _DBGOVERNOR_BUFFER_8192 - 1, QUERY_USER_CONN_LIMIT, 		(unsigned long) limit, user_name_alloc);

	if (db_mysql_exec_query(sql_buffer, &mysql_do_command))
		LOG(L_ERR|L_MYSQL, "Can't execute sql request. Restriction aborted");
	MYSQL_RES *res = (*_mysql_store_result)(mysql_do_command);
	(*_mysql_free_result)(res);
}

//Set new max_user_connections parameter
void
update_user_limit(const char *user_name, unsigned int limit)
{
	update_user_limit_no_flush(user_name, limit);
	flush_user_priv();
}

//Old function. Useless now
void
flush_user_stat()
{
	return;
}

//Save all privileges to base
void
flush_user_priv()
{
	if (mysql_do_command == NULL)
		return;
	if (db_mysql_exec_query(QUERY_FLUSH_USER_PRIV, &mysql_do_command))
		LOG(L_ERR|L_MYSQL, "can't flush user privs");
	MYSQL_RES *res = (*_mysql_store_result)(mysql_do_command);
	(*_mysql_free_result)(res);
}

//KILL QUERY request
void kill_query(const char *user_name)
{
	if (mysql_do_command == NULL)
		return;
	char user_name_alloc[USERNAMEMAXLEN * 2];
	(*_mysql_real_escape_string)(mysql_do_command, user_name_alloc, user_name, strlen(user_name));

	char sql_buffer[_DBGOVERNOR_BUFFER_8192];
	snprintf(sql_buffer, sizeof(sql_buffer), QUERY_KILL_USER_QUERY, user_name_alloc);

	if (db_mysql_exec_query(sql_buffer, &mysql_do_command))
		LOG(L_ERR|L_MYSQL, "Can't execute 'Kill Query'");
	MYSQL_RES *res = (*_mysql_store_result)(mysql_do_command);
	(*_mysql_free_result)(res);
}

void kill_query_by_id(long id, MYSQL **mysql_internal)
{
	if (*mysql_internal == NULL)
		return;
	char sql_buffer[_DBGOVERNOR_BUFFER_8192];
	snprintf(sql_buffer, sizeof(sql_buffer), QUERY_KILL_USER_QUERY_ID, id);
	if (db_mysql_exec_query(sql_buffer, mysql_internal))
		LOG(L_ERR|L_MYSQL, "Can't execute 'Kill Connection'");
	MYSQL_RES *res = (*_mysql_store_result)(*mysql_internal);
	(*_mysql_free_result)(res);
}

void
governor_enable()
{
	if (is_plugin_version)
	{
		LOG(L_SRV|L_MYSQL, "Executing QUERY_GOVERNOR_MODE_ENABLE_PLG");
		if (db_mysql_exec_query(QUERY_GOVERNOR_MODE_ENABLE_PLG, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute QUERY_GOVERNOR_MODE_ENABLE_PLG");

		LOG(L_SRV|L_MYSQL, "Executing QUERY_GOVERNOR_RECON_LVE_PLG2");
		if (db_mysql_exec_query(QUERY_GOVERNOR_RECON_LVE_PLG2, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute QUERY_GOVERNOR_RECON_LVE_PLG2");
	} else
	{
		LOG(L_SRV|L_MYSQL, "Executing QUERY_GOVERNOR_MODE_ENABLE");
		if (db_mysql_exec_query(QUERY_GOVERNOR_MODE_ENABLE, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute QUERY_GOVERNOR_MODE_ENABLE");
	}
	if (mysql_send_governor)
	{
		MYSQL_RES *res = (*_mysql_store_result) (mysql_send_governor);
		(*_mysql_free_result) (res);
	}
}

void
governor_enable_reconn()
{
	if (is_plugin_version)
	{
		if (db_mysql_exec_query(QUERY_GOVERNOR_MODE_ENABLE_RECON_PLG, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute sql request ENABLE_GOVERNOR");
		if (db_mysql_exec_query(QUERY_GOVERNOR_RECON_LVE_PLG2, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute sql request ENABLE_GOVERNOR_SECOND");
	} else
	{
		if (db_mysql_exec_query(QUERY_GOVERNOR_MODE_ENABLE_RECON, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute sql request ENABLE_GOVERNOR");
	}
	if (mysql_send_governor)
	{
		MYSQL_RES *res = (*_mysql_store_result) (mysql_send_governor);
		(*_mysql_free_result) (res);
	}
}

void
governor_enable_lve()
{
	if (is_plugin_version)
	{
		LOG(L_SRV|L_MYSQL, "db_mysql_exec_query(QUERY_GOVERNOR_MODE_ENABLE_LVE_PLG)");
		if (db_mysql_exec_query (QUERY_GOVERNOR_MODE_ENABLE_LVE_PLG, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute sql request ENABLE_GOVERNOR");
		LOG(L_SRV|L_MYSQL, "db_mysql_exec_query(QUERY_GOVERNOR_RECON_LVE_PLG2)");
		if (db_mysql_exec_query (QUERY_GOVERNOR_RECON_LVE_PLG2, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute sql request ENABLE_GOVERNOR_SECOND");
	} else
	{
		LOG(L_SRV|L_MYSQL, "db_mysql_exec_query(QUERY_GOVERNOR_MODE_ENABLE_LVE)");
		if (db_mysql_exec_query (QUERY_GOVERNOR_MODE_ENABLE_LVE, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute sql request ENABLE_GOVERNOR");
	}
	if (mysql_send_governor)
	{
		MYSQL_RES *res = (*_mysql_store_result) (mysql_send_governor);
		(*_mysql_free_result) (res);
	}
}

void
governor_enable_reconn_lve()
{
	if (is_plugin_version)
	{
		if (db_mysql_exec_query(QUERY_GOVERNOR_MODE_ENABLE_RECON_LVE_PLG, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute sql request ENABLE_GOVERNOR");
		if (db_mysql_exec_query(QUERY_GOVERNOR_RECON_LVE_PLG2, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute sql request ENABLE_GOVERNOR_SECOND");
	} else
	{
		if (db_mysql_exec_query(QUERY_GOVERNOR_MODE_ENABLE_RECON_LVE, &mysql_send_governor))
			LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute sql request ENABLE_GOVERNOR");
	}
	if (mysql_send_governor)
	{
		MYSQL_RES *res = (*_mysql_store_result) (mysql_send_governor);
		(*_mysql_free_result) (res);
	}
}

//KILL CONNECTION request
void
kill_connection(const char *user_name)
{
	if (mysql_do_command == NULL)
		return;
	char user_name_alloc[USERNAMEMAXLEN * 2];
	(*_mysql_real_escape_string)(mysql_do_command, user_name_alloc, user_name, strlen(user_name));
	char sql_buffer[_DBGOVERNOR_BUFFER_8192];
	snprintf(sql_buffer, _DBGOVERNOR_BUFFER_8192, QUERY_KILL_USER_CONNECTION, user_name_alloc);
	if (db_mysql_exec_query(sql_buffer, &mysql_do_command))
		LOG(L_ERR|L_SRV|L_MYSQL, "Can't execute sql request Kill connection");
	MYSQL_RES *res = (*_mysql_store_result)(mysql_do_command);
	(*_mysql_free_result)(res);
}

int
db_connect (const char *host, const char *user_name,
	const char *user_password, const char *db_name,
	int argc, char *argv[])
{
	strcpy (global_user_name, "");
	strcpy (global_host, "");
	strcpy (global_user_password, "");
	strcpy (global_db_name, "");

	LOG(L_IMPORTANT|L_MYSQL, "Open send_command connection operation");
	if (db_connect_common (&mysql_send_governor, host, user_name, user_password,
			db_name, argc, argv, 1) < 0)
	{
		LOG(L_ERR|L_MYSQL, "send_command connection error");
		return -1;
	}

	LOG(L_IMPORTANT|L_MYSQL, "Open write_connection operation");
	if (db_connect_common (&mysql_do_command, host, user_name,
			user_password, db_name, argc, argv, 0) < 0)
	{
		LOG(L_ERR|L_MYSQL, "write_connection error");
		db_close_send();
		return -1;
	}

	LOG(L_IMPORTANT|L_MYSQL, "Open do_kill connection operation");
	if (db_connect_common (&mysql_do_kill, host, user_name,
			user_password, db_name, argc, argv, 0) < 0)
	{
		LOG(L_ERR|L_MYSQL, "do_kill connection error");
		db_close_command();
		db_close_send();
		return -1;
	}

	return 0;
}

static int find_mariadb104plus(char *buffer)
{
	char *saveptr;
	char *ptr;
	int ver;
	if (strstr (buffer, "-MariaDB") == NULL)
		return 0;

	ptr = strtok_r(buffer, ".", &saveptr);
	if (!ptr)
		return 0;

	ver = atoi(ptr);
	if (ver > 10)
		return 1;

	if (ver < 10)
		return 0;

	ptr = strtok_r(NULL, ".", &saveptr);
	if (!ptr)
		return 0;

	ver = atoi(ptr);
	if (ver >= 4)
		return 1;

	return 0;
}

int
check_mysql_version()
{
	MYSQL_RES *res;
	MYSQL_ROW row;
	unsigned long *lengths;
	char buffer[_DBGOVERNOR_BUFFER_2048];
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	if (mysql_send_governor != NULL)
	{
		if (db_mysql_exec_query (QUERY_GET_SERVER_INFO, &mysql_send_governor))
		{
			LOG(L_ERR|L_MYSQL, "Get mysql vesrion request failed");
			return 0;
		}
		res = (*_mysql_store_result) (mysql_send_governor);
		row = (*_mysql_fetch_row) (res);
		if (row)
		{
			lengths = (*_mysql_fetch_lengths) (res);
			db_mysql_get_string (buffer, row[0], lengths[0],
						_DBGOVERNOR_BUFFER_2048);
			if (strstr (buffer, "-cll-lve"))
			{
				if (strstr (buffer, "-cll-lve-plg"))
				{
					is_plugin_version = 1;
				}
				is_mariadb_104plus = find_mariadb104plus(buffer);

				LOG(L_IMPORTANT|L_MYSQL, "MySQL version correct %s", buffer);
				if (is_plugin_version)
					LOG(L_IMPORTANT|L_MYSQL, "Governor with plugin mode enabled");
				LOG(L_IMPORTANT|L_MYSQL, "MariaDB version 10.4+ %sFOUND", is_mariadb_104plus ? "" : "NOT ");
				(*_mysql_free_result) (res);
				return 1;
			}
			else
			{
				LOG(L_IMPORTANT|L_MYSQL, "Update your MySQL to CLL version from repo.cloudlinux.com. Current is %s", buffer);
				(*_mysql_free_result) (res);
				return 0;
			}
		}
		else
		{
			(*_mysql_free_result) (res);
			LOG(L_ERR|L_MYSQL, "Unknown mysql version");
			return 0;
		}
	}
	else
	{
		LOG(L_ERR|L_MYSQL, "Connection to db is absent");
		return 0;
	}
}

char *
get_work_user (void)
{
	return work_user;
}

//LVE CONNECTION request
void
lve_connection(const char *user_name)
{
	char user_name_alloc[USERNAMEMAXLEN * 2];
	(*_mysql_real_escape_string) (mysql_do_command, user_name_alloc, user_name, strlen(user_name));
	char sql_buffer[_DBGOVERNOR_BUFFER_8192];
	snprintf (sql_buffer, _DBGOVERNOR_BUFFER_8192, QUERY_LVE_USER_CONNECTION, user_name_alloc);
	if (db_mysql_exec_query (sql_buffer, &mysql_do_command))
		LOG(L_ERR|L_MYSQL, "Can't execute sql request");
	MYSQL_RES *res = (*_mysql_store_result) (mysql_do_command);
	(*_mysql_free_result) (res);
}

//LOGGER USER QUERIES
int create_dir(void)
{
	GDate *date = g_date_new();
	const time_t timestamp = time(NULL);
	g_date_set_time_t(date, timestamp);

	if (g_mkdir_with_parents(PATH_TO_LOG_USER_QUERIES, 0755) == 0)
	{
		if (g_chdir(PATH_TO_LOG_USER_QUERIES) == 0)
		{
			char tek_day_dir[100];
			sprintf(tek_day_dir, "%d-%d-%d", g_date_get_year(date), g_date_get_month(date), g_date_get_day(date));
			if (g_mkdir_with_parents(tek_day_dir, 0755) == 0)
			{
				g_date_free(date);
				if (g_chdir(tek_day_dir) == 0)
					return 1;
			}
		}
	}
	g_date_free(date);
	return 0;
}

void log_user_queries(const char *user_name)
{
	if (mysql_do_command == NULL)
		return;

	const time_t timestamp = time(NULL);

	char user_name_alloc[USERNAMEMAXLEN * 2];
	(*_mysql_real_escape_string)(mysql_do_command, user_name_alloc, user_name, strlen(user_name));
	char sql_buffer[_DBGOVERNOR_BUFFER_8192];
	snprintf(sql_buffer, sizeof(sql_buffer), QUERY_GET_PROCESSLIST_INFO);
	if (db_mysql_exec_query (sql_buffer, &mysql_do_command))
	{
		LOG(L_ERR|L_MYSQL, "Get show processlist failed");
		return;
	}

	MYSQL_RES *res = (*_mysql_store_result) (mysql_do_command);
	unsigned long counts = (*_mysql_num_rows) (res);

	if (create_dir () && counts > 0)
	{
		char file_name[USERNAMEMAXLEN + 1 + 10];
		snprintf(file_name, sizeof(file_name), "%s.%lld", user_name, (long long)timestamp);
		FILE *log_queries = fopen(file_name, "w");
		if (log_queries)
		{
			MYSQL_ROW row;
			while ((row = (*_mysql_fetch_row) (res)))
			{
				if (strcmp(row[1], user_name) == 0)
				{
					char buffer[_DBGOVERNOR_BUFFER_8192];
					const unsigned long *lengths = (*_mysql_fetch_lengths) (res);
					db_mysql_get_string (buffer, row[7], lengths[7], _DBGOVERNOR_BUFFER_8192);
					fprintf (log_queries, "%s\n", buffer);
				}
			}
			fclose (log_queries);
		}
		else
		{
			(*_mysql_free_result) (res);
			LOG(L_ERR|L_MYSQL, "Can't open file %s", file_name);
			return;
		}
	}
	(*_mysql_free_result) (res);
}

MYSQL **
get_mysql_connect (void)
{
	return &mysql_do_kill;
}

int
activate_plugin()
{
	if (is_plugin_version)
	{
		int is_found_plg = 0;
		MYSQL_RES *res;
		MYSQL_ROW row;
		unsigned long *lengths;
		char buffer[_DBGOVERNOR_BUFFER_2048];
		struct governor_config data_cfg;
		get_config_data (&data_cfg);

		if (mysql_send_governor != NULL)
		{
			if (db_mysql_exec_query (QUERY_GET_PLUGIN_INFO, &mysql_send_governor))
			{
				LOG(L_ERR|L_MYSQL, "Get mysql plugin request failed");
				return 0;
			}
			res = (*_mysql_store_result) (mysql_send_governor);
			while ((row = (*_mysql_fetch_row) (res)))
			{
				lengths = (*_mysql_fetch_lengths) (res);
				db_mysql_get_string (buffer, row[0], lengths[0],
						_DBGOVERNOR_BUFFER_2048);
				if (!strncasecmp (buffer, "GOVERNOR", _DBGOVERNOR_BUFFER_2048))
				{
					is_found_plg = 1;
				}
			}
			(*_mysql_free_result) (res);
			if (!is_found_plg)
			{
				if (db_mysql_exec_query (QUERY_SET_PLUGIN_INFO, &mysql_send_governor))
				{
					// very strange if()
					if (!strstr ((char *) (*_mysql_error) (mysql_send_governor),
							"Function 'governor' already exists"))
					{
					}
					LOG(L_ERR|L_MYSQL, "Set mysql plugin request failed");
					return 0;
				}
				res = (*_mysql_store_result) (mysql_do_command);
				(*_mysql_free_result) (res);
			}
		}
		else
		{
			LOG(L_ERR|L_MYSQL, "Connection to db is absent");
			return 0;
		}
	}
	return 1;
}

unsigned
select_max_user_connections(const char *username)
{
	char select_buffer[_DBGOVERNOR_BUFFER_8192] = {0};
	MYSQL_RES *res;
	MYSQL_ROW row;
	long val = 0;
	unsigned result = 0;

	if (username == NULL)
	{
		return 0;
	}
	snprintf(select_buffer, _DBGOVERNOR_BUFFER_8192 - 1, QUERY_SELECT_MAX_USER_CONNECTIONS, username);
	if (db_mysql_exec_query(select_buffer, &mysql_do_command) != 0)
	{
		LOG(L_ERR|L_MYSQL, "Can't execute request for max_user_connections (user: %s)", username);
		return 0;
	}
	res = (*_mysql_store_result) (mysql_do_command);
	if (res == NULL)
	{
		LOG(L_ERR|L_MYSQL, "Can't store result for max_user_connections (user: %s)", username);
		return 0;
	}
	row = (*_mysql_fetch_row) (res);
	if (row == NULL)
	{
		/*
			Log it as debug, not as warning, it is ok, that the account is already removed, but still presents in dbuser-map.

			We store in dbuser-map all db accounts, even temporary ones, in order to prevent
			denial-of-service attack via phpMyAdmin.
		*/
		LOG(L_MYSQL, "Can't fetch data from for max_user_connections (user: %s)", username);
		(*_mysql_free_result) (res);
		return 0;
	}
	val = strtol(*row, NULL, 10);
	result = (unsigned) val;
	if (val < 0 || val > UINT_MAX || errno == ERANGE)
	{
		result = 0;
	}
	(*_mysql_free_result) (res);
	return result;
}
