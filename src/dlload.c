/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */
#include <stdio.h>
#include <dlfcn.h>
#include "dlload.h"

#include "governor_config.h"
#include "log.h"

M_mysql_store_result = NULL;
M_mysql_num_rows = NULL;
M_mysql_free_result = NULL;
M_mysql_fetch_lengths = NULL;
M_mysql_fetch_row = NULL;
M_my_init = NULL;
M_load_defaults = NULL;
M_mysql_init = NULL;
M_mysql_real_connect = NULL;
M_mysql_options = NULL;
M_mysql_query = NULL;
M_mysql_close = NULL;
M_mysql_error = NULL;
M_mysql_real_escape_string = NULL;
M_mysql_ping = NULL;

static void *lib_handle = NULL;

//Load mysql fucntions

void
delete_mysql_function (void)
{
	if (lib_handle != NULL)
	{
		dlclose (lib_handle);
		lib_handle = NULL;
	}
}

static const char *mysqlclient_libs[] =
{
	"libmysqlclient.so.21",
	"libmysqlclient_r.so.18",
	"libmysqlclient_r.so.16",
	"libmysqlclient_r.so.15",
	"libmysqlclient_r.so",
	"libmysqlclient.so",
	"libmysqlclient.so.18",
	"libmysqlclient.so.19",
	"libmariadb.so",
	"libmariadb.so.3",
	"libperconaserverclient.so.18"
};


#define LOAD_FUNCTION_SKIP(x) do { \
	_##x = dlsym(lib_handle, #x);\
	if ((error = dlerror()) != NULL) {\
		_##x = NULL; }\
} while(0)

#define LOAD_FUNCTION_LOGGED(x) do {\
	_##x = dlsym(lib_handle, #x);\
	if ((error = dlerror()) != NULL) {\
		get_config_data(&data_cfg);\
		WRITE_LOG (NULL, 0, "cannot find (%s) sym in (%s) library: %s",\
				data_cfg.log_mode, #x, mysqlclient_lib, error);\
		delete_mysql_function();\
		return -1; }\
} while(0)


// -1 - error
//  0 - OK
int
init_mysql_function (void)
{
	int i;
	char *error;
	const char *mysqlclient_lib = NULL;
	struct governor_config data_cfg;

	if (!lib_handle)
	{
		for (i = 0; i < sizeof mysqlclient_libs / sizeof mysqlclient_libs[0]; ++i)
		{
			mysqlclient_lib = mysqlclient_libs[i];
			lib_handle = dlopen(mysqlclient_lib, RTLD_LAZY);
			if (lib_handle)
				break;
		}
	}

	if (!lib_handle)
	{
		get_config_data(&data_cfg);
		WRITE_LOG (NULL, 0, "cannot find any mysqlclient library", data_cfg.log_mode);
		return -1;
	}
	//assert(mysqlclient_lib != NULL);

	LOAD_FUNCTION_LOGGED (mysql_store_result);
	LOAD_FUNCTION_LOGGED (mysql_num_rows);
	LOAD_FUNCTION_LOGGED (mysql_free_result);
	LOAD_FUNCTION_LOGGED (mysql_fetch_lengths);
	LOAD_FUNCTION_LOGGED (mysql_fetch_row);
	LOAD_FUNCTION_SKIP (my_init);
	LOAD_FUNCTION_SKIP (load_defaults);
	LOAD_FUNCTION_LOGGED (mysql_init);
	LOAD_FUNCTION_LOGGED (mysql_real_connect);
	LOAD_FUNCTION_LOGGED (mysql_options);
	LOAD_FUNCTION_LOGGED (mysql_query);
	LOAD_FUNCTION_LOGGED (mysql_close);
	LOAD_FUNCTION_LOGGED (mysql_error);
	LOAD_FUNCTION_LOGGED (mysql_real_escape_string);
	LOAD_FUNCTION_LOGGED (mysql_ping);
	return 0;
}

