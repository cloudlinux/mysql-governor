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

// -1 - error
//  0 - OK
int
init_mysql_function (void)
{
  char *error;

  if (lib_handle == NULL)
    {
      lib_handle = dlopen ("libmysqlclient.so.21", RTLD_LAZY);
      if (!lib_handle)
	{
          lib_handle = dlopen ("libmysqlclient_r.so.18", RTLD_LAZY);
          if (!lib_handle)
	    {
	      lib_handle = dlopen ("libmysqlclient_r.so.16", RTLD_LAZY);
	      if (!lib_handle)
	        {
	          lib_handle = dlopen ("libmysqlclient_r.so.15", RTLD_LAZY);
	          if (!lib_handle)
		    {
		      lib_handle = dlopen ("libmysqlclient_r.so", RTLD_LAZY);
		      if (!lib_handle)
		        {
		          lib_handle = dlopen ("libmysqlclient.so", RTLD_LAZY);
		          if (!lib_handle)
			    {
			      lib_handle = dlopen ("libperconaserverclient.so.18", RTLD_LAZY);
			      if (!lib_handle)
			      {
				    return -1;
			      }
			    }
		        }
		    }
	        }
	    }
	}

      LOAD_FUNCTION (mysql_store_result);
      LOAD_FUNCTION (mysql_num_rows);
      LOAD_FUNCTION (mysql_free_result);
      LOAD_FUNCTION (mysql_fetch_lengths);
      LOAD_FUNCTION (mysql_fetch_row);
      LOAD_FUNCTION_SKIP (my_init);
      LOAD_FUNCTION_SKIP (load_defaults);
      LOAD_FUNCTION (mysql_init);
      LOAD_FUNCTION (mysql_real_connect);
      LOAD_FUNCTION (mysql_options);
      LOAD_FUNCTION (mysql_query);
      LOAD_FUNCTION (mysql_close);
      LOAD_FUNCTION (mysql_error);
      LOAD_FUNCTION (mysql_real_escape_string);
      LOAD_FUNCTION (mysql_ping);

    }
  return 0;
}

void
delete_mysql_function (void)
{
  if (lib_handle != NULL)
    {
      dlclose (lib_handle);
      lib_handle = NULL;
    }
}
