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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include <sys/select.h>
#include <unistd.h>

#include "data.h"
#include "governor_config.h"
#include "log.h"
#include "mysql_connector_common.h"
#include "dlload.h"
#include "shared_memory.h"

#ifndef NOGOVERNOR

int
main (int argc, char *argv[])
{
	int cmd = 0;
	struct governor_config data_cfg;

	if (!config_init (CONFIG_PATH))
	{
		fprintf (stderr, "Unable to read config file: %s\n", CONFIG_PATH);
		fflush (stderr);
		exit (EXIT_FAILURE);
	}

	get_config_data (&data_cfg);

	if (argc > 1)
	{
		if (!strcasecmp (argv[1], "force-old"))
		{
			cmd = 1;
		}
		if (!strcasecmp (argv[1], "show-bad-users-list"))
		{
			cmd = 2;
		}
		if (!strcasecmp (argv[1], "help"))
		{
			cmd = 3;
		}
	}
	if (cmd == 3)
	{
		printf ("Usage: /usr/sbin/mysql_unfreeze [comand]\n");
		printf ("Commands list:\n");
		printf
		("     empty command        :unfreeze users according to configuration file options\n");
		printf
		("     force-old            :unfreeze users by DBDISABLE method (for old restriction removing)\n");
		printf
		("     show-bad-users-list  :show bad users list (if lve using)\n");
		return 0;
	}
	if (!config_init (CONFIG_PATH))
	{
		fprintf (stderr, "Unable to read config file. Unfreeze aborted\n");
		fflush (stderr);
		exit (-1);
	}
	open_log (data_cfg.log);
	init_mysql_function ();
	if (!data_cfg.is_gpl && data_cfg.use_lve && (cmd != 1))
	{
		if (cmd == 0)
		{
			if (db_connect (data_cfg.host, data_cfg.db_login,
					data_cfg.db_password, "information_schema", argc, argv) < 0)
				exit (-1);
			//unfreeze_lve();
			if (init_bad_users_list_utility () >= 0)
			{
				LOG(L_UNFRZ, "Unfreeze completed");
				remove_bad_users_list_utility ();
			}
			else
			{
				LOG(L_ERR, "Can't init BAD users list");
			}
			db_close ();
		}
		else
		{
			user_in_bad_list_client_show ();
		}
	}
	else
	{
		if (!data_cfg.is_gpl)
		{
			if (db_connect (data_cfg.host, data_cfg.db_login,
					data_cfg.db_password, "information_schema", argc, argv) < 0)
				exit (-1);
			//unfreeze_all();
			//unfreeze_lve();
			LOG(L_UNFRZ, "Unfreeze completed");
			db_close ();
		}
	}
	delete_mysql_function ();
	return 0;
}

#endif
