/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "data.h"
#include "dbgovernor_string_functions.h"
#include "dlload.h"
#include "governor_config.h"
#include "log.h"
#include "stats.h"
#include "user_account.h"
#include "getsysinfo.h"
#include "log-decoder.h"
#include "wrappers.h"

#include "calc_stats.h"

#include "dbtop_server.h"

void accept_connections (int s);
static void *run_writer (void *data);
static void *run_dbctl_command (void *data);
void send_account (const char *key, Account * ac, FILE * out);

void *
run_server (void *data)
{
	LOG(L_LIFE|L_DBTOP, "thread begin");

	int s;
	if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		LOG(L_ERR|L_DBTOP, "can't create socket: %d", errno);
		// close_log ();
		// close_restrict_log ();
		// exit (EXIT_FAILURE);
		return NULL;
	}

	struct sockaddr_un saun;
	saun.sun_family = AF_UNIX;
	strcpy (saun.sun_path, SOCK_ADDRESS);

	unlink (SOCK_ADDRESS);
	int len = sizeof (saun.sun_family) + strlen (saun.sun_path);

	if (bind (s, (struct sockaddr *) &saun, len) < 0)
	{
		LOG(L_ERR|L_DBTOP, "bind failed: %d", errno);
		// close_log ();
		// close_restrict_log ();
		close (s);
		// exit (EXIT_FAILURE);
		return NULL;
	}

	if (listen (s, 3) < 0)
	{
		LOG(L_ERR|L_DBTOP, "listen failed: %d", errno);
		// close_log ();
		// close_restrict_log ();
		close (s);
		// exit (EXIT_FAILURE);
		return NULL;
	}
	/* Start daemon accept cycle */
	accept_connections (s);
	close (s);

	LOG(L_LIFE|L_DBTOP, "thread end");
	return NULL;
}

/*
    This function is called from handle_client_connect, open file descriptor is passed as a pointer.
    handle_client_connect expects that this function will close file descriptor
*/
void *
run_dbtop_command (void *data)
{
	FILE *out;
	intptr_t ns = (intptr_t) data;
	out = fdopen ((int) ns, "w+");
	if (!out)
	{
		//Try to open second time
		LOG(L_DBTOP, "first fdopen() failed");
		out = fdopen ((int) ns, "w+");
		//If null, then cancel command
		if (!out)
		{
			LOG(L_DBTOP, "second fdopen() failed");
			close (ns);
			return NULL;
		}
	}
	int new_record = 1, get_response;
	size_t resp = 0;
	resp = fwrite_wrapper (&new_record, sizeof (int), 1, out);
	if (!resp)
	{
		LOG(L_DBTOP, "write failed");
		fflush (out);
		fclose (out);
		return NULL;
	}
	resp = fread_wrapper (&get_response, sizeof (int), 1, out);
	if (!resp)
	{
		LOG(L_DBTOP, "no response");
		fflush (out);
		fclose (out);
		return NULL;
	}
	g_hash_table_foreach ((GHashTable *) get_accounts (), (GHFunc) send_account,
				out);
	new_record = 2;
	fwrite_wrapper (&new_record, sizeof (int), 1, out);
	fflush (out);
	fclose (out);
	return NULL;
}

/*
    handle_client_connect expects that functions called from it will close file descriptor
*/
void *handle_client_connect(void *fd)
{
	int ns = (int) ((intptr_t) fd);

	client_type_t ctt;
	int result = read(ns, &ctt, sizeof(client_type_t));
	switch (result)
	{
		case 0:
		case -1:
			close (ns);
			return NULL;
	}

	if (ctt == DBTOP)
	{
		run_writer(fd);
	}
	else if (ctt == DBCTL)
	{
		run_dbctl_command(fd);
	}
	else if (ctt == DBTOPCL)
	{
		run_dbtop_command(fd);
	}
	else
	{
		LOG(L_ERR|L_DBTOP, "incorrect connection");
		close (ns);
	}
	return NULL;
}

void
accept_connections (int s)
{
	struct sockaddr_un fsaun;
	int fromlen = sizeof (fsaun);
	pthread_t thread;

	while (1)
	{
		int ns;

		if ((ns = accept (s, (struct sockaddr *) &fsaun, &fromlen)) < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				LOG(L_ERR|L_DBTOP, "can't server accept");
				close_log ();
				close_restrict_log ();
				return;
			}
		}
		intptr_t accept_socket = (intptr_t) ns;
		pthread_create (&thread, NULL, handle_client_connect, (void*) accept_socket);
		pthread_detach (thread);
	}
}

volatile static int flag_need_to_renew_dbmap = 0;

void *
renew_map_on_request (void *data)
{
	LOG(L_LIFE|L_USRMAPRQ, "thread begin");

	time_t last_renew = 0;
	flag_need_to_renew_dbmap = 0;

	while (1)
	{
		if (flag_need_to_renew_dbmap)
		{
			time_t current_check = time(NULL);
			if ((last_renew+DBMAPHOOK_ANTIDDOS)<current_check)
			{
				flag_need_to_renew_dbmap = 0;
				last_renew = current_check;
				pid_t renew_pid = fork ();
				if (renew_pid < 0)
					LOG(L_ERR|L_USRMAPRQ, "(%d)Fork error (renew dbmap). Path %s", errno, "dbupdate");
				else
				{
					if (!renew_pid)
					{
						execl ("/usr/share/lve/dbgovernor/mysqlgovernor.py",
								"/usr/share/lve/dbgovernor/mysqlgovernor.py", "--dbupdate", NULL);
						LOG(L_ERR|L_USRMAPRQ, "(%d)Exec error (renew dbmap). Path %s", errno, "dbupdate");
						exit (0);
					}
				}
			}
		}
		sleep(DBMAPHOOK_RECHECK);
	}

	LOG(L_LIFE|L_USRMAPRQ, "thread end");
	return NULL;
}

/* NOTE:
   Modifying a GHashTable while iterating over it can lead to undefined behavior.
   More safe and common approach to mitigate this issue is to create a snapshot of
   the keys and then iterate over this snapshot to make the necessary modifications.
 */
static void
dbctl_restrict_set_safe(GHashTable *accounts_hash, DbCtlCommand *command)
{
	GList *keys, *iterator;
	gpointer key;

	lock_acc();
	keys = g_hash_table_get_keys(accounts_hash);

	for (iterator = keys; iterator; iterator = iterator->next)
	{
		key = iterator->data;
		dbctl_restrict_set(key, g_hash_table_lookup(accounts_hash, key), command);
	}

	unlock_acc();
	g_list_free(keys);
}

/*
    This function is called from handle_client_connect, open file descriptor is passed as a pointer.
    handle_client_connect expects that this function will close file descriptor
*/
static void *run_dbctl_command(void *data)
{
	intptr_t ns = (intptr_t) data;

	DbCtlCommand command;
	int result = read(ns, &command, sizeof(DbCtlCommand));

	struct governor_config data_cfg;
	get_config_data(&data_cfg);

	if (command.command == REREAD_CFG)
	{
		//config_free();
		//config_init( CONFIG_PATH );
		reread_config ();
	}
	else if (command.command == REINIT_USERS_LIST)
	{
		reread_config ();
		reinit_users_list ();
	}
	else if (command.command == RESTRICT)
	{
		if (!data_cfg.is_gpl)
		{
			if (data_cfg.all_lve || !data_cfg.use_lve)
			{
				close (ns);
				return NULL;	//lve use=all or off
			}
			GHashTable *accounts = get_accounts();
			dbctl_restrict_set_safe(accounts, &command);
		}
	}
	else if (command.command == UNRESTRICT)
	{
		if (!data_cfg.is_gpl)
		{
			if (data_cfg.all_lve || !data_cfg.use_lve)
			{
				close(ns);
				return NULL;	//lve use=all or off
			}
			lock_acc ();
			g_hash_table_foreach ((GHashTable *) get_accounts (),
				(GHFunc) dbctl_unrestrict_set, &command);
			unlock_acc ();
		}
	}
	else if (command.command == UNRESTRICT_A)
	{
		if (!data_cfg.is_gpl)
		{
			if (data_cfg.all_lve || !data_cfg.use_lve)
			{
				close(ns);
				return NULL;	//lve use=all or off
			}
			lock_acc ();
			g_hash_table_foreach ((GHashTable *) get_accounts (),
				(GHFunc) dbctl_unrestrict_all_set, NULL);
			unlock_acc ();
		}
	}
	else if (command.command == LIST || command.command == LIST_R)
	{
		FILE *out;
		out = fdopen ((int) ns, "w+");
		if (!out)
		{
			close (ns);
			return NULL;
		}
		int new_record = 1, get_response;

		while (!feof (out))
		{
			fwrite_wrapper (&new_record, sizeof (int), 1, out);
			if (!fread_wrapper (&get_response, sizeof (int), 1, out))
				break;

			g_hash_table_foreach ((GHashTable *) get_accounts (),
				(GHFunc) send_account, out);
			new_record = 2;
			if (!fwrite_wrapper (&new_record, sizeof (int), 1, out))
				break;

			fflush (out);
			sleep (1);
			new_record = 1;
		}
		fclose (out);
		ns = -1;
	}
	else if (command.command == DBUSER_MAP_CMD)
	{
		flag_need_to_renew_dbmap = 1;
	}

	if (ns >= 0)
	{
		close (ns);
	}

	return NULL;
}

/*
    This function is called from handle_client_connect, open file descriptor is passed as a pointer.
    handle_client_connect expects that this function will close file descriptor
*/
static void *
run_writer (void *data)
{
	FILE *out;
	intptr_t ns = (intptr_t) data;
	out = fdopen ((int) ns, "w+");
	if (!out)
	{
		out = fdopen ((int) ns, "w+");
		if (!out)
		{
			close (ns);
			return NULL;
		}
	}
	int new_record = 1, get_response;
	while (!feof (out))
	{
		fwrite_wrapper (&new_record, sizeof (int), 1, out);
		if (!fread_wrapper (&get_response, sizeof (int), 1, out))
			break;
		g_hash_table_foreach ((GHashTable *) get_accounts (),
			(GHFunc) send_account, out);
		new_record = 2;
		if (!fwrite_wrapper (&new_record, sizeof (int), 1, out))
			break;
		fflush (out);
		sleep (1);
		new_record = 1;
	}
	fclose (out);
	return NULL;
}

void
send_account (const char *key, Account * ac, FILE * out)
{
	int new_record = 0;
	stats_limit_cfg cfg_buf;
	stats_limit_cfg *sl = config_get_account_limit (ac->id, &cfg_buf);
	if (sl->mode != IGNORE_MODE)
	{
		if (!fwrite_wrapper (&new_record, sizeof (int), 1, out))
			return;
		dbtop_exch dt;
		lock_acc ();
		strncpy (dt.id, ac->id, sizeof (username_t) - 1);
		memcpy (&dt.current, &ac->current, sizeof (Stats));
		memcpy (&dt.short_average, &ac->short_average, sizeof (Stats));
		memcpy (&dt.mid_average, &ac->mid_average, sizeof (Stats));
		memcpy (&dt.long_average, &ac->long_average, sizeof (Stats));
		memcpy (&dt.restricted, &ac->restricted, sizeof (int));
		memcpy (&dt.timeout, &ac->timeout, sizeof (int));
		memcpy (&dt.info, &ac->info, sizeof (restrict_info));
		memcpy (&dt.start_count, &ac->start_count, sizeof (time_t));
		unlock_acc ();
		if (!fwrite_wrapper (&dt, sizeof (dbtop_exch), 1, out))
			return;
	}
}

