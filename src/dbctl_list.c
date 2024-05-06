/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Shkatula Pavel <shpp@cloudlinux.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <string.h>
#include <math.h>
#include <glib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "data.h"
#include "stats.h"
#include "wrappers.h"
#include "governor_config.h"
#include "shared_memory.h"

#include "dbctl_list.h"
#include "dbctl_conn.h"
#include "dbctl_cfg.h"

DbCtlLimitAttr *dbctl_l_attr_list = NULL;

GList *
read_info (FILE * in)
{
	GList *recv_accounts = NULL;
	Account *ac;
	int new_record;
	int tester = 1;

	while (fread_wrapper (&new_record, sizeof (int), 1, in))
	{
		if (new_record == 1)
		{
			fwrite_wrapper (&tester, sizeof (int), 1, in);
		}
		else if (new_record == 0)
		{
			ac = malloc (sizeof (Account));
			ac->id = malloc (sizeof (username_t));
			ac->users = NULL;
			dbtop_exch dt;
			if (fread_wrapper (&dt, sizeof (dbtop_exch), 1, in))
			{
				strncpy (ac->id, dt.id, sizeof (username_t));
				memcpy (&ac->current, &dt.current, sizeof (Stats));
				memcpy (&ac->short_average, &dt.short_average, sizeof (Stats));
				memcpy (&ac->mid_average, &dt.mid_average, sizeof (Stats));
				memcpy (&ac->long_average, &dt.long_average, sizeof (Stats));
				memcpy (&ac->restricted, &dt.restricted, sizeof (int));
				memcpy (&ac->timeout, &dt.timeout, sizeof (int));
				memcpy (&ac->info, &dt.info, sizeof (restrict_info));
				memcpy (&ac->start_count, &dt.start_count, sizeof (time_t));
				recv_accounts = g_list_append (recv_accounts, ac);
			}
			else
			{
				perror ("Done");
				exit (0);
			}
		}
		else
			return recv_accounts;
	}
	return recv_accounts;
}

gint
CompareAccountByUsername (gconstpointer ptr_a, gconstpointer ptr_b)
{
	Account *a, *b;
	a = (Account *) ptr_a;
	b = (Account *) ptr_b;

	return strncmp (a->id, b->id, USERNAMEMAXLEN);
}

GPtrArray *
addMemoryUser (FILE * in, GPtrArray * tags)
{
	DbCtlFoundTag *found_tag_list = NULL;
	GList *ac = NULL;
	GList *list = read_info (in);
	GPtrArray *Tags = tags;

	for (ac = g_list_first (list); ac != NULL; ac = g_list_next (ac))
	{
		found_tag_list = (DbCtlFoundTag *) malloc (sizeof (DbCtlFoundTag));
		strcpy (found_tag_list->tag, "user");
		found_tag_list->attr =
			g_hash_table_new_full (g_str_hash, g_str_equal,
				(GDestroyNotify) found_tag_key_destroyed,
				(GDestroyNotify) found_tag_data_destroyed);
		found_tag_list->limit_attr = g_ptr_array_new ();

		Account *_ac = (Account *) ac->data;
		int found_user = 0, i = 0;
		for (; i < Tags->len; i++)
		{
			DbCtlFoundTag *found_tag_ = g_ptr_array_index (Tags, i);
			char *name_list = GetUserName (found_tag_->attr);
			if (name_list)
				if (strcmp (name_list, _ac->id) == 0)
					found_user++;
		}

		if (!found_user)
		{
			char *key_ = g_strdup ("name");
			char *val_ = g_strdup (_ac->id);
			g_hash_table_insert (found_tag_list->attr, key_, val_);
			key_ = g_strdup ("mode");
			val_ = g_strdup ("restrict");
			g_hash_table_insert (found_tag_list->attr, key_, val_);
			g_ptr_array_add (Tags, found_tag_list);
		}
		else
		{
			if (found_tag_list->attr)
				g_hash_table_destroy (found_tag_list->attr);
			if (found_tag_list->limit_attr)
				g_ptr_array_free (found_tag_list->limit_attr, TRUE);
			free (found_tag_list);
		}

		free (_ac->id);
		free (_ac);
	}

	g_list_free (list);
	return Tags;
}

static void
print_list (FILE * in, int flag, int non_priv, int raw)
{
	DbCtlLimitAttr cpu_def, read_def, write_def;
	char val = 'M';
	if (flag == 1)
		val = 'K';
	else if ( flag == 2 )
		val = ' ';
	non_priv = 1;
	if (access(CONFIG_PATH, R_OK) == 0)
	{
		non_priv = 0;
	}
	ReadCfg ((non_priv?DUPLICATE_CONFIG_PATH:CONFIG_PATH), "default");
	if (flag)
		printf (" user\tcpu(%%)\tread(%cB/s)\twrite(%cB/s)\n", val, val);
	else
		printf (" user             cpu(%%)                     read(%cB/s)                        write(%cB/s)\n", val, val);

	GetLimitsForDefault (GetCfg (), flag, 0);

	DbCtlFoundTag *found_tag_ = g_ptr_array_index (GetCfg (), 0);

	strncpy (cpu_def.l_current,
		GetLimitAttr (found_tag_->limit_attr, "cpu", "current"),
		sizeof (cpu_def.l_current) - 1);
	strncpy (cpu_def.l_short,
		GetLimitAttr (found_tag_->limit_attr, "cpu", "short"),
		sizeof (cpu_def.l_short) - 1);
	strncpy (cpu_def.l_mid, GetLimitAttr (found_tag_->limit_attr, "cpu", "mid"),
		sizeof (cpu_def.l_mid) - 1);
	strncpy (cpu_def.l_long,
		GetLimitAttr (found_tag_->limit_attr, "cpu", "long"),
		sizeof (cpu_def.l_long) - 1);

	strncpy (read_def.l_current,
		GetLimitAttr (found_tag_->limit_attr, "read", "current"),
		sizeof (read_def.l_current) - 1);
	strncpy (read_def.l_short,
		GetLimitAttr (found_tag_->limit_attr, "read", "short"),
		sizeof (read_def.l_short) - 1);
	strncpy (read_def.l_mid,
		GetLimitAttr (found_tag_->limit_attr, "read", "mid"),
		sizeof (read_def.l_mid) - 1);
	strncpy (read_def.l_long,
		GetLimitAttr (found_tag_->limit_attr, "read", "long"),
		sizeof (read_def.l_long) - 1);

	strncpy (write_def.l_current,
		GetLimitAttr (found_tag_->limit_attr, "write", "current"),
		sizeof (write_def.l_current) - 1);
	strncpy (write_def.l_short,
		GetLimitAttr (found_tag_->limit_attr, "write", "short"),
		sizeof (write_def.l_short) - 1);
	strncpy (write_def.l_mid,
		GetLimitAttr (found_tag_->limit_attr, "write", "mid"),
		sizeof (write_def.l_mid) - 1);
	strncpy (write_def.l_long,
		GetLimitAttr (found_tag_->limit_attr, "write", "long"),
		sizeof (write_def.l_long) - 1);
	FreeCfg ();

	DbCtlLimitAttr limit_attr_def;
	ReadCfg ((non_priv?DUPLICATE_CONFIG_PATH:CONFIG_PATH), "user");
	GPtrArray *tags = addMemoryUser (in, GetCfg ());
	GetLimitsForUsers (tags, &cpu_def, &read_def, &write_def, flag, raw, 0);
	FreeCfg ();
}


static void
print_json (FILE * in, int flag)
{
	int raw = 1;
	int non_priv = 1;
	DbCtlLimitAttr cpu_def, read_def, write_def;
	if (access(CONFIG_PATH, R_OK) == 0)
	{
		non_priv = 0;
	}
	printf("{ ");
	ReadCfg ((non_priv?DUPLICATE_CONFIG_PATH:CONFIG_PATH), "default");
	GetLimitsForDefault (GetCfg (), flag, 1);

	DbCtlFoundTag *found_tag_ = g_ptr_array_index (GetCfg (), 0);

	strncpy (cpu_def.l_current, GetLimitAttr (found_tag_->limit_attr, "cpu", "current"), sizeof (cpu_def.l_current) - 1);
	strncpy (cpu_def.l_short,   GetLimitAttr (found_tag_->limit_attr, "cpu", "short"),   sizeof (cpu_def.l_short)   - 1);
	strncpy (cpu_def.l_mid,     GetLimitAttr (found_tag_->limit_attr, "cpu", "mid"),     sizeof (cpu_def.l_mid)     - 1);
	strncpy (cpu_def.l_long,    GetLimitAttr (found_tag_->limit_attr, "cpu", "long"),    sizeof (cpu_def.l_long)    - 1);

	strncpy (read_def.l_current, GetLimitAttr (found_tag_->limit_attr, "read", "current"), sizeof (read_def.l_current) - 1);
	strncpy (read_def.l_short,   GetLimitAttr (found_tag_->limit_attr, "read", "short"),   sizeof (read_def.l_short)   - 1);
	strncpy (read_def.l_mid,     GetLimitAttr (found_tag_->limit_attr, "read", "mid"),     sizeof (read_def.l_mid)     - 1);
	strncpy (read_def.l_long,    GetLimitAttr (found_tag_->limit_attr, "read", "long"),    sizeof (read_def.l_long)    - 1);

	strncpy (write_def.l_current, GetLimitAttr (found_tag_->limit_attr, "write", "current"), sizeof (write_def.l_current) - 1);
	strncpy (write_def.l_short,   GetLimitAttr (found_tag_->limit_attr, "write", "short"),   sizeof (write_def.l_short)   - 1);
	strncpy (write_def.l_mid,     GetLimitAttr (found_tag_->limit_attr, "write", "mid"),     sizeof (write_def.l_mid)     - 1);
	strncpy (write_def.l_long,    GetLimitAttr (found_tag_->limit_attr, "write", "long"),    sizeof (write_def.l_long)    - 1);
	FreeCfg ();

	DbCtlLimitAttr limit_attr_def;
	ReadCfg ((non_priv?DUPLICATE_CONFIG_PATH:CONFIG_PATH), "user");
	GPtrArray *tags = addMemoryUser (in, GetCfg ());
	GetLimitsForUsers (tags, &cpu_def, &read_def, &write_def, flag, 1, 1);
	FreeCfg ();
	printf(" }\n");
}

char
get_restrict_level (GOVERNORS_PERIOD_NAME restrict_level)
{
	char ch;
	switch (restrict_level)
	{
		case 0:
			ch = '1';
			break;
		case 1:
			ch = '2';
			break;
		case 2:
			ch = '3';
			break;
		default:
			ch = '4';
	}
	return ch;
}

char *
read_restrict_reriod (Account * ac)
{
	char ch;
	if (ac->info.field_restrict == NO_PERIOD)
	{
		return "";
	}
	else
	{
		switch (ac->info.field_restrict)
		{
			case CURRENT_PERIOD:
				return "current";
				break;
			case SHORT_PERIOD:
				return "short";
				break;
			case MID_PERIOD:
				return "mid";
				break;
			case LONG_PERIOD:
				return "long";
				break;
		}
	}
	return "";
}

char *
read_restrict_reason (Account * ac)
{
	char ch;
	if (ac->info.field_restrict == NO_PERIOD)
	{
		return "";
	}
	else
	{
		switch (ac->info.field_level_restrict)
		{
			case CPU_PARAM:
				return "cpu";
				break;
			case READ_PARAM:
				return "read";
				break;
			case WRITE_PARAM:
				return "write";
				break;
		}
	}
	return "";
}

int
get_time_to_end (Account * ac)
{
	return (((ac->start_count + ac->timeout) - time (NULL)) < 0) ? 0
		  : ((ac->start_count + ac->timeout) - time (NULL));
}

void
print_list_rest (FILE * in)
{
	char stringBuf[1024];

	GList *ac = NULL;
	GList *list = read_info (in);

	list = g_list_sort (list, CompareAccountByUsername);
	printf (" USER             REASON  PERIOD  LEVEL   TIME LEFT(s)\n");
	for (ac = g_list_first (list); ac != NULL; ac = g_list_next (ac))
	{
		Account *_ac = (Account *) ac->data;

		if (_ac->info.field_restrict != NO_PERIOD)
		{
			//printf( " %-16s %-6s  %-6s   %c     %-4d\n", 
			printf (" %-16s %-6s  %-6s   %c     %d\n", _ac->id,	//name
				read_restrict_reason (_ac),	//reason
				read_restrict_reriod (_ac),	//period
				get_restrict_level (_ac->restricted),	//level
				get_time_to_end (_ac)	//time left
				);
		}
		free (_ac->id);
		free (_ac);
	}
	g_list_free (list);
}

int
list_all (int flag, int non_priv, int raw)
{
	FILE *in = NULL;
	FILE *out = NULL;
	int socket = -1;
	if (opensock (&socket, &in, &out))
	{
		client_type_t ctt = DBCTL;
		fwrite (&ctt, sizeof (client_type_t), 1, out);
		fflush (out);

		DbCtlCommand command = { 0 };
		command.command = LIST;
		strcpy (command.parameter, "");
		strcpy (command.options.username, "");
		command.options.cpu = 0;
		command.options.level = 0;
		command.options.read = 0;
		command.options.write = 0;
		command.options.timeout = 0;
		command.options.user_max_connections = 0;

		fwrite_wrapper (&command, sizeof (DbCtlCommand), 1, out);
		fflush (out);

		print_list (in, flag, non_priv, raw);
		closesock (socket, in, out);
	}
	else
	{
		closesock (socket, in, out);
		return 0;
	}
	return 1;
}

int
list_all_json (int flag)
{
	FILE *in = NULL;
	FILE *out = NULL;
	int socket = -1;
	if (opensock (&socket, &in, &out))
	{
		client_type_t ctt = DBCTL;
		fwrite (&ctt, sizeof (client_type_t), 1, out);
		fflush (out);

		DbCtlCommand command = { 0 };
		command.command = LIST;
		strcpy (command.parameter, "");
		strcpy (command.options.username, "");
		command.options.cpu = 0;
		command.options.level = 0;
		command.options.read = 0;
		command.options.write = 0;
		command.options.timeout = 0;
		command.options.user_max_connections = 0;

		fwrite_wrapper (&command, sizeof (DbCtlCommand), 1, out);
		fflush (out);

		print_json (in, flag);
		closesock (socket, in, out);
	}
	else
	{
		closesock (socket, in, out);
		return 0;
	}
	return 1;
}

int
list_restricted (void)
{
	FILE *in = NULL;
	FILE *out = NULL;
	int _socket = -1;

	if (opensock (&_socket, &in, &out))
	{
		client_type_t ctt = DBCTL;
		fwrite (&ctt, sizeof (client_type_t), 1, out);
		fflush (out);

		DbCtlCommand command;
		command.command = LIST_R;
		strcpy (command.parameter, "");
		strcpy (command.options.username, "");
		command.options.cpu = 0;
		command.options.level = 0;
		command.options.read = 0;
		command.options.write = 0;
		command.options.timeout = 0;
		command.options.user_max_connections = 0;

		fwrite_wrapper (&command, sizeof (DbCtlCommand), 1, out);
		fflush (out);

		print_list_rest (in);
		closesock (_socket, in, out);
	}
	else
	{
		closesock (_socket, in, out);
		return 0;
	}
	return 1;
}

void
list_restricted_shm (void)
{
	int rc = init_bad_users_list_client_without_init ();
	if (rc != 0)
	{
		fprintf(stderr, "ERROR - Cannot get bad users list\n");
	}
	else
	{
		printf_bad_list_cleint_persistent ();
	}
}
