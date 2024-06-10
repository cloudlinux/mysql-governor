/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include "dbgovernor_string_functions.h"
#include "governor_config.h"
#include "user_account.h"
#include "dbuser_map.h"

static GHashTable *user_account_table;

int check_if_user_restricted(const username_t username, const GHashTable *accounts)
{
	const struct user_account *ua = get_user_account(username);
	const Account *ac = g_hash_table_lookup((GHashTable*)accounts, ua->account);
	return ac->timeout > 0;
}

User_stats *add_user_stats(const username_t username, GHashTable *accounts, GHashTable *users)
{
	struct user_account *ua = get_user_account(username);
	Account *ac = g_hash_table_lookup(accounts, ua->account);
	if (!ac)
	{
		ac = init_account(ua->account);
		g_hash_table_insert(accounts, ua->account, ac);
	}
	User_stats *us = init_user_stats(ua->username, ac);
	g_hash_table_insert(users, (gpointer) ua->username, us);
	g_ptr_array_add(ac->users, us);
	return us;
}

void
init_user_account_table (void)
{
	user_account_table = g_hash_table_new (g_str_hash, g_str_equal);
}

void
free_user_account_table (void)
{
	g_hash_table_foreach (user_account_table, (GHFunc) free, NULL);
	g_hash_table_unref (user_account_table);
}

struct user_account *get_user_account(const username_t username)
{
	struct user_account *ua =
		g_hash_table_lookup (user_account_table, username);
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	if (!ua)
	{
		ua = malloc (sizeof (struct user_account));
		strlcpy (ua->username, username, USERNAMEMAXLEN);
		g_hash_table_insert (user_account_table, ua->username, ua);
		stats_limit_cfg cfg_buf;
		stats_limit_cfg *sl = config_get_account_limit (ua->username, &cfg_buf);
		if (sl->account_flag)
		{
			char *ptr = NULL;
			if (lock_read_map () == 0)
			{
				ptr = get_account(username);
				unlock_rdwr_map ();
			}
			if (ptr == NULL)
			{
				char *ptr = strchr (username, data_cfg.separator);
				if (ptr == NULL || ptr == username)
				{
					strlcpy (ua->account, username, USERNAMEMAXLEN);
				}
				else
				{
					strlcpy (ua->account, username, ptr - username + 1);
				}
			}
			else
			{
				strlcpy (ua->account, ptr, USERNAMEMAXLEN);
			}

		/*if(data_cfg.separator != '*'){
			char *ptr = strchr (username, data_cfg.separator);
			if (ptr == NULL || ptr == username)
			{
			strlcpy (ua->account, username, USERNAMEMAXLEN);
			}
			else
			{
			strlcpy (ua->account, username, ptr - username + 1);
			}
			} else {
			char *ptr = NULL;
			if( lock_read_map() == 0 )
			{
			ptr=get_account(username);
			unlock_rdwr_map();
			}
			if (ptr == NULL)
			{
			strlcpy (ua->account, username, USERNAMEMAXLEN);
			}
			else
			{
			strlcpy (ua->account, ptr, USERNAMEMAXLEN);
			}
			} */
		}
		else
		{
			strlcpy (ua->account, username, USERNAMEMAXLEN);
		}
	}
	return ua;
}
