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
#include <string.h>

#include <errno.h>
#include <glib.h>
#include <pthread.h>

#include "governor_config.h"
#include "data.h"
#include "log.h"
#include "calc_stats.h"

#include "dbuser_map.h"

#define MAX_TRY 10
#define DELTA_TIME 300
//#define DELTA_TIME 10

static GHashTable *userMap = NULL;
pthread_rwlock_t map_rw_lock = PTHREAD_RWLOCK_INITIALIZER;

void
trim (char *s)
{
  char d[strlen(s)+1];
  int i, j;
  for (i = j = 0; s[i] != '\0'; i++)
    if (s[i] != ' ' && s[i] != '\n')
      d[j++] = s[i];

  d[j] = '\0';
  strcpy (s, d);
}

time_t
last_modify_map (void)
{
  struct stat sb;

  if (stat (DBUSER_MAP_FILE, &sb) == -1)
    return -1;

  return sb.st_mtime;
}

int
get_map_file (struct governor_config *data_cfg)
{
  FILE *map;
  char buf[1024];
  username_t username, account_name;
  parameter_t uid;
  int len = 0;

  int l = 0;
  if (userMap != NULL)
    g_hash_table_destroy (userMap);
  userMap = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  if ((map = fopen ((char *) DBUSER_MAP_FILE, "r")) == 0)
    return 0;
  while (!feof (map))
    {
      if (fgets (buf, sizeof (buf), map))
	{
	  len = 0;
	  int i = 0, split = 0, split2 = 0;
	  for (l = 0; l < USERNAMEMAXLEN; l++)
	    {
	      username[l] = 0;
	      uid[l] = 0;
	      account_name[l] = 0;
	    }

	  for (i = 0; i < strlen (buf); i++)
	    {
	      if (split == 0)
		{
		  if (buf[i] != ' ') {
                    if(i<(sizeof(username_t)-1)) {
			username[len] = buf[i];
			len++;
		    }
		  } else
		    {
		      username[len] = '\0';
		      split = i;
		      len = 0;
		    }
		}
	      else
		{
		  if (split2 == 0)
		    {
		      if (buf[i] != ' ') {
                        if((i-split-1)<(sizeof(username_t)-1)) {
			    account_name[len] = buf[i];
                            len++;
                        }
		      } else
			{
			  account_name[len] = '\0';
			  split2 = i;
                          len = 0;
			}
		    }
		  else
		    {
		      if (i > split2)
			{
			  if (buf[i] != '\n') {
                            if((i-split2-1)<(sizeof(parameter_t)-1)) {
			        uid[len] = buf[i];
			        len++;
			    }
			  }
			}
		    }
		}
	    }
	  if (len) uid[len]='\0';
	  uid[USERNAMEMAXLEN - 1] = '\0';
	  trim (username);
	  trim (uid);
	  trim (account_name);
	  if (!username[0] || !account_name[0])
	    continue;

	  char *username_key = g_strndup (username, USERNAMEMAXLEN);

	  if (username_key)
	    {
	      UserMap *UserMap_ = NULL;
	      UserMap_
		= (UserMap *) g_hash_table_lookup (userMap, username_key);

	      if (UserMap_ == NULL)
		{
		  UserMap_ = (UserMap *) g_malloc (sizeof (UserMap));

		  for (l = 0; l < USERNAMEMAXLEN; l++)
		    {
		      UserMap_->username[l] = 0;
		      UserMap_->account_name[l] = 0;
		    }
		  UserMap_->uid = 0;

		  strncpy (UserMap_->username, username,
			   sizeof (UserMap_->username) - 1);
		  strncpy (UserMap_->account_name, account_name,
			   sizeof (UserMap_->account_name) - 1);
		  int tmp_uid = data_cfg->separate_lve ? atoi (uid) : BAD_LVE;

		  if (data_cfg->log_mode == DEBUG_MODE)
		    {
		      WRITE_LOG (NULL, 0, "Added user %s account %s with uid %d",
				 data_cfg->log_mode, UserMap_->username,
				 UserMap_->account_name, tmp_uid);
		    }

		  if (tmp_uid >= 1)
		    {
		      UserMap_->uid = tmp_uid;
		      g_hash_table_insert (userMap, username_key, UserMap_);
		    }
		  else
		    {
		      g_free (UserMap_);
		      g_free (username_key);
		    }
		}
	      else
		{
		  g_free (username_key);
		}
	    }
	}
    }
  fclose (map);

  return 1;
}

void
list_uid (gpointer key, UserMap * um, void *data)
{
  add_empty_stats_for_uid (um->username);
}

void
set_dbuser_map (void)
{
  g_hash_table_foreach (userMap, (GHFunc) list_uid, NULL);
}

void *
parse_map_file_every_hour (void *data)
{
  struct governor_config data_cfg;
  time_t last_mod, curr;

  curr = last_modify_map ();
  if (curr == -1)
    {
      time (&curr);
      curr -= DELTA_TIME;
    }
  else
    {
      curr--;
    }
  get_config_data (&data_cfg);
  while (1)
    {
      last_mod = last_modify_map ();
      if (curr < last_mod)
	{
	  if (lock_write_map () == 0)
	    {
	      if (!get_map_file (&data_cfg))
		{
		  WRITE_LOG (NULL, 0, "Failed read dbuser-map file",
			     data_cfg.log_mode);
		}
	      else
		curr = last_mod;
	      unlock_rdwr_map ();
	    }
	  if (lock_read_map () == 0)
	    {
	      set_dbuser_map ();
	      unlock_rdwr_map ();
	    }
	  reinit_users_list ();
	}
      sleep (DELTA_TIME);
    }

  return NULL;
}

gboolean
find_uid (gpointer key, UserMap * um, void *data)
{
  return (strcmp (um->username, (char *) data) == 0);
}

int
get_uid (const username_t u)
{
  UserMap *UserMap_ = NULL;
  if (userMap)
    {
      UserMap_
	= (UserMap *) g_hash_table_find (userMap, (GHRFunc) find_uid, (gpointer)u);
    }

  return UserMap_ ? UserMap_->uid : BAD_LVE;
}

char *
get_account (username_t u)
{
  UserMap *UserMap_ = NULL;
  if (userMap)
    {
      UserMap_
	= (UserMap *) g_hash_table_find (userMap, (GHRFunc) find_uid, u);
    }

  return UserMap_ ? (char *) UserMap_->account_name : NULL;
}

int
lock_read_map (void)
{
  return pthread_rwlock_rdlock (&map_rw_lock);
}

int
lock_write_map (void)
{
  return pthread_rwlock_wrlock (&map_rw_lock);
}

int
unlock_rdwr_map (void)
{
  return pthread_rwlock_unlock (&map_rw_lock);
}
