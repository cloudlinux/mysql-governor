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
void *run_writer (void *data);
void *run_dbctl_command (void *data);
void send_account (const char *key, Account * ac, FILE * out);

void *
run_server (void *data)
{
  int i, s, len;
  struct sockaddr_un saun;
  int ret;
  struct governor_config data_cfg;

  get_config_data (&data_cfg);

  if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
      WRITE_LOG (NULL, 0, "Can't create socket(DBTOP)", data_cfg.log_mode);
      close_log ();
      close_restrict_log ();
      exit (EXIT_FAILURE);
    }

  saun.sun_family = AF_UNIX;
  strcpy (saun.sun_path, SOCK_ADDRESS);

  unlink (SOCK_ADDRESS);
  len = sizeof (saun.sun_family) + strlen (saun.sun_path);

  if (bind (s, (struct sockaddr *) &saun, len) < 0)
    {
      WRITE_LOG (NULL, 0, "Can't server bind(DBTOP)", data_cfg.log_mode);
      close_log ();
      close_restrict_log ();
      close (s);
      exit (EXIT_FAILURE);
    }

  if (listen (s, 3) < 0)
    {
      WRITE_LOG (NULL, 0, "Can't server listen(DBTOP)", data_cfg.log_mode);
      close_log ();
      close_restrict_log ();
      close (s);
      exit (EXIT_FAILURE);
    }
  /* Start daemon accept cycle */
  accept_connections (s);
  close (s);

  return NULL;
}

void *
run_dbtop_command (void *data)
{
  FILE *out;
  intptr_t ns = (intptr_t) data;
  out = fdopen ((int) ns, "w+");
  if (!out)
    {
      //Try to open second time
      out = fdopen ((int) ns, "w+");
      //If null, then cancel command
      if (!out)
	{
	  close (ns);
	  return NULL;
	}
    }
  int new_record = 1, get_response;
  size_t resp = 0;
  resp = fwrite_wrapper (&new_record, sizeof (int), 1, out);
  if (!resp)
    {
      fflush (out);
      fclose (out);
      return NULL;
    }
  resp = fread_wrapper (&get_response, sizeof (int), 1, out);
  if (!resp)
    {
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

void *handle_client_connect(void *fd)
{
  int ns = (int) ((intptr_t) fd), result;
  struct governor_config data_cfg;

  get_config_data (&data_cfg);

  client_type_t ctt;
  result = read (ns, &ctt, sizeof (client_type_t));
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
      WRITE_LOG (NULL, 0, "incorrect connection(DBTOP)", data_cfg.log_mode);

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
  struct governor_config data_cfg;

  get_config_data (&data_cfg);

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
	      WRITE_LOG (NULL, 0, "Can't server accept(DBTOP)", data_cfg.log_mode);
	      close_log ();
	      close_restrict_log ();
	      exit (EXIT_FAILURE);
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
  time_t last_renew = 0;
  flag_need_to_renew_dbmap = 0;
  struct governor_config data_cfg;
  get_config_data (&data_cfg);

  while (1)
    {
	  if (flag_need_to_renew_dbmap){
		  time_t current_check = time(NULL);
		  if ((last_renew+DBMAPHOOK_ANTIDDOS)<current_check){
		  		 flag_need_to_renew_dbmap = 0;
		  		 last_renew = current_check;
		  		 pid_t renew_pid = fork ();
 	 		     if (renew_pid < 0)
 	 		 	{
 	 		 	  WRITE_LOG (NULL, 0, "(%d)Fork error (renew dbmap). Path %s", data_cfg.log_mode,
 	 		 		     errno, "dbupdate");
 	 		 	}
 	 		       else
 	 		 	{
 	 		 	  if (!renew_pid)
 	 		 	    {
 	 		 	      execl ("/usr/share/lve/dbgovernor/mysqlgovernor.py",
 	 		 	    		  "/usr/share/lve/dbgovernor/mysqlgovernor.py", "--dbupdate", NULL);
 	 		 	      WRITE_LOG (NULL, 0, "(%d)Exec error (renew dbmap). Path %s",
 	 		 			 data_cfg.log_mode, errno, "dbupdate");
 	 		 	      exit (0);
 	 		 	    }
 	 		 	}
		  	}
	  }
	  sleep(DBMAPHOOK_RECHECK);
    }

  return NULL;
}

void *
run_dbctl_command (void *data)
{
  int result;
  intptr_t ns = (intptr_t) data;

  DbCtlCommand command;
  result = read (ns, &command, sizeof (DbCtlCommand));

  struct governor_config data_cfg;
  get_config_data (&data_cfg);

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
	  lock_acc ();
	  g_hash_table_foreach ((GHashTable *) get_accounts (),
				(GHFunc) dbctl_restrict_set, &command);
	  unlock_acc ();
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

  close (ns);

  return NULL;
}

void *
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
