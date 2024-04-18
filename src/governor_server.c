/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

#include "data.h"

#include "governor_server.h"
#include "log.h"
#include "governor_config.h"
#include "tid_table.h"
#include "parce_proc_fs.h"
#include "calc_stats.h"
#include "tick_generator.h"
#include "commands.h"

#define SEC2NANO 1000000000

int break_thread = 0;
int global_socket = 0;
struct pollfd *fds = NULL;
nfds_t nfds;

void
cleanup (int shut, int s, int howmany)
{
  /*
   * Shutdown and close sock1 completely.
   */
  if (shut)
    {
      shutdown (s, howmany);
    }
  close (s);
}				/* end cleanup */

void
sighandler (int sig)
{
  if (sig == SIGINT)
    {
      cleanup (0, global_socket, 1);
      exit (EXIT_SUCCESS);
    }
}

static void
declsighandler (void)
{
  struct sigaction action;

  sigemptyset (&action.sa_mask);
  sigaddset (&action.sa_mask, SIGINT);
  action.sa_flags = 0;
  action.sa_handler = sighandler;
  sigaction (SIGINT, &action, NULL);
}

void
create_socket (void)
{
  int i, s, len;
  struct sockaddr_un saun;
  int ret;
  int opt = 1;
  struct governor_config data_cfg;

  get_config_data (&data_cfg);


  if ((global_socket = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
      WRITE_LOG (NULL, 0, "Can't create socket", data_cfg.log_mode);
      close_log ();
      close_restrict_log ();
      exit (EXIT_FAILURE);
    }

  if (setsockopt (global_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt)
      < 0)
    {
      WRITE_LOG (NULL, 0, "Can't change socket options", data_cfg.log_mode);
      close_log ();
      close_restrict_log ();
      exit (EXIT_FAILURE);
    }

  saun.sun_family = AF_UNIX;
  strcpy (saun.sun_path, MYSQL_SOCK_ADDRESS);

  unlink (MYSQL_SOCK_ADDRESS);
  len = sizeof (saun.sun_family) + strlen (saun.sun_path);

  if (bind (global_socket, (struct sockaddr *) &saun, len) < 0)
    {
      WRITE_LOG (NULL, 0, "Can't bind to socket address %s", data_cfg.log_mode,
		 SOCK_ADDRESS);
      close_log ();
      close_restrict_log ();
      exit (EXIT_FAILURE);
    }

  if (listen (global_socket, 32) < 0)
    {
      WRITE_LOG (NULL, 0, "Can't listen on socket", data_cfg.log_mode);
      close_log ();
      close_restrict_log ();
      exit (EXIT_FAILURE);
    }

  declsighandler ();
}

int
get_soket (void)
{
  return global_socket;
}

ssize_t
recv_wrapper (int __fd, void *__buf, size_t __n, int __flags)
{
  int retval, trys = 0;
  while (1)
    {
      retval = recv (__fd, __buf, __n, __flags);
      if (retval < 0)
	{
	  if (errno != EWOULDBLOCK)
	    {
	      break;
	    }
	  trys++;
	  if (trys == 100)
	    {
	      break;
	    }
	}
      else
	{
	  break;
	}
    }
  return retval;
}

void *
proceed_data_every_second (void *data)
{
  char buffer[_DBGOVERNOR_BUFFER_2048];
  double old_tm = 0.0, new_tm = 0.0;
  struct timespec cur_tm;
  struct governor_config data_cfg;

  while (1)
    {
      sleep (1);

      //Check all table of tids
      monitor_data_from_client (NULL);

      clock_gettime (CLOCK_REALTIME, &cur_tm);
      new_tm = cur_tm.tv_sec + (double) cur_tm.tv_nsec / (double) SEC2NANO;
      if (old_tm == 0.0)
	old_tm = new_tm;

      //Calculate average and all exists non proceeded accounts
      if (new_tm - old_tm >= 1.0)
	{
	  proceed_accounts (new_tm);
	  old_tm = new_tm;
	}

      //Send commands to DB MySQL
      send_commands_cycle ();

      //Print statistics to restrict log
      get_config_data (&data_cfg);
      if (data_cfg.restrict_format >= 4)
	{
	  print_to_restrict_log_stats (NULL);
	}
    }
  return NULL;
}

void
term_handler (int i)
{
  break_thread++;
}

void *
get_data_from_client (void *data)
{
  int ret;
  int timeout = 1000;
  struct sockaddr_un fsaun;
  struct timespec cur_tm;
  double old_tm = 0.0, new_tm = 0.0;
  int fromlen = sizeof (fsaun);
  nfds = 1;
  fds = (struct pollfd *) calloc (1, nfds * sizeof (struct pollfd));
  fds->fd = get_soket ();
  fds->events = POLLIN;
  reinit_command_list ();

  struct governor_config data_cfg;

  struct sigaction sa = { 0 };
  sigset_t newset;
  sigemptyset (&newset);
  sigaddset (&newset, SIGHUP);
  sigprocmask (SIG_BLOCK, &newset, 0);
  sa.sa_handler = term_handler;
  sigaction (SIGTERM, &sa, 0);
  sigaction (SIGKILL, &sa, 0);
  int sync = 1;

  for (;;)
    {

      if (break_thread)
	{
	  return NULL;
	}

      get_config_data (&data_cfg);

      int i;
#ifdef TEST
      //print_tid_data();
#endif
      //Wait max 1 second
      ret = poll (fds, nfds, timeout);
#ifdef TEST
      //printf("Get count of events %d\n", ret);
#endif
      if (ret == -1)
	{
	  //Try to recreate socket
	  WRITE_LOG (NULL, 0, "Error on polling socket. Recreating socket",
		     data_cfg.log_mode);
	  for (i = 0; (i < nfds) && (ret); i++)
	    {
	      cleanup (0, (fds + i)->fd, 1);
	    }
	  create_socket ();

	  nfds = 1;
	  struct pollfd *fds_tmp = NULL;
	  fds_tmp =
	    (struct pollfd *) realloc (fds, nfds * sizeof (struct pollfd));
	  if (fds_tmp)
	    {
	      fds = fds_tmp;
	    }
	  fds->fd = get_soket ();
	  fds->events = POLLIN;
	}
      for (i = 0; (i < nfds) && (ret); i++)
	{
#ifdef TEST
	  //printf("Check index %d revents %d nfds %d\n", i, (fds + i)->revents, nfds);
#endif
	  if (!(fds + i)->revents)
	    continue;
	  ret--;

	  if (((fds + i)->fd == get_soket ())
	      && ((fds + i)->revents & POLLIN))
	    {
	      /*
	       * Accept connection from socket:
	       * accepted connection will be on socket (fds+nfds)->fd.
	       */
	      struct pollfd *fds_tmp = NULL;
	      fds_tmp = (struct pollfd *) realloc (fds,
						   (nfds +
						    1) *
						   sizeof (struct pollfd));
	      if (fds_tmp)
		{
		  fds = fds_tmp;
		}

	      (fds + nfds)->fd = accept (global_socket,
					 (struct sockaddr *) &fsaun,
					 &fromlen);
#ifdef TEST
	      //printf("Get accept descriptor %d\n", i, (fds + nfds)->fd);
#endif
	      if ((fds + nfds)->fd == -1)
		{
		  WRITE_LOG (NULL, 0, "Error on polling socket. Accepting error",
			     data_cfg.log_mode);
		  cleanup (0, (fds + nfds)->fd, 1);
		  fds_tmp = (struct pollfd *) realloc (fds,
						       nfds *
						       sizeof (struct
							       pollfd));
		  if (fds_tmp)
		    {
		      fds = fds_tmp;
		    }
		  continue;
		}
	      (fds + nfds)->events = POLLIN;
#ifdef _GNU_SOURCE
	      (fds + nfds)->events |= POLLRDHUP;
#endif
	      nfds++;
	      continue;
	    }

	  //Descriptor is not open. Just remove it from array
	  if ((fds + i)->revents & POLLNVAL)
	    {
#ifdef TEST
	      //printf("Empty descriptor %d\n", (fds + i)->fd);
#endif
	      remove_tid_data_by_fd ((fds + i)->fd);
	      nfds--;
	      memcpy (fds + i, fds + i + 1,
		      (nfds - i) * sizeof (struct pollfd));
	      struct pollfd *fds_tmp = NULL;
	      fds_tmp = (struct pollfd *) realloc (fds,
						   nfds *
						   sizeof (struct pollfd));
	      if (fds_tmp)
		{
		  fds = fds_tmp;
		}
	      continue;
	    }
	  //Disconnect
	  if ((fds + i)->revents & POLLHUP)
	    {
#ifdef TEST
	      //printf("Disconnected descriptor %d\n", (fds + i)->fd);
#endif
	      remove_tid_data_by_fd ((fds + i)->fd);
	      cleanup (0, (fds + i)->fd, 2);
	      nfds--;
	      memcpy (fds + i, fds + i + 1,
		      (nfds - i) * sizeof (struct pollfd));
	      struct pollfd *fds_tmp = NULL;
	      fds_tmp = (struct pollfd *) realloc (fds,
						   nfds *
						   sizeof (struct pollfd));
	      if (fds_tmp)
		{
		  fds = fds_tmp;
		}
	      continue;
	    }
#ifdef _GNU_SOURCE
	  if ((fds + i)->revents & POLLRDHUP)
	    {
	      remove_tid_data_by_fd ((fds + i)->fd);
	      cleanup (1, (fds + i)->fd, 2);
	      nfds--;
	      memcpy (fds + i, fds + i + 1,
		      (nfds - i) * sizeof (struct pollfd));
	      struct pollfd *fds_tmp = NULL;
	      fds_tmp =
		(struct pollfd *) realloc (fds,
					   nfds * sizeof (struct pollfd));
	      if (fds_tmp)
		{
		  fds = fds_tmp;
		}
	      continue;
	    }
#endif
	  //Socket error
	  if ((fds + i)->revents & POLLERR)
	    {
#ifdef TEST
	      //printf("Error descriptor %d\n", (fds + i)->fd);
#endif
	      remove_tid_data_by_fd ((fds + i)->fd);
	      WRITE_LOG (NULL, 0, "Error on polling socket. Error %d",
			 data_cfg.log_mode, errno);
	      cleanup (0, (fds + i)->fd, 2);
	      nfds--;
	      memcpy (fds + i, fds + i + 1,
		      (nfds - i) * sizeof (struct pollfd));
	      struct pollfd *fds_tmp = NULL;
	      fds_tmp = (struct pollfd *) realloc (fds,
						   nfds *
						   sizeof (struct pollfd));
	      if (fds_tmp)
		{
		  fds = fds_tmp;
		}
	      continue;
	    }

	  //Should read info?
	  if ((fds + i)->revents & POLLIN)
	    {
#ifdef TEST
	      //printf("Read descriptor %d\n", (fds + i)->fd);
#endif
	      client_data message;
	      //TODO check this code twice
	      int retval, retval_fcntl;
	      retval_fcntl = fcntl ((fds + i)->fd, F_SETFL,
				    fcntl ((fds + i)->fd,
					   F_GETFL) | O_NONBLOCK);
	      //retval = recv((fds + i)->fd, &message, sizeof(message), 0);
	      retval =
		recv_wrapper ((fds + i)->fd, &message, sizeof (message), 0);
	      if (retval <= 0 || retval_fcntl < 0)
		{
		  remove_tid_data_by_fd ((fds + i)->fd);
		  if (retval == 0)
		    {
#ifdef TEST
		      //printf("Disconnect on read descriptor %d\n", (fds + i)->fd);
#endif
		      /* Disconnect */
		      cleanup (1, (fds + i)->fd, 2);
		    }
		  else
		    {
		      WRITE_LOG (NULL, 0, "Error on polling socket. Read %d",
				 data_cfg.log_mode, errno);
		      cleanup (0, (fds + i)->fd, 1);
		    }
		  nfds--;
		  memcpy (fds + i, fds + i + 1,
			  (nfds - i) * sizeof (struct pollfd));
		  struct pollfd *fds_tmp = NULL;
		  fds_tmp = (struct pollfd *) realloc (fds,
						       nfds *
						       sizeof (struct
							       pollfd));
		  if (fds_tmp)
		    {
		      fds = fds_tmp;
		    }
		  continue;
		}
	      else if (message.magic != CD_MAGIC)
		{
	      if (sync)
	        WRITE_LOG (NULL, 0, "Governor library version mismatch detected - stat processing stopped. Try to restart mysqld service", data_cfg.log_mode);
	      sync = 0;
		}
	      else if (message.magic == CD_MAGIC)
		{
	      if (!sync)
	        WRITE_LOG (NULL, 0, "Governor library version mismatch fixed - stat processing restored", data_cfg.log_mode);
	      sync = 1;
		  if (data_cfg.restrict_format >= 4)
		    {
		      WRITE_LOG (NULL,
				 1,
				 "Received info descriptor %d TYPE %d, WATCH TID %d, USER NAME %s, CPU %ld, WRITE %ld, READ %ld",
				 data_cfg.log_mode,
				 (fds + i)->fd, message.type, message.tid,
				 message.username, message.cpu, message.write,
				 message.read);
		    }
#ifdef TEST
		  //printf("Get cpu %ld, tid %d, tm %f, type %d\n", message.cpu, message.tid, (double)message.update_time + (double)message.naoseconds /(double) SEC2NANO, message.type);
#endif
		  if (message.type == 0)
		    {
		    if (!data_cfg.improved_accuracy)
		    {
		      tid_table tbl_buff;
		      memset (&tbl_buff, 0, sizeof (tid_table));
		      tid_table *tbl = get_tid_data (message.tid, &tbl_buff);
		      //This tid use another user. This strange
		      /*if ((tbl != NULL)
		         && (!strncmp(tbl_buff.username, message.username,
		         USERNAMEMAXLEN))) {
		         if (data_cfg.log_mode == DEBUG_MODE)
		         WRITE_LOG(NULL, 0,
		         "Lost TID user info. User name %s",
		         data_cfg.log_mode, tbl->username);
		         } */
		      add_new_tid_data (&message, (fds + i)->fd);
		    }
		    else
		      add_new_begin_tid_data (&message, (fds + i)->fd);
		    }
		  else
		    {
		    if (!data_cfg.improved_accuracy)
		    {
		      tid_table tbl_buff;
		      memset (&tbl_buff, 0, sizeof (tid_table));
		      tid_table *tbl = get_tid_data (message.tid, &tbl_buff);
		      if (tbl)
			{
			  //Stats st;
			  clac_stats_difference_add_to_counters (&message,
								 &tbl_buff);
			  //add_new_stats(tbl->username, &st, get_current_tick());
			  remove_tid_data (message.tid);
			}
		    }
		    else
		      add_new_end_tid_data (&message);
		    }
		}
	      continue;
	    }

	}

    }
  return NULL;
}

void
chek_user_perf (gpointer key, tid_table * item, gpointer user_data)
{
  if (!item)
    return;
  pid_t kkey = GPOINTER_TO_INT (key);
  double old_tm = item->update_time
    + (double) item->naoseconds / (double) SEC2NANO;
  struct timespec cur_tm;
  cur_tm.tv_sec = ((struct timespec *) user_data)->tv_sec;
  cur_tm.tv_nsec = ((struct timespec *) user_data)->tv_nsec;
  double new_tm = cur_tm.tv_sec + (double) cur_tm.tv_nsec / (double) SEC2NANO;
  struct governor_config data_cfg;

  get_config_data (&data_cfg);

  if (data_cfg.restrict_format >= 4)
    {
      WRITE_LOG (NULL,
		 1,
		 "Watch info for WATCH TID %d, USER NAME %s, CPU %ld, WRITE %ld, READ %ld Time %f",
		 data_cfg.log_mode,
		 kkey, item->username, item->cpu, item->write, item->read,
		 old_tm);
    }

  if (data_cfg.improved_accuracy)
  {
	  //thread have end info
	  if (item->type == 1)
	  {
		  double cpu = item->cpu_end;
		  //use rusage
		  if ((-1 != item->stime_begin.tv_sec) && (-1 != item->utime_begin.tv_sec))
		  {
			  cpu = calc_cpu_from_rusage(item);
			  item->cpu = 0;
		  }
		  clac_stats_difference_inner_add_to_counters (cpu, item->read_end, item->write_end, item);

		  //remove tid from threads list
		  add_tid_to_bad_list (kkey);
		  return;
	  }
  }

  if (data_cfg.improved_accuracy || (new_tm - old_tm) > 1.0)
    {
      dbgov_proc_time item1;
      dbgov_iostat item2;

      if ((get_proc_time (&item1, item->pid, kkey) == -2)
	  || (get_io_stat (&item2, item->pid, kkey) == -2))
	{
	  add_tid_to_bad_list (kkey);
	  return;
	}

      if (data_cfg.restrict_format >= 4)
	{
	  WRITE_LOG (NULL,
		     1,
		     "Proceed info for WATCH TID %d, USER NAME %s, CPU %ld, WRITE %ld, READ %ld Time %f---> NEW CPU %f, WRITE %ld, READ %ld Cur_tm %f",
		     data_cfg.log_mode,
		     kkey, item->username, item->cpu, item->write, item->read,
		     old_tm, item1.utime + item1.stime, item2.write_bytes,
		     item2.read_bytes, new_tm);
	}
#ifdef TEST
      //      struct timespec cur_tm11;
      //      clock_gettime(CLOCK_REALTIME, &cur_tm11);
      //double new_tm = cur_tm11.tv_sec
      //    + (double) cur_tm11.tv_nsec / (double) SEC2NANO;
      //printf("Get cpu1 %ld, tid %d, tm %f\n", item1.utime + item1.stime, kkey, new_tm);
#endif

      clac_stats_difference_inner_add_to_counters (item1.utime + item1.stime,
						   item2.read_bytes,
						   item2.write_bytes, item);
      //add_new_stats(item->username, &st, get_current_tick());
      //coverity[missing_lock]
      item->cpu = item1.utime + item1.stime;
      //coverity[missing_lock]
      item->read = item2.read_bytes;
      //coverity[missing_lock]
      item->write = item2.write_bytes;
      //coverity[missing_lock]
      item->update_time = cur_tm.tv_sec;
      //coverity[missing_lock]
      item->naoseconds = cur_tm.tv_nsec;
      //mark begin info as invalid
      item->utime_begin.tv_sec = -1;
      item->stime_begin.tv_sec = -1;


      //add_new_tid_data2(*kkey, item);

    }
}

void
monitor_data_from_client (void *data)
{
  struct governor_config data_cfg;

  get_config_data (&data_cfg);
  if (data_cfg.restrict_format >= 4)
    {
      WRITE_LOG (NULL, 1, "TID Table size %ld", data_cfg.log_mode, get_tid_size ());
    }
  struct timespec cur_tm;
  clock_gettime (CLOCK_REALTIME, &cur_tm);
  struct timespec *tm = malloc (sizeof (struct timespec));
  if (tm)
    {
      tm->tv_sec = cur_tm.tv_sec;
      tm->tv_nsec = cur_tm.tv_nsec;
      proceed_tid_data ((GHFunc) chek_user_perf, (gpointer) tm);
    }
  free (tm);
}
