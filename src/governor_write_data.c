/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#undef pthread_mutex_t
#undef pthread_mutex_lock
#undef pthread_mutex_unlock

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <linux/unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>

#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <sys/resource.h>
#include <inttypes.h>
#include <search.h>

#include "data.h"

#include "governor_write_data.h"
#include "parce_proc_fs.h"
#include "dbgovernor_string_functions.h"
#include "shared_memory.h"

#define SEC2NANO 1000000000

pthread_mutex_t mtx_write = PTHREAD_MUTEX_INITIALIZER;

typedef struct _sock_data
{
  int socket;
  int status;
} sock_data;
sock_data sd = { -1, 0 };

static int
try_lock2 (pthread_mutex_t * mtx)
{
  int trys = 0, rc = 0;
  while (trys < 10)
    {
      rc = pthread_mutex_trylock (mtx);
      if (rc == 0)
	return 0;
      if (rc == EBUSY)
	trys++;
      else
	return -1;
    }
  return -1;
}

static int
try_lock (pthread_mutex_t * mtx)
{
  int rc = pthread_mutex_trylock (mtx);

  switch (rc)
    {
    case 0:
      break;
    case EBUSY:
      {
	struct timespec tim;

	clock_gettime (CLOCK_REALTIME, &tim);
	tim.tv_nsec += (double) 0.05 *(double) SEC2NANO;

	rc = pthread_mutex_timedlock (mtx, &tim);
	if (rc)
	  return -1;
      }
      break;
    case EINVAL:
    default:
      rc = -1;
      break;
    }

  return rc;
}

static int close_sock_in ();

static int
connection_with_timeout_poll (int sk, struct sockaddr_un *sa, socklen_t len,
			      int timeout)
{
  int flags = 0, error = 0, ret = 0, error_len =
    sizeof (error), current_size = 0, index = 0;
  int nfds = 1;
  int ts;

  ts = timeout * 1000;
  struct pollfd fds[1];

  memset (fds, 0, sizeof (fds));

  fds[0].fd = sk;
  fds[0].events = POLLOUT;

  if ((flags = fcntl (sk, F_GETFL, 0)) < 0)
    return -1;

  if (fcntl (sk, F_SETFL, flags | O_NONBLOCK) < 0)
    return -1;


  if ((ret = connect (sk, (struct sockaddr *) sa, len)) < 0)
    if ((errno != EINPROGRESS) && (errno != EINTR))
      return -1;

  int is_eintr = 0;
  do
    {
      if ((ret = poll (fds, nfds, ts)) < 0)
	{
	  if (errno != EINTR)
	    {
	      close (sk);
	      return -1;
	    }
	  is_eintr = 1;
	}
      else
	{
	  is_eintr = 0;
	}
    }
  while (is_eintr);
  if (ret == 0)
    {
      close (sk);
      errno = ETIMEDOUT;
      return -1;
    }
  else if (fds[0].revents & POLLNVAL)
    {
      close (sk);
      return -1;
    }
  else if (fds[0].revents & POLLHUP)
    {
      close (sk);
      return -1;
    }
  else
#ifdef _GNU_SOURCE
  if (fds[0].revents & POLLHUP)
    {
      close (sk);
      return -1;
    }
  else
#endif
  if (fds[0].revents & POLLERR)
    {
      close (sk);
      return -1;
    }

  if (getsockopt (sk, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
    {
      close (sk);
      return -1;
    }
  if (error)
    {
      close (sk);
      errno = error;
      return -1;
    }


  /*if(fcntl(sk, F_SETFL, flags) < 0) {
     close(sk);
     return -1;
     } */

  return 0;
}

static int
connection_with_timeout_select (int sk, struct sockaddr_un *sa, socklen_t len,
				int timeout)
{
  int flags = 0, error = 0, ret = 0, error_len = sizeof (error);
  fd_set read_set, write_set;
  struct timeval ts;

  ts.tv_sec = timeout;
  ts.tv_usec = 0;

  FD_ZERO (&read_set);
  FD_SET (sk, &read_set);
  write_set = read_set;

  if ((flags = fcntl (sk, F_GETFL, 0)) < 0)
    return -1;

  if (fcntl (sk, F_SETFL, flags | O_NONBLOCK) < 0)
    return -1;

  if ((ret = connect (sk, (struct sockaddr *) sa, len)) < 0)
    if (errno != EINPROGRESS)
      return -1;

  if (ret != 0)
    {
      if ((ret = select (sk + 1, &read_set, &write_set, NULL, &ts)) < 0)
	{
	  close (sk);
	  return -1;
	}
      if (ret == 0)
	{
	  close (sk);
	  errno = ETIMEDOUT;
	  return -1;
	}

      if (FD_ISSET (sk, &read_set) || FD_ISSET (sk, &write_set))
	{
	  if (getsockopt (sk, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
	    {
	      close (sk);
	      return -1;
	    }
	}
      else
	{
	  close (sk);
	  return -1;
	}

      if (error)
	{
	  close (sk);
	  errno = error;
	  return -1;
	}
    }

  /*if(fcntl(sk, F_SETFL, flags) < 0) {
     close(sk);
     return -1;
     } */

  return 0;
}

static int
connect_to_server_in ()
{
  int s, len;
  struct sockaddr_un saun;
  sd.socket = -1;
  sd.status = 0;

  if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
      return -1;
    }

  saun.sun_family = AF_UNIX;
  strncpy (saun.sun_path, MYSQL_SOCK_ADDRESS, sizeof (saun.sun_path) - 1);

  len = sizeof (struct sockaddr_un);

  if (connection_with_timeout_poll (s, &saun, len, 5) < 0)
    {
      return -2;
    }
  /*int rt_code;
     rt_code = fcntl(s, F_GETFL, 0);
     fcntl(s, F_SETFL, rt_code | O_NONBLOCK); */

  sd.socket = s;
  sd.status = 1;
  return 0;
}

static int not_first_connect = 0;

int
connect_to_server ()
{
  int ret = 0;
  pthread_mutex_lock (&mtx_write);
  ret = connect_to_server_in ();
  pthread_mutex_unlock (&mtx_write);
  if (!ret) return ret;

  // special processing for the first unsuccesful connect
  if (not_first_connect)
  {
    return ret;
  } else
  {
    not_first_connect = 1;
    return 0;
  }
}

int
connect_to_server_ex ()
{
  int ret = 0;
  pthread_mutex_lock (&mtx_write);
  ret = connect_to_server_in ();
  pthread_mutex_unlock (&mtx_write);
  if (!ret) return ret;

  // special processing for the first unsuccesful connect
  if (not_first_connect)
  {
    return ret;
  } else
  {
    not_first_connect = 1;
    return 1;
  }
}

int
send_info (char *username, int type)
{

  if (sd.socket < 0)
    return 0;
  pid_t current_pid = getpid ();
  pid_t current_tid = gettid_p ();

  dbgov_proc_time item1;
  dbgov_iostat item2;

  get_proc_time (&item1, current_pid, current_tid);
  get_io_stat (&item2, current_pid, current_tid);
  struct rusage usage;
  if (-1 == getrusage(RUSAGE_THREAD, &usage))
    memset(&usage, 0, sizeof(usage));

#ifdef TEST
  //printf("Prepare info PID %d TID %d CPU %lld R+W %lld\n", current_pid, current_tid, item1.stime + item1.utime, item2.read_bytes+item2.write_bytes);
#endif
  struct timespec tim;

  clock_gettime (CLOCK_REALTIME, &tim);

  client_data snd;
  snd.magic = CD_MAGIC;
  snd.type = type;
  strlcpy (snd.username, username, sizeof (snd.username));
  snd.pid = current_pid;
  snd.tid = current_tid;
  snd.read = item2.read_bytes;
  snd.write = item2.write_bytes;
  snd.cpu = item1.stime + item1.utime;
  snd.update_time = tim.tv_sec;
  snd.naoseconds = tim.tv_nsec;
  snd.utime = usage.ru_utime;
  snd.stime = usage.ru_stime;

  if (try_lock (&mtx_write))
    return -1;
  /*if (!sd.status) {
     close(sd.socket);
     if (connect_to_server_in() < 0) {
     pthread_mutex_unlock(&mtx_write);
     return -1;
     }
     } */
  //pthread_mutex_unlock(&mtx_write);

  //if (try_lock(&mtx_write)) return -1;
  if (send (sd.socket, &snd, sizeof (client_data), 0) != sizeof (client_data))
    {
      //close_sock_in();
      pthread_mutex_unlock (&mtx_write);
      return -1;
    }
  pthread_mutex_unlock (&mtx_write);

  return 0;

}

int
send_info_begin (char *username)
{
#ifdef TEST
  //printf("Send begin info %s, %d, %d\n", username, sd.socket, sd.status);
#endif
  return send_info (username, 0);
}

int
send_info_end (char *username)
{
#ifdef TEST
  //printf("Send end info %s, %d, %d\n", username, sd.socket, sd.status);
#endif
  return send_info (username, 1);
}

static int
close_sock_in ()
{
  if (sd.status)
    {
      close (sd.socket);
      sd.status = 0;
    }
  return 0;
}

int
close_sock ()
{
  int rc = 0;
  pthread_mutex_lock (&mtx_write);
  rc = close_sock_in ();
  pthread_mutex_unlock (&mtx_write);
  return rc;
}

typedef int (*pthread_mutex_func_t)(pthread_mutex_t *);

pthread_mutex_func_t orig_pthread_mutex_lock_ptr = NULL;
pthread_mutex_func_t orig_pthread_mutex_trylock_ptr = NULL;
pthread_mutex_func_t orig_pthread_mutex_unlock_ptr = NULL;

static int void_pthread_mutex_func(pthread_mutex_t *mutex)
{
	(void)mutex;
	return 0;
}

void init_libgovernor(void)
{
	if (!orig_pthread_mutex_lock_ptr && !orig_pthread_mutex_trylock_ptr && !orig_pthread_mutex_unlock_ptr) {

		pthread_mutex_func_t orig_lock_ptr = NULL;
		pthread_mutex_func_t orig_trylock_ptr = NULL;
		pthread_mutex_func_t orig_unlock_ptr = NULL;

		orig_pthread_mutex_lock_ptr = void_pthread_mutex_func;
		orig_pthread_mutex_trylock_ptr = void_pthread_mutex_func;
		orig_pthread_mutex_unlock_ptr = void_pthread_mutex_func;

		orig_lock_ptr = (pthread_mutex_func_t)(intptr_t)dlsym(RTLD_NEXT, "pthread_mutex_lock");
		orig_trylock_ptr = (pthread_mutex_func_t)(intptr_t)dlsym(RTLD_NEXT, "pthread_mutex_trylock");
		orig_unlock_ptr = (pthread_mutex_func_t)(intptr_t)dlsym(RTLD_NEXT, "pthread_mutex_unlock");

		if (!orig_lock_ptr || !orig_trylock_ptr || !orig_unlock_ptr) {

			fprintf(stderr, "%s dlerror:%s\n", __func__, dlerror());
			abort();
		}

		orig_pthread_mutex_lock_ptr = orig_lock_ptr;
		orig_pthread_mutex_trylock_ptr = orig_trylock_ptr;
		orig_pthread_mutex_unlock_ptr = orig_unlock_ptr;
	}
}

static int orig_pthread_mutex_lock(pthread_mutex_t *mutex)
{
	if (orig_pthread_mutex_lock_ptr == NULL)
		init_libgovernor();

	if (orig_pthread_mutex_lock_ptr == NULL) {

		fprintf(stderr, "%s(%p) mutex:%p\n", __func__, orig_pthread_mutex_lock_ptr, (void *)mutex);
		return EINVAL;
	}
	else
		return (*orig_pthread_mutex_lock_ptr)(mutex);
}

static int orig_pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	if (orig_pthread_mutex_trylock_ptr == NULL)
		init_libgovernor();

	if (orig_pthread_mutex_trylock_ptr == NULL) {

		fprintf(stderr, "%s(%p) mutex:%p\n", __func__, orig_pthread_mutex_trylock_ptr, (void *)mutex);
		return EINVAL;
	}
	else
		return (*orig_pthread_mutex_trylock_ptr)(mutex);
}

static int orig_pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	if (orig_pthread_mutex_unlock_ptr == NULL)
		init_libgovernor();

	if (orig_pthread_mutex_unlock_ptr == NULL) {

		fprintf(stderr, "%s(%p) mutex:%p\n", __func__, orig_pthread_mutex_unlock_ptr, (void *)mutex);
		return EINVAL;
	}
	else
		return (*orig_pthread_mutex_unlock_ptr)(mutex);
}

static unsigned int lock_cnt = 0;
static unsigned int unlock_cnt = 0;
static unsigned int trylock_cnt = 0;

void fini_libgovernor(void)
{
}

static void *lve_library_handle = NULL;
static void *lve = NULL;

void *(*init_lve) (void *, void *) = NULL;
int (*destroy_lve) (void *) = NULL;
int (*lve_enter_flags) (void *, uint32_t, uint32_t *, int) = NULL;
int (*lve_exit) (void *, uint32_t *) = NULL;
int (*is_in_lve) (void *) = NULL;

void governor_init_message_log(void);

int governor_load_lve_library ()
{
	lve_library_handle = NULL;

	governor_init_message_log();
	char *error_dl = NULL;
	lve_library_handle = dlopen ("liblve.so.0", RTLD_LAZY);
	if (!lve_library_handle)
	{
		print_message_log("%s: dlopen(liblve.so.0) failed; errno %d", __FUNCTION__, errno);
	}

	if (!lve_library_handle)
		return 0;

	while (1)
	{
		init_lve = (void *(*)(void *, void *)) dlsym(lve_library_handle, "init_lve");
		if ((error_dl = dlerror ()) != NULL)
		{
			print_message_log("%s: ERROR dlerror after dlsym(init_lve) ret (%s); init_lve(%p) errno %d", __FUNCTION__, error_dl, init_lve, errno);
			init_lve = NULL;
			destroy_lve = NULL;
			lve_enter_flags = NULL;
			lve_exit = NULL;
			is_in_lve = NULL;
			break;
		}

		destroy_lve = (int (*)(void *)) dlsym(lve_library_handle, "destroy_lve");
		if ((error_dl = dlerror ()) != NULL)
		{
			print_message_log("%s: ERROR dlerror after dlsym(destroy_lve) ret (%s); destroy_lve(%p) errno %d", __FUNCTION__, error_dl, destroy_lve, errno);
			init_lve = NULL;
			destroy_lve = NULL;
			lve_enter_flags = NULL;
			lve_exit = NULL;
			is_in_lve = NULL;
			break;
		}

		lve_enter_flags = (int (*)(void *, uint32_t, uint32_t *, int)) dlsym(lve_library_handle, "lve_enter_flags");
		if ((error_dl = dlerror ()) != NULL)
		{
			print_message_log("%s: ERROR dlerror after dlsym(lve_enter_flags) ret (%s); lve_enter_flags(%p) errno %d", __FUNCTION__, error_dl, lve_enter_flags, errno);
			init_lve = NULL;
			destroy_lve = NULL;
			lve_enter_flags = NULL;
			lve_exit = NULL;
			is_in_lve = NULL;
			break;
		}

		lve_exit = (int (*)(void *, uint32_t *)) dlsym(lve_library_handle, "lve_exit");
		if ((error_dl = dlerror ()) != NULL)
		{
			print_message_log("%s: ERROR dlerror after dlsym(lve_exit) ret (%s); lve_exit(%p) errno %d", __FUNCTION__, error_dl, lve_exit, errno);
			init_lve = NULL;
			destroy_lve = NULL;
			lve_enter_flags = NULL;
			lve_exit = NULL;
			is_in_lve = NULL;
			break;
		}

		is_in_lve = (int (*)(void *)) dlsym(lve_library_handle, "is_in_lve");
		if ((error_dl = dlerror ()) != NULL)
		{
			print_message_log("%s: WARN dlerror after dlsym(is_in_lve) ret (%s); is_in_lve(%p) errno %d", __FUNCTION__, error_dl, is_in_lve, errno);
			is_in_lve = NULL;
			break;
		}
		break;
	}

	if (!lve_exit)
		return 0;

	return (lve_library_handle != NULL) ? 1 : 0;
}

int governor_init_lve(void)
{
	if (init_lve)
	{
		if (lve == NULL)
		{
			lve = init_lve (malloc, free);
			if (!lve)
			{
				print_message_log("%s: ERROR, init_lve failed: errno %d", __FUNCTION__, errno);
			}
		}
	}
	else
	{
		print_message_log("%s: ERROR, init_lve is not initialized", __FUNCTION__);
	}

	if (lve == NULL)
	{
		return -1;
	}

	init_bad_users_list_client ();

	return 0;
}

void governor_destroy_lve(void)
{
	if (destroy_lve && lve)
	{
		destroy_lve (lve);
	}

	if (lve_library_handle)
	{
		dlclose (lve_library_handle);
	}

	remove_bad_users_list_client ();
}

__thread uint32_t lve_uid = 0;
__thread uint32_t in_lve = 0;
//Thread dependent variable for thread cookie storage needs for governor_enter_lve, governor_lve_exit
__thread uint32_t lve_cookie = 0;

static const int lve_flags = ((1 << 0) | (1 << 2) | (1 << 3) | (1 << 4)); //LVE_NO_MAXENTER|LVE_SILENCE|LVE_NO_UBC|LVE_NO_KILLABLE

int governor_enter_lve(uint32_t * cookie, char *username)
{
	if (!lve_enter_flags || !lve)
	{
		print_message_log("%s(%s) FAILED - LVE is not inited %p-%p", __FUNCTION__, username, lve_enter_flags, lve);
		return -1;
	}
	if (in_lve)
	{
		print_message_log("%s(%s) - already in LVE", __FUNCTION__, username);
		return 1;
	}

	if (!strncmp("root", username, 4 ))
	{
		// silently to suppress excessive logs
		return 1;
	}
	int container_lve = is_user_in_bad_list_cleint_persistent(username);
	if (container_lve < 0)
	{
		print_message_log("%s(%s) FAILED - is_user_in_bad_list_cleint_persistent FAILED", __FUNCTION__, username);
		return -1;
	}
	if (container_lve == 0)
	{
		print_message_log("%s(%s) NO NEED as is_user_in_bad_list_cleint_persistent cannot find it", __FUNCTION__, username);
		return 1;
	}

	print_message_log("%s(%s) is_user_in_bad_list_cleint_persistent FOUND it - %d - before lve_enter_flags call", __FUNCTION__, username, container_lve);
	errno = 0;
	int rc = lve_enter_flags(lve, container_lve, cookie, lve_flags);
	int keep_errno = errno;
	if (rc)
	{
		if (keep_errno == EPERM)
		{			//if already inside LVE
					//lve_exit(lve, cookie);
					//return -1;
			lve_uid = container_lve;
			in_lve = 1;
			print_message_log("%s(%s) ALREADY IN LVE as lve_enter_flags(%d) ret %d with errno==EPERM", __FUNCTION__, username, container_lve, rc);
			return 0;
		}
		print_message_log("%s(%s) FAILED as lve_enter_flags(%d) ret %d with errno %d (no EPERM)", __FUNCTION__, username, container_lve, rc, keep_errno);
		return -1;
	}
	lve_uid = container_lve;
	in_lve = 1;
	print_message_log("%s(%s) lve_enter_flags(%d) ENTERED INTO LVE", __FUNCTION__, username, container_lve, rc, keep_errno, EPERM);
	return 0;
}

int governor_enter_lve_light(uint32_t * cookie)
{
	if (!lve_enter_flags || !lve)
	{
		print_message_log("%s FAILED - LVE is not inited %p-%p", __FUNCTION__, lve_enter_flags, lve);
		return -1;
	}

	if (in_lve)
	{
		print_message_log("%s  - already in LVE", __FUNCTION__ );
		return 1;
	}

	if (!lve_uid)
	{
		print_message_log("%s  NO NEED as lve_uid %d", __FUNCTION__, lve_uid);
		return 1;
	}

	errno = 0;
	int rc = lve_enter_flags(lve, lve_uid, cookie, lve_flags);
	int keep_errno = errno;
	if (rc)
	{
		if (keep_errno == EPERM)
		{	//if already inside LVE
			//lve_exit(lve, cookie);
			//return -1;
			print_message_log("%s lve_enter_flags(%d) failed with code %d, but errno==EPERM - already in LVE", __FUNCTION__, lve_uid, rc);
			return 0;
		}
		print_message_log("%s lve_enter_flags(%d) failed with code %d and errno %d - FAILED", __FUNCTION__, lve_uid, rc, keep_errno);
		return -1;
	}
	print_message_log("%s lve_enter_flags(%d) OK", __FUNCTION__, lve_uid);
	return 0;
}

void governor_lve_exit(uint32_t * cookie)
{
	if (!lve_exit || !lve)
	{
		print_message_log("%s FAILED - LVE is not inited %p-%p", __FUNCTION__, lve_exit, lve);
		return;
	}

	if (!in_lve)
	{
		print_message_log("%s - not in LVE (uid %d)", __FUNCTION__, lve_uid);
		return;
	}

	print_message_log("%s (uid %d)", __FUNCTION__, lve_uid);
	lve_exit(lve, cookie);
	in_lve = 0;
}


typedef struct __mysql_mutex
{
	pid_t key; //thread_id
	int is_in_lve; //
	int is_in_mutex; //mutex_lock count
	int put_in_lve; //
	int critical;
	int was_in_lve; //
} mysql_mutex;

static int mysql_mutex_cmp(const void *a, const void *b)
{
	mysql_mutex *pa = (mysql_mutex *)a;
	mysql_mutex *pb = (mysql_mutex *)b;

	if (pa->key < pb->key)
		return -1;

	if (pa->key > pb->key)
		return 1;

	return 0;
}

__thread mysql_mutex *mysql_mutex_ptr = 0;

static void * gv_hash = NULL;

static pthread_mutex_t gv_hash_mutex = PTHREAD_MUTEX_INITIALIZER;

static int governor_add_mysql_thread_info(void)
{
	mysql_mutex *mm = NULL;
	mysql_mutex key;
	void * ptr;

	orig_pthread_mutex_lock(&gv_hash_mutex);
	key.key = gettid_p();
	ptr = tfind(&key, &gv_hash, mysql_mutex_cmp);
	if (ptr != NULL)
	{
		mm = *(mysql_mutex **)ptr;
		orig_pthread_mutex_unlock(&gv_hash_mutex);
		mysql_mutex_ptr = mm;
		return 0;
	}

	mm = (mysql_mutex *) calloc(1, sizeof(mysql_mutex));
	if (mm == NULL)
	{
		orig_pthread_mutex_unlock(&gv_hash_mutex);
		return -1;
	}
	mm->key = key.key;

	if (!tsearch(mm, &gv_hash, mysql_mutex_cmp))
	{
		free(mm);
		orig_pthread_mutex_unlock(&gv_hash_mutex);
		return -1;
	}

	orig_pthread_mutex_unlock(&gv_hash_mutex);
	mysql_mutex_ptr = mm;

	return 0;
}

static void governor_remove_mysql_thread_info(void)
{
	orig_pthread_mutex_lock(&gv_hash_mutex);
	if (gv_hash)
	{
		mysql_mutex *mm = NULL;
		mysql_mutex key;
		void * ptr;

		key.key = gettid_p();
		ptr = tfind(&key, &gv_hash, mysql_mutex_cmp);
		if (ptr != NULL) {

			mm = *(mysql_mutex **)ptr;
			tdelete(&key, &gv_hash, mysql_mutex_cmp);
			free(mm);
		}
	}
	orig_pthread_mutex_unlock(&gv_hash_mutex);
	mysql_mutex_ptr = NULL;
}

static void governor_destroy_mysql_thread_info(void)
{
	if (gv_hash) {
		orig_pthread_mutex_lock(&gv_hash_mutex);
		tdestroy(gv_hash, free);
		gv_hash = NULL;
		orig_pthread_mutex_unlock(&gv_hash_mutex);
	}
}

__attribute__((noinline)) int governor_put_in_lve(char *user)
{
	if (governor_add_mysql_thread_info() < 0)
		return -1;

	if (mysql_mutex_ptr) {
		if (!governor_enter_lve(&lve_cookie, user)) {
			mysql_mutex_ptr->is_in_lve = 1;
		}
		mysql_mutex_ptr->is_in_mutex = 0;
	}

	return 0;
}

__attribute__((noinline)) void governor_lve_thr_exit(void)
{
	if (mysql_mutex_ptr && mysql_mutex_ptr->is_in_lve == 1) {
		governor_lve_exit(&lve_cookie);
		mysql_mutex_ptr->is_in_lve = 0;
	}
	governor_remove_mysql_thread_info();
}

__attribute__((noinline)) int governor_put_in_lve_nowraps(char *user)
{
	return governor_enter_lve(&lve_cookie, user);
}

__attribute__((noinline)) void governor_lve_thr_exit_nowraps(void)
{
	governor_lve_exit(&lve_cookie);
}

__attribute__((noinline)) int pthread_mutex_lock(pthread_mutex_t *mp)
{
	//printf("%s mutex:%p\n", __func__, (void *)mp);
	lock_cnt++;
	if (mysql_mutex_ptr) {
		if (mysql_mutex_ptr->is_in_lve == 1)
		{
			if (!mysql_mutex_ptr->critical)
				governor_lve_exit(&lve_cookie);
			mysql_mutex_ptr->is_in_lve = 2;
		}
		else if (mysql_mutex_ptr->is_in_lve > 1)
		{
			mysql_mutex_ptr->is_in_lve++;
		}
		mysql_mutex_ptr->is_in_mutex++;
	}

	return orig_pthread_mutex_lock(mp);
}

__attribute__((noinline)) int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	//printf("%s mutex:%p\n", __func__, (void *)mutex);
	unlock_cnt++;
	int ret = orig_pthread_mutex_unlock(mutex);

	if (mysql_mutex_ptr) {
		if (mysql_mutex_ptr->is_in_lve == 2) {
			if(mysql_mutex_ptr->critical) {
				mysql_mutex_ptr->is_in_lve = 1;
			} else if (!governor_enter_lve_light(&lve_cookie)) {
				mysql_mutex_ptr->is_in_lve = 1;
			}
		} else if (mysql_mutex_ptr->is_in_lve > 2) {
			mysql_mutex_ptr->is_in_lve--;
		}
		mysql_mutex_ptr->is_in_mutex--;
	}

	return ret;
}

__attribute__((noinline)) int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	//printf("%s mutex:%p\n", __func__, (void *)mutex);
	trylock_cnt++;
	int ret = 0;
	if (mysql_mutex_ptr) {
		if (mysql_mutex_ptr->is_in_lve == 1) {
			if(!mysql_mutex_ptr->critical)
				governor_lve_exit(&lve_cookie);
		}
	}

	ret = orig_pthread_mutex_trylock(mutex);

	if (mysql_mutex_ptr) {
		if (ret != EBUSY){
			if (mysql_mutex_ptr->is_in_lve == 1) {
				mysql_mutex_ptr->is_in_lve = 2;
			} else if (mysql_mutex_ptr->is_in_lve > 1) {
				mysql_mutex_ptr->is_in_lve++;
			}
			mysql_mutex_ptr->is_in_mutex++;
		} else {
			if (mysql_mutex_ptr->is_in_lve == 1){
				if(mysql_mutex_ptr->critical){
					mysql_mutex_ptr->is_in_lve = 1;
				} else if (!governor_enter_lve_light(&lve_cookie)) {
					mysql_mutex_ptr->is_in_lve = 1;
				} else {
					mysql_mutex_ptr->is_in_lve = 0;
				}
			}
		}
	}

	return ret;
}

__attribute__((noinline)) void governor_reserve_slot(void)
{
	if (mysql_mutex_ptr) {
		if (mysql_mutex_ptr->is_in_lve == 1) {
			if (!mysql_mutex_ptr->critical)
				governor_lve_exit(&lve_cookie);
			mysql_mutex_ptr->is_in_lve = 2;
		} else if (mysql_mutex_ptr->is_in_lve > 1) {
			mysql_mutex_ptr->is_in_lve++;
		}
		mysql_mutex_ptr->is_in_mutex++;
	}
}

__attribute__((noinline)) void governor_release_slot(void)
{
	if (mysql_mutex_ptr) {
		if (mysql_mutex_ptr->is_in_lve == 2) {
			if (mysql_mutex_ptr->critical) {
				mysql_mutex_ptr->is_in_lve = 1;
			} else if (!governor_enter_lve_light(&lve_cookie)) {
				mysql_mutex_ptr->is_in_lve = 1;
			}
		} else if (mysql_mutex_ptr->is_in_lve > 2) {
			mysql_mutex_ptr->is_in_lve--;
		}
		mysql_mutex_ptr->is_in_mutex--;
	}
}

__attribute__((noinline)) void governor_critical_section_begin(void)
{
	if (mysql_mutex_ptr) {
		if (!mysql_mutex_ptr->critical)
			mysql_mutex_ptr->was_in_lve = mysql_mutex_ptr->is_in_lve;
		mysql_mutex_ptr->critical++;
	}
}

__attribute__((noinline)) void governor_critical_section_end(void)
{
	if (mysql_mutex_ptr) {
		mysql_mutex_ptr->critical--;
		if (mysql_mutex_ptr->critical < 0)
			mysql_mutex_ptr->critical = 0;
		if (!mysql_mutex_ptr->critical && (mysql_mutex_ptr->was_in_lve > 1) && (mysql_mutex_ptr->is_in_lve == 1)) {
			if (!governor_enter_lve_light(&lve_cookie)) {
				mysql_mutex_ptr->is_in_lve = 1;
			}
		}
	}
}

void governor_destroy(void)
{
	governor_destroy_mysql_thread_info();
	governor_destroy_lve();
	close_sock();
}

void governor_lve_exit_null(void)
{
}

int governor_lve_enter_pid(pid_t pid)
{
	return 0;
}

int governor_is_in_lve()
{
	return -1;
}

