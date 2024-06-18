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
#include "log.h"

#define SEC2NANO 1000000000

pthread_mutex_t mtx_write = PTHREAD_MUTEX_INITIALIZER;

typedef struct _sock_data
{
	int socket;
	int status;
} sock_data;
sock_data sd = { -1, 0 };

static int try_lock(pthread_mutex_t *mtx)
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

static int close_sock_in();

static int connection_with_timeout_poll(int sk, struct sockaddr_un *sa, socklen_t len, int timeout)
{
	int ret = 0;

	int ts = timeout * 1000;

	struct pollfd fds[1];
	int nfds = 1;
	memset(fds, 0, sizeof(fds));
	fds[0].fd = sk;
	fds[0].events = POLLOUT;

	int flags = 0;
	if ((flags = fcntl (sk, F_GETFL, 0)) < 0)
		return -1;
	if (fcntl (sk, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;

	if ((ret = connect (sk, (struct sockaddr *) sa, len)) < 0)
		if (errno != EINPROGRESS && errno != EINTR)
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

	int error = 0;
	socklen_t error_len = sizeof(error);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &error, &error_len) < 0)
	{
		close(sk);
		return -1;
	}
	if (error)
	{
		close(sk);
		errno = error;
		return -1;
	}

	/*if(fcntl(sk, F_SETFL, flags) < 0) {
		close(sk);
		return -1;
		} */

	return 0;
}

static int connect_to_server_in()
{
	open_log(MYSQLD_EXTLOG_PATH);
	init_log_ex(false);

	sd.socket = -1;
	sd.status = 0;

	int s;
	if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		LOG(L_INFO, "failed to create socket to connect to mysqld");
		return -1;
	}

	struct sockaddr_un saun;
	saun.sun_family = AF_UNIX;
	strlcpy(saun.sun_path, MYSQL_SOCK_ADDRESS, sizeof(saun.sun_path));
	socklen_t len = sizeof(struct sockaddr_un);

	if (connection_with_timeout_poll(s, &saun, len, 5) < 0)
	{
		LOG(L_INFO, "failed to connect to mysqld over socket");
		return -2;
	}
	/*int rt_code;
		rt_code = fcntl(s, F_GETFL, 0);
		fcntl(s, F_SETFL, rt_code | O_NONBLOCK); */

	sd.socket = s;
	sd.status = 1;

	LOG(L_INFO, "connected to mysqld over socket");
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
	if (!ret)
		return ret;

	// special processing for the first unsuccessful connect for CLOS-1783
	if (not_first_connect)
	{
		return ret;
	} else
	{
		not_first_connect = 1;
		if (ret)
			LOG(L_INFO, "first failure of connect to mysqld over socket is forgiven");
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
	if (!ret)
		return ret;

	// special processing for the first unsuccessful connect
	if (not_first_connect)
	{
		return ret;
	} else
	{
		not_first_connect = 1;
		return 1;
	}
}

static int send_info(const char *username, int type)
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
	snd.nanoseconds = tim.tv_nsec;
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

int send_info_begin(const char *username)
{
#ifdef TEST
	//printf("Send begin info %s, %d, %d\n", username, sd.socket, sd.status);
#endif
	return send_info(username, 0);
}

int send_info_end(const char *username)
{
#ifdef TEST
	//printf("Send end info %s, %d, %d\n", username, sd.socket, sd.status);
#endif
	return send_info(username, 1);
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

// for OBSOMUT
void init_libgovernor(void)
{
	if (!orig_pthread_mutex_lock_ptr && !orig_pthread_mutex_trylock_ptr && !orig_pthread_mutex_unlock_ptr)
	{
		pthread_mutex_func_t orig_lock_ptr = NULL;
		pthread_mutex_func_t orig_trylock_ptr = NULL;
		pthread_mutex_func_t orig_unlock_ptr = NULL;

		orig_pthread_mutex_lock_ptr = void_pthread_mutex_func;
		orig_pthread_mutex_trylock_ptr = void_pthread_mutex_func;
		orig_pthread_mutex_unlock_ptr = void_pthread_mutex_func;

		orig_lock_ptr = (pthread_mutex_func_t)(intptr_t)dlsym(RTLD_NEXT, "pthread_mutex_lock");
		orig_trylock_ptr = (pthread_mutex_func_t)(intptr_t)dlsym(RTLD_NEXT, "pthread_mutex_trylock");
		orig_unlock_ptr = (pthread_mutex_func_t)(intptr_t)dlsym(RTLD_NEXT, "pthread_mutex_unlock");

		if (!orig_lock_ptr || !orig_trylock_ptr || !orig_unlock_ptr)
		{
			//LOG(L_ERR|L_MUT, "failed to load original pthread_mutex_...() functions: %s", dlerror());
			fprintf(stderr, "%s dlerror:%s\n", __func__, dlerror());
			abort();
		}

		orig_pthread_mutex_lock_ptr = orig_lock_ptr;
		orig_pthread_mutex_trylock_ptr = orig_trylock_ptr;
		orig_pthread_mutex_unlock_ptr = orig_unlock_ptr;

		//LOG(L_MUT, "pthread_mutex_...() intercepted");
	}
}

static int orig_pthread_mutex_lock(pthread_mutex_t *mutex)
{
	if (orig_pthread_mutex_lock_ptr == NULL)
		init_libgovernor();

	if (orig_pthread_mutex_lock_ptr == NULL)
	{
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

	if (orig_pthread_mutex_trylock_ptr == NULL)
	{
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

	if (orig_pthread_mutex_unlock_ptr == NULL)
	{
		fprintf(stderr, "%s(%p) mutex:%p\n", __func__, orig_pthread_mutex_unlock_ptr, (void *)mutex);
		return EINVAL;
	}
	else
		return (*orig_pthread_mutex_unlock_ptr)(mutex);
}

static unsigned int lock_cnt = 0;
static unsigned int unlock_cnt = 0;
static unsigned int trylock_cnt = 0;

// for OBSOMUT
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

//void governor_init_message_log(void);

int governor_load_lve_library ()
{
	lve_library_handle = NULL;

	//governor_init_message_log();
	char *error_dl = NULL;
	lve_library_handle = dlopen ("liblve.so.0", RTLD_LAZY);
	if (!lve_library_handle)
		LOG(L_ERR, "dlopen(liblve.so.0) failed; errno %d", errno);

	if (!lve_library_handle)
		return 0;

	while (1)
	{
		init_lve = (void *(*)(void *, void *)) dlsym(lve_library_handle, "init_lve");
		if ((error_dl = dlerror ()) != NULL)
		{
			LOG(L_ERR, "dlerror after dlsym(init_lve) ret (%s); init_lve(%p) errno %d", error_dl, init_lve, errno);
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
			LOG(L_ERR, "dlerror after dlsym(destroy_lve) ret (%s); destroy_lve(%p) errno %d", error_dl, destroy_lve, errno);
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
			LOG(L_ERR, "dlerror after dlsym(lve_enter_flags) ret (%s); lve_enter_flags(%p) errno %d", error_dl, lve_enter_flags, errno);
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
			LOG(L_ERR, "dlerror after dlsym(lve_exit) ret (%s); lve_exit(%p) errno %d", error_dl, lve_exit, errno);
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
			LOG(L_ERR, "dlerror after dlsym(is_in_lve) ret (%s); is_in_lve(%p) errno %d", error_dl, is_in_lve, errno);
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
				LOG(L_ERR, "init_lve failed: errno %d", errno);
		}
	}
	else
	{
		LOG(L_ERR, "init_lve is not initialized");
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
//Thread dependent variable for thread cookie storage needs for governor_enter_lve, governor_lve_exit
__thread uint32_t lve_cookie = 0;

static const int lve_flags = ((1 << 0) | (1 << 2) | (1 << 3) | (1 << 4)); //LVE_NO_MAXENTER|LVE_SILENCE|LVE_NO_UBC|LVE_NO_KILLABLE

int governor_enter_lve(uint32_t * cookie, const char *username)
{
	if (!lve_enter_flags || !lve)
	{
		LOG(L_FRZ, "(%s) FAILED - LVE is not inited %p-%p", username, lve_enter_flags, lve);
		return -1;
	}

	if (!strncmp("root", username, 4 ))
	{
		// silently to suppress excessive logs
		return 1;
	}
	int container_lve = is_user_in_bad_list_client_persistent(username);
	if (container_lve < 0)
	{
		LOG(L_ERR|L_FRZ, "(%s) FAILED - is_user_in_bad_list_client_persistent FAILED", username);
		return -1;
	}
	if (container_lve == 0)
	{
		LOG(L_FRZ, "(%s) NO NEED as is_user_in_bad_list_client_persistent cannot find it", username);
		return 1;
	}

	LOG(L_FRZ, "(%s) is_user_in_bad_list_client_persistent FOUND it - %d - before lve_enter_flags call", username, container_lve);
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
			LOG(L_FRZ, "(%s) ALREADY IN LVE as lve_enter_flags(%d) ret %d with errno==EPERM", username, container_lve, rc);
			return 0;
		}
		LOG(L_ERR|L_FRZ, "(%s) FAILED as lve_enter_flags(%d) ret %d with errno %d (no EPERM)", username, container_lve, rc, keep_errno);
		return -1;
	}
	lve_uid = container_lve;
	LOG(L_FRZ, "(%s) lve_enter_flags(%d) ENTERED INTO LVE", username, container_lve, rc, keep_errno, EPERM);
	return 0;
}

int governor_enter_lve_light(uint32_t * cookie)
{
	if (!lve_enter_flags || !lve)
	{
		LOG(L_FRZ, "LVE is not inited %p-%p", lve_enter_flags, lve);
		return -1;
	}

	if (!lve_uid)
	{
		LOG(L_FRZ, "NO NEED as lve_uid %d", lve_uid);
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
			LOG(L_FRZ, "lve_enter_flags(%d) failed with code %d, but errno==EPERM - already in LVE", lve_uid, rc);
			return 0;
		}
		LOG(L_ERR|L_FRZ, "lve_enter_flags(%d) failed with code %d and errno %d - FAILED", lve_uid, rc, keep_errno);
		return -1;
	}
	LOG(L_FRZ, "lve_enter_flags(%d) OK", lve_uid);
	return 0;
}

void governor_lve_exit(uint32_t * cookie)
{
	if (!lve_exit || !lve)
	{
		LOG(L_UNFRZ, "LVE is not inited %p-%p", lve_exit, lve);
		return;
	}

	LOG(L_UNFRZ, "(uid %d)", lve_uid);
	lve_exit(lve, cookie);
}

//**************************************************************************************************
// OBSOMUT (=='OBSOlete governor thread-local MUTex') {{{
//
// History:
// This mechanism was long used to support thread info for Full LVE mode in MySQL/MariaDB patches.
// It was recognized as overly complex and problematic during patch refactoring (CLOS-2697),
// is no more utilized by the modern refactored patches,
// and retains here only for compatibility of the current libgovernor with old cl-MySQL/cl-MariaDB versions.
//
// Principle:
// The structure of a few integers is allocated dynamically for a thread.
// Those integers are mostly of 'semi-boolean' nature -
// that is, 0 means 'false', but different positive values denote different states within 'true':
// 'outside mutex or mutex depth', 'are we in critical sections and how deep', etc.
// The structure address is stored in a thread-local pointer,
// and is also memorized in a 'thread id' -> 'pointer' map, protected by its own guard mutex.
// The purpose of it all is the very idea of the Full mode:
// having mutex lock()/unlock() API intercepted somehow, recognize the outermost mutex,
// and if the thread is in LVE at the lock() moment, exit LVE temporarily for the duration of mutex ownership,
// to avoid being frozen by LVE while holding global resources.
// OBSOMUT is activated by obsomut_add_thread_info(), which sets the main thread state variable, 'obsomut_mutex_ptr'.
// Once it became active, some functions below, exported from libgovernor, update that state.
// Finally, the state is taken into account in our pthread_mutex_...() substitutes,
// installed through init_libgovernor()/fini_libgovernor() .so callbacks.
//
// Why obsolete:
// Most patches contained OBSOMUT immediately in their code, using MySQL/MariaDB's native hash.h/.c as map implementation.
// It was analyzed during the refactoring, and very little left of it - a single 'LVE+mutex depth' counter.
// The map appeared not needed (probably planned for heap deallocation, but right before exiting mysqld)
// and causing potential performance problems -
// collisions due to unimplemented (constant) hash function and locking the map guard mutex.
// The state system was overly complex due to support of 'critical_section' pair of primitives, which are of doubtful need (CLOS-2734).
// The selective regard for native pthread_mutex_...() return result also causes confusion.
// So, OBSOMUT has gone from the refactored patches.
// But the below OBSOMUT implementation, residing inside libgovernor.so,
// using tsearch() function family for map implementation (instead of MySQL hash.c),
// still remains for the older cl-MySQL/cl-MariaDB - those calling governor_put_in_lve()/governor_lve_thr_exit().
// Of the modern patches, probably only 'govlve_mariadb_10_6_18.patch' was using it recently,
// but it's superseded by 'cl_lve_mariadb_10_6_18.patch'.
//
// It's very important to note, that our custom pthread_mutex_...() functions regard only libgovernor-residing thread info.
// They don't see any thread info maintained in the patch itself.
// That is, they do additional custom job only for OBSOMUT - i.e., for some very old patches calling governor_put_in_lve()/governor_lve_thr_exit().
// If we knew we don't ever need to serve those old patches with libgovernor,
// we could remove our pthread_mutex_...() subsitutes and our init_libgovernor()/fini_libgovernor() used to inject them.
//
// Yet once: all patches fall into two categories:
// - Old ones, calling governor_put_in_lve():
//      they WILL use OBSOMUT from libgovernor.so.
//      they DON'T NEED to implement their own thread info - OBSOMUT or any other.
//      they DON'T NEED intercepting mutex lock()/unlock() using macros. If they do intercept, they count each lock() and unlock() twice - which looks bad, but shouldn't cause bugs.
// - Old ones, NOT calling governor_put_in_lve(), plus all new ones:
//      they will NOT use OBSOMUT from libgovernor.so.
//      they DO NEED to implement their thread own info, and most certainly they have it as old hash.cc-based OBSOMUT.
//      they DO NEED intercepting mutex lock()/unlock() using macros, otherwise they don't track lock()/unlock() at all.

typedef struct __obsomut_mutex
{
	pid_t key; 				// thread_id
	int is_in_lve;
	int is_in_mutex;		// mutex_lock count
	int put_in_lve;			// see long comment below about governor_setlve_mysql_thread_info()
	int critical;
	int was_in_lve;
} obsomut_mutex;

static int obsomut_mutex_cmp(const void *a, const void *b)	// for tsearch() family
{
	const obsomut_mutex *pa = (const obsomut_mutex*)a;
	const obsomut_mutex *pb = (const obsomut_mutex*)b;
	if (pa->key < pb->key)
		return -1;
	if (pa->key > pb->key)
		return 1;
	return 0;
}

/*
The only use of "put_in_lve" member was observed in this function,
defined in MysQL/MariaDB patches but never called, at least since 2016:

void governor_setlve_mysql_thread_info(pid_t thread_id)
{
	pid_t *buf = NULL;
	mysql_mutex *mm = nullptr;
	pthread_mutex_lock(&mtx_mysql_lve_mutex_governor_ptr);
	if (mysql_lve_mutex_governor)
	{
		buf = (pid_t *)((intptr_t)thread_id);
		mm = (mysql_mutex *) my_hash_search(mysql_lve_mutex_governor, (uchar *) buf, sizeof(buf));
		if (mm)
		{
			if (!mm->is_in_lve)
				mm->put_in_lve = 1;
		}
	}
	pthread_mutex_unlock(&mtx_mysql_lve_mutex_governor_ptr);
}

Looked like an unfinished or abandoned idea.
It was used in tests, though, but it's only written and printed there, and no decisions are taken based on its value.
*/

static __thread obsomut_mutex *obsomut_mutex_ptr = NULL;

static void *obsomut_hash = NULL;	// to be accessed using tsearch() and relatives
static pthread_mutex_t obsomut_hash_mutex = PTHREAD_MUTEX_INITIALIZER;	// protect 'obsomut_hash' accessed from multiple threads

static int obsomut_add_thread_info(void)
{
	obsomut_mutex *mm = NULL;
	obsomut_mutex key;
	void *ptr;

	orig_pthread_mutex_lock(&obsomut_hash_mutex);
	key.key = gettid_p();
	ptr = tfind(&key, &obsomut_hash, obsomut_mutex_cmp);
	if (ptr != NULL)
	{
		mm = *(obsomut_mutex *const*)ptr;
		orig_pthread_mutex_unlock(&obsomut_hash_mutex);
		obsomut_mutex_ptr = mm;
		return 0;
	}

	mm = (obsomut_mutex*)calloc(1, sizeof(obsomut_mutex));
	if (mm == NULL)
	{
		orig_pthread_mutex_unlock(&obsomut_hash_mutex);
		return -1;
	}
	mm->key = key.key;

	if (!tsearch(mm, &obsomut_hash, obsomut_mutex_cmp))
	{
		free(mm);
		orig_pthread_mutex_unlock(&obsomut_hash_mutex);
		return -1;
	}

	orig_pthread_mutex_unlock(&obsomut_hash_mutex);
	obsomut_mutex_ptr = mm;
	return 0;
}

static void obsomut_remove_thread_info(void)
{
	orig_pthread_mutex_lock(&obsomut_hash_mutex);
	if (obsomut_hash)
	{
		obsomut_mutex *mm = NULL;
		obsomut_mutex key;
		const void *ptr;

		key.key = gettid_p();
		ptr = tfind(&key, &obsomut_hash, obsomut_mutex_cmp);
		if (ptr != NULL)
		{
			mm = *(obsomut_mutex *const*)ptr;
			tdelete(&key, &obsomut_hash, obsomut_mutex_cmp);
			free(mm);
		}
	}
	orig_pthread_mutex_unlock(&obsomut_hash_mutex);
	obsomut_mutex_ptr = NULL;
}

static void obsomut_destroy_all_thread_info(void)
{
	if (obsomut_hash)
	{
		orig_pthread_mutex_lock(&obsomut_hash_mutex);
		tdestroy(obsomut_hash, free);
		obsomut_hash = NULL;
		orig_pthread_mutex_unlock(&obsomut_hash_mutex);
	}
}
//**************************************************************************************************
// }}} OBSOMUT
//**************************************************************************************************





// OBSOLETE: not called from the current patches
__attribute__((noinline)) int governor_put_in_lve(const char *user)
{
	if (obsomut_add_thread_info() < 0)
		return -1;

	if (obsomut_mutex_ptr)
	{
		if (!governor_enter_lve(&lve_cookie, user))
		{
			obsomut_mutex_ptr->is_in_lve = 1;
		}
		obsomut_mutex_ptr->is_in_mutex = 0;
	}

	return 0;
}

// OBSOLETE: called rarely - e.g., from 'govlve_mariadb_10_6_18.patch', but to be replaced by 'governor_lve_exit' after patch refactoring
__attribute__((noinline)) void governor_lve_thr_exit(void)
{
	if (obsomut_mutex_ptr && obsomut_mutex_ptr->is_in_lve == 1)
	{
		governor_lve_exit(&lve_cookie);
		obsomut_mutex_ptr->is_in_lve = 0;
	}
	obsomut_remove_thread_info();
}

// OBSOLETE: not loaded by most current patches (yet NOT ALL checked)
__attribute__((noinline)) int governor_put_in_lve_nowraps(const char *user)
{
	return governor_enter_lve(&lve_cookie, user);
}

// OBSOLETE: not loaded by most current patches (yet NOT ALL checked)
__attribute__((noinline)) void governor_lve_thr_exit_nowraps(void)
{
	governor_lve_exit(&lve_cookie);
}

// for OBSOMUT
__attribute__((noinline)) int pthread_mutex_lock(pthread_mutex_t *mp)
{
	//printf("%s mutex:%p\n", __func__, (void *)mp);
	lock_cnt++;
	if (obsomut_mutex_ptr)
	{
		if (obsomut_mutex_ptr->is_in_lve == 1)
		{
			if (!obsomut_mutex_ptr->critical)
				governor_lve_exit(&lve_cookie);
			obsomut_mutex_ptr->is_in_lve = 2;
		}
		else if (obsomut_mutex_ptr->is_in_lve > 1)
		{
			obsomut_mutex_ptr->is_in_lve++;
		}
		obsomut_mutex_ptr->is_in_mutex++;
	}

	return orig_pthread_mutex_lock(mp);
}

// for OBSOMUT
__attribute__((noinline)) int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	//printf("%s mutex:%p\n", __func__, (void *)mutex);
	unlock_cnt++;	// not used anywhere
	int ret = orig_pthread_mutex_unlock(mutex);

	if (obsomut_mutex_ptr)
	{
		if (obsomut_mutex_ptr->is_in_lve == 2)
		{
			if(obsomut_mutex_ptr->critical)
			{
				obsomut_mutex_ptr->is_in_lve = 1;
			} else if (!governor_enter_lve_light(&lve_cookie))
			{
				obsomut_mutex_ptr->is_in_lve = 1;
			}
		} else if (obsomut_mutex_ptr->is_in_lve > 2)
		{
			obsomut_mutex_ptr->is_in_lve--;
		}
		obsomut_mutex_ptr->is_in_mutex--;
	}

	return ret;
}

// for OBSOMUT
__attribute__((noinline)) int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	//printf("%s mutex:%p\n", __func__, (void *)mutex);
	trylock_cnt++;
	int ret = 0;
	if (obsomut_mutex_ptr)
	{
		if (obsomut_mutex_ptr->is_in_lve == 1)
		{
			if(!obsomut_mutex_ptr->critical)
				governor_lve_exit(&lve_cookie);
		}
	}

	ret = orig_pthread_mutex_trylock(mutex);

	if (obsomut_mutex_ptr)
	{
		if (ret != EBUSY)
		{
			if (obsomut_mutex_ptr->is_in_lve == 1)
				obsomut_mutex_ptr->is_in_lve = 2;
			else if (obsomut_mutex_ptr->is_in_lve > 1)
				obsomut_mutex_ptr->is_in_lve++;
			obsomut_mutex_ptr->is_in_mutex++;
		} else
		{
			if (obsomut_mutex_ptr->is_in_lve == 1)
			{
				if (obsomut_mutex_ptr->critical)
					obsomut_mutex_ptr->is_in_lve = 1;
				else if (!governor_enter_lve_light(&lve_cookie))
					obsomut_mutex_ptr->is_in_lve = 1;
				else
					obsomut_mutex_ptr->is_in_lve = 0;
			}
		}
	}

	return ret;
}

// OBSOLETE: called rarely - e.g., from 'govlve_mariadb_10_6_18.patch', but to be replaced by the implementation inside patch code after patch refactoring
__attribute__((noinline)) void governor_reserve_slot(void)
{
	if (obsomut_mutex_ptr)
	{
		if (obsomut_mutex_ptr->is_in_lve == 1)
		{
			if (!obsomut_mutex_ptr->critical)
				governor_lve_exit(&lve_cookie);
			obsomut_mutex_ptr->is_in_lve = 2;
		} else if (obsomut_mutex_ptr->is_in_lve > 1)
		{
			obsomut_mutex_ptr->is_in_lve++;
		}
		obsomut_mutex_ptr->is_in_mutex++;
	}
}

// OBSOLETE: called rarely - e.g., from 'govlve_mariadb_10_6_18.patch', but to be replaced by the implementation inside patch code after patch refactoring
__attribute__((noinline)) void governor_release_slot(void)
{
	if (obsomut_mutex_ptr)
	{
		if (obsomut_mutex_ptr->is_in_lve == 2)
		{
			if (obsomut_mutex_ptr->critical)
			{
				obsomut_mutex_ptr->is_in_lve = 1;
			} else if (!governor_enter_lve_light(&lve_cookie))
			{
				obsomut_mutex_ptr->is_in_lve = 1;
			}
		} else if (obsomut_mutex_ptr->is_in_lve > 2)
		{
			obsomut_mutex_ptr->is_in_lve--;
		}
		obsomut_mutex_ptr->is_in_mutex--;
	}
}

// OBSOLETE: called rarely - e.g., from 'govlve_mariadb_10_6_18.patch', but to be replaced by the implementation inside patch code after patch refactoring.
// Moreover, the very need for "critical section" API is under evaluation (CLOS-2734),
// and even if it proves needed, we can use a patch code implementation, preferred in almost all modern patches.
__attribute__((noinline)) void governor_critical_section_begin(void)
{
	if (obsomut_mutex_ptr)
	{
		if (!obsomut_mutex_ptr->critical)
			obsomut_mutex_ptr->was_in_lve = obsomut_mutex_ptr->is_in_lve;
		obsomut_mutex_ptr->critical++;
	}
}

// OBSOLETE: called rarely - e.g., from 'govlve_mariadb_10_6_18.patch', but to be replaced by the implementation inside patch code after patch refactoring.
// Moreover, the very need for "critical section" API is under evaluation (CLOS-2734),
// and even if it proves needed, we can use a patch code implementation, preferred in almost all modern patches.
__attribute__((noinline)) void governor_critical_section_end(void)
{
	if (obsomut_mutex_ptr)
	{
		obsomut_mutex_ptr->critical--;
		if (obsomut_mutex_ptr->critical < 0)
			obsomut_mutex_ptr->critical = 0;
		if (!obsomut_mutex_ptr->critical && (obsomut_mutex_ptr->was_in_lve > 1) && (obsomut_mutex_ptr->is_in_lve == 1))
		{
			if (!governor_enter_lve_light(&lve_cookie))
			{
				obsomut_mutex_ptr->is_in_lve = 1;
			}
		}
	}
}

// OBSOLETE: loaded by some current patches, but never called
void governor_destroy(void)
{
	obsomut_destroy_all_thread_info();
	governor_destroy_lve();
	close_sock();
}

// OBSOLETE: loaded by some current patches, but never called
void governor_lve_exit_null(void)
{
}

// OBSOLETE: loaded by some current patches, but never called
int governor_lve_enter_pid(pid_t pid)
{
	return 0;
}

// OBSOLETE: loaded by some current patches, but never called
int governor_is_in_lve()
{
	return -1;
}
