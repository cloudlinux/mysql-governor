/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>

#include "log.h"
#include "data.h"
#include "dbgovernor_string_functions.h"
#include "shared_memory.h"
#include "dbuser_map.h"

#define MAX_ITEMS_IN_TABLE 100000

#define SHARED_MEMORY_NAME_PRIVATE "/var/lve/dbgovernor-shm/governor_bad_users_list"

/*
    Custom cl_shm_open is used, instead of system shm_open,
    and bad users list will be located in the custom location -
    /var/lve/dbgovernor-shm instead of /dev/shm
*/
static const char *shared_memory_name = SHARED_MEMORY_NAME_PRIVATE;

#define cl_stat_shared_memory_file(st) stat(shared_memory_name, (st))

int cl_shm_open(int oflag, mode_t mode)
{
	oflag |= O_NOFOLLOW | O_CLOEXEC;

	/* Disable asynchronous cancellation.  */
	int state;
	pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &state);

	int fd = open (shared_memory_name, oflag, mode);

	pthread_setcancelstate (state, NULL);

	return fd;
}


// this variable set in mysql_connector_common.c file. users only by governor binaries
// don`t use in mysql shared library
char *unix_socket_address = NULL;

typedef struct __items_structure
{
	char username[USERNAMEMAXLEN];
	int32_t uid;
} items_structure;

typedef struct __shm_structure
{
	pthread_rwlock_t rwlock;
	long item_count;
	items_structure items[MAX_ITEMS_IN_TABLE];
} shm_structure;

shm_structure *bad_list = NULL;
int shm_fd = -1;

int init_bad_users_list_utility(void)
{
	if ((shm_fd = cl_shm_open(O_RDWR, 0600)) < 0)
	{
		return -1;
	}

	if ((bad_list = (shm_structure *) cl_mmap(0, sizeof (shm_structure), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0)) == MAP_FAILED)
	{
		close(shm_fd);
		shm_fd = -1;
		return -1;
	}

	int rc = pthread_rwlock_wrlock(&bad_list->rwlock);
	if (rc)
		LOG(L_ERR, "pthread_rwlock_wrlock()=%d", rc);
	else
	{
		clear_bad_users_list();
		rc = pthread_rwlock_unlock(&bad_list->rwlock);
		if (rc)
			LOG(L_ERR, "pthread_rwlock_unlock()=%d", rc);
	}

	return 0;
}

int remove_bad_users_list_utility(void)
{
	if (bad_list && bad_list != MAP_FAILED)
	{
		cl_munmap(bad_list, sizeof(shm_structure));
	}
	if (shm_fd >= 0)
	{
		close(shm_fd);
		shm_fd = -1;
	}
	return 0;
}

#ifndef LIBGOVERNOR

/*
   uid/gid will not be changed by chown function with -1 value
   But POSIX says that their types are integer, no mention of signed or unsigned
   And on the Linux they are unsigned in fact
*/
static uid_t mysql_uid = UNINITED_UID;
static gid_t mysql_gid = UNINITED_GID;

void init_mysql_uidgid()
{
	const struct passwd *passwd = getpwnam("mysql");
	if (passwd)
		mysql_uid = passwd->pw_uid;
	const struct group *group = getgrnam("mysql");
	if (group)
		mysql_gid = group->gr_gid;
}

uid_t get_mysql_uid()
{
	return mysql_uid;
}

gid_t get_mysql_gid()
{
	return mysql_gid;
}

int init_bad_users_list(void)
{
	//if(shared_memory_name) shm_unlink(shared_memory_name);
	//sem_unlink(SHARED_MEMORY_SEM);
	mode_t old_umask = umask(0);

	if (mysql_uid == UNINITED_UID || mysql_gid == UNINITED_GID)
	{
		init_mysql_uidgid();
	}
	bool first = false;
	if ((shm_fd = cl_shm_open(O_CREAT | O_EXCL | O_RDWR, 0600)) > 0)
	{
		first = true;
	}
	else if ((shm_fd = cl_shm_open(O_RDWR, 0600)) < 0)
	{
		umask(old_umask);
		LOG(L_ERR, "cl_shm_open(%s) failed with %d code - EXITING", shared_memory_name, errno);
		return -1;
	}
	else
	{
		struct stat file;
		if (cl_stat_shared_memory_file(&file) == 0)
		{
			if (file.st_size < sizeof(shm_structure))
				first = true;
		}
	}

	/* Make chown even if file existed before open - to fix possible previous errors */
	int rc = fchown(shm_fd, mysql_uid, mysql_gid);
	if (rc)
		LOG(L_ERR, "chown(%s, %d, %d) failed with %d code - IGNORING", shared_memory_name, (int)mysql_uid, (int)mysql_gid, errno);
	rc = fchmod(shm_fd, S_IRUSR | S_IWUSR);
	if (rc)
		LOG(L_ERR, "chmod(%s, %o) failed with %d code - IGNORING", shared_memory_name, S_IRUSR | S_IWUSR, errno);

	if (first)
	{
		if (ftruncate(shm_fd, sizeof(shm_structure)))
			LOG(L_ERR, "truncate(%s, %u) failed with %d code - IGNORING", shared_memory_name, (unsigned)sizeof(shm_structure), errno);
	}

	if ((bad_list = (shm_structure *) cl_mmap(0, sizeof (shm_structure), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0)) == MAP_FAILED)
	{
		LOG(L_ERR, "cl_map(%s) failed with %d code - EXITING", shared_memory_name, errno);
		close(shm_fd);
		shm_fd = -1;
		umask(old_umask);
		return -1;
	}

	if (first)
	{
		pthread_rwlockattr_t attr;
		rc = pthread_rwlockattr_init(&attr);
		if (rc)
		{
			LOG(L_ERR, "pthread_rwlockattr_init()=%d", rc);
			goto fail;
		}
		rc = pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
		if (rc)
		{
			LOG(L_ERR, "pthread_rwlockattr_setpshared()=%d", rc);
			goto fail;
		}
		rc = pthread_rwlock_init(&bad_list->rwlock, &attr);
		if (rc)
		{
			LOG(L_ERR, "pthread_rwlock_init()=%d", rc);
			goto fail;
		}
		goto end;
fail:
		cl_munmap(bad_list, sizeof(shm_structure));
		close(shm_fd);
		shm_fd = -1;
		umask(old_umask);
		return -1;
end:	;
	}

	umask(old_umask);

	rc = pthread_rwlock_wrlock(&bad_list->rwlock);
	if (rc)
		LOG(L_ERR, "pthread_rwlock_wrlock()=%d", rc);
	else
	{
		clear_bad_users_list();
		rc = pthread_rwlock_unlock(&bad_list->rwlock);
		if (rc)
			LOG(L_ERR, "pthread_rwlock_unlock()=%d", rc);
	}

	return 0;
}

// looks like never called
int init_bad_users_list_if_not_exitst(void)
{
	if (!bad_list || bad_list == MAP_FAILED)
		return init_bad_users_list();
	return 0;
}

#endif // LIBGOVERNOR

static int governor_rwlock_timedrdlock(pthread_rwlock_t *rwlock, unsigned timeout_sec)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts))
	{
		LOG(L_ERR, "clock_gettime() failed, errno=%d", errno);
		return -1;
	}
	ts.tv_sec += timeout_sec;
	return pthread_rwlock_timedrdlock(rwlock, &ts);
}

static int governor_rwlock_timedwrlock(pthread_rwlock_t *rwlock, unsigned timeout_sec)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts))
	{
		LOG(L_ERR, "clock_gettime() failed, errno=%d", errno);
		return -1;
	}
	ts.tv_sec += timeout_sec;
	return pthread_rwlock_timedwrlock(rwlock, &ts);
}

void clear_bad_users_list(void)
{
	if (!bad_list || bad_list == MAP_FAILED)
		return;
	bad_list->item_count = 0;
	memset(bad_list->items, 0, sizeof(bad_list->items));
}

int remove_bad_users_list(void)
{
	if (bad_list && bad_list != MAP_FAILED)
	{
		cl_munmap(bad_list, sizeof(shm_structure));
	}
	if (shm_fd >= 0)
	{
		close(shm_fd);
		shm_fd = -1;
	}
	bad_list = NULL;
	return 0;
}

#ifndef LIBGOVERNOR

static int is_user_in_list(const char *username)
{
	if (!bad_list || bad_list == MAP_FAILED)
	{
		LOG(L_FRZ, "(%s): EXIT as bad_list is NOT INITED %p", username, bad_list);
		return -1;
	}
	long i;
	for (i=0; i < bad_list->item_count; i++)
	{
		LOG(L_FRZ, "(%s): %ld/%ld: before check against(%s)", username, i, bad_list->item_count, bad_list->items[i].username);
		if (!strncmp(bad_list->items[i].username, username, USERNAMEMAXLEN-1))
		{
			LOG(L_FRZ, "(%s): %ld/%ld: FOUND(%s)", username, i, bad_list->item_count, bad_list->items[i].username);
			return 1;
		}
	}
	LOG(L_FRZ, "(%s): NOT FOUND from %ld", username, bad_list->item_count);
	return 0;
}

int add_user_to_list(const char *username, int is_all)
{
	if (!bad_list || bad_list == MAP_FAILED)
	{
		LOG(L_FRZ, "(%s, %d): FAILED as bad_list is NOT INITED %p", username, is_all, bad_list);
		return -1;
	}

	// First check if the user is already in the list
	// before any locks and heavy operation on the map
	if (is_user_in_list(username))
	{
		LOG(L_FRZ, "(%s, %d): EXIT as is_user_in_list FOUND it", username, is_all);
		return 0;
	}

	int uid = BAD_LVE;
	if (lock_read_map() == 0)
	{
		uid = get_uid(username);
		unlock_rdwr_map();
		LOG(L_FRZ, "(%s, %d): get_uid ret %d", username, is_all, uid);
	}
	else
	{
		LOG(L_FRZ, "(%s, %d): lock_read_map failed so NO CALL to get_uid and uid left BAD_LVE %d", username, is_all, uid);
	}
	if (is_all && uid == BAD_LVE)
	{
		LOG(L_FRZ, "(%s, %d): set uid to 0 due to is_all!=0 and uid==BAD_LVE", username, is_all);
		uid = 0;
	}

	if (bad_list->item_count+1 == MAX_ITEMS_IN_TABLE)
	{
		LOG(L_FRZ, "(%s, %d): FAILED as must add it but NO SPACE", username, is_all);
		return -2;
	}

	int rc = governor_rwlock_timedwrlock(&bad_list->rwlock, 1);
	if (rc)
	{
		LOG(L_ERRSENTRY|L_FRZ, "failed to add to bad_list, username '%s', is_all=%d, timedwrlock()=%d", username, is_all, rc);
		return -3;
	}
	LOG(L_FRZ, "(%s, %d): adding it with uid %d to %ld pos", username, is_all, uid, bad_list->item_count);
	strlcpy(bad_list->items[bad_list->item_count].username, username, USERNAMEMAXLEN);
	bad_list->items[bad_list->item_count++].uid = uid;
	rc = pthread_rwlock_unlock(&bad_list->rwlock);
	if (rc)
		LOG(L_ERR|L_FRZ, "(%s, %d): pthread_rwlock_unlock()=%d", username, is_all, rc);

	return 0;
}

#endif // LIBGOVERNOR

int delete_user_from_list(const char *username)
{
	if (!bad_list || bad_list == MAP_FAILED)
		return -1;
	long i;
	for (i=0; i < bad_list->item_count; i++)
	{
		if (!strncmp(bad_list->items[i].username, username, USERNAMEMAXLEN-1))
		{
			int rc = governor_rwlock_timedwrlock(&bad_list->rwlock, 1);
			if (rc)
				LOG(L_ERRSENTRY|L_UNFRZ, "failed to delete from bad_list, username '%s', timedwrlock()=%d", username, rc);
			else
			{
				if (i < bad_list->item_count-1)
					memmove(bad_list->items + i,
							bad_list->items + (i + 1),
							sizeof(items_structure) * (bad_list->item_count - i - 1));
				bad_list->item_count--;
				rc = pthread_rwlock_unlock(&bad_list->rwlock);
				if (rc)
					LOG(L_ERR|L_UNFRZ, "pthread_rwlock_unlock()=%d", rc);
				return 0;
			}
		}
	}
	return -2;
}

int delete_allusers_from_list(void)
{
	if (!bad_list || bad_list == MAP_FAILED)
		return -1;

	int rc = governor_rwlock_timedwrlock(&bad_list->rwlock, 10);
	if (rc)
	{
		LOG(L_ERR|L_MON, "governor_rwlock_timedwrlock()=%d", rc);
		return -2;
	}
	clear_bad_users_list();
	rc = pthread_rwlock_unlock(&bad_list->rwlock);
	if (rc)
		LOG(L_ERR|L_MON, "pthread_rwlock_unlock()=%d", rc);
	return 0;
}

long get_users_list_size(void)
{
	if (!bad_list || bad_list == MAP_FAILED)
		return 0;
	return bad_list->item_count;
}

void printf_bad_users_list(void)
{
	if (!bad_list || bad_list == MAP_FAILED)
		return;
	long i;
	for (i=0; i < bad_list->item_count; i++)
		printf("%ld) user - %s, uid - %d\n", i, bad_list->items[i].username, bad_list->items[i].uid);
}

// Seems like not used. Not called form the MySQL patches, at least modern.
int32_t is_user_in_bad_list_client(const char *username)
{
	int shm_fd_clients = 0;
	int32_t fnd = 0;
	shm_structure *bad_list_clients;
	if ((shm_fd_clients = cl_shm_open(O_RDWR, 0600)) < 0)
	{
		return 0;
	}
	if ((bad_list_clients = (shm_structure *) cl_mmap(0, sizeof(shm_structure), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd_clients, 0)) == MAP_FAILED)
	{
		close(shm_fd_clients);
		return 0;
	}

	if (bad_list_clients)
	{
		int rc = governor_rwlock_timedrdlock(&bad_list_clients->rwlock, 1);
		if (rc)
			LOG(L_ERR|L_FRZ, "(%s): pthread_rwlock_rdlock()=%d", username, rc);
		else
		{
			long i;
			for (i=0; i < bad_list_clients->item_count; i++)
				if (!strncmp(bad_list_clients->items[i].username, username, USERNAMEMAXLEN))
				{
					fnd = bad_list_clients->items[i].uid;
					break;
				}
			rc = pthread_rwlock_unlock(&bad_list_clients->rwlock);
			if (rc)
				LOG(L_ERR|L_FRZ, "(%s): pthread_rwlock_unlock()=%d", username, rc);
		}
	}

	cl_munmap(bad_list_clients, sizeof(shm_structure));
	close(shm_fd_clients);
	return fnd;
}

int user_in_bad_list_client_show(void)
{
	int shm_fd_clients = 0;
	int fnd = 0;
	mode_t old_umask = umask(0);
	shm_structure *bad_list_clients;
	if ((shm_fd_clients = cl_shm_open(O_RDWR, 0600)) < 0)
	{
		umask(old_umask);
		return 0;
	}
	if ((bad_list_clients = (shm_structure *) cl_mmap(0, sizeof(shm_structure), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd_clients, 0)) == MAP_FAILED)
	{
		close(shm_fd_clients);
		umask(old_umask);
		return 0;
	}

	umask(old_umask);

	if (bad_list_clients)
	{
		int rc = governor_rwlock_timedrdlock(&bad_list_clients->rwlock, 10);
		if (rc)
			LOG(L_ERR|L_UNFRZ, "governor_rwlock_timedrdlock()=%d", rc);
		else
		{
			long i;
			for (i=0; i < bad_list_clients->item_count; i++)
				printf("%s\n", bad_list_clients->items[i].username);
			rc = pthread_rwlock_unlock(&bad_list_clients->rwlock);
			if (rc)
				LOG(L_ERR|L_UNFRZ, "pthread_rwlock_unlock()=%d", rc);
		}
	}

	cl_munmap(bad_list_clients, sizeof(shm_structure));
	close(shm_fd_clients);
	return fnd;
}

int shm_fd_clients_global = -1;
shm_structure *bad_list_clients_global = NULL;
pthread_mutex_t mtx_shared = PTHREAD_MUTEX_INITIALIZER;

int init_bad_users_list_client(void)
{
	mode_t old_umask = umask(0);
	pthread_mutex_lock(&mtx_shared);
	bool first = false, need_truncate = false;
	if ((shm_fd_clients_global = cl_shm_open((O_CREAT | O_EXCL | O_RDWR), 0600)) > 0)
	{
		first = true;
	}
	else if ((shm_fd_clients_global = cl_shm_open(O_RDWR, 0600)) < 0)
	{
		pthread_mutex_unlock(&mtx_shared);
		umask(old_umask);
		return -1;
	}
	else
	{
		struct stat file;
		if (cl_stat_shared_memory_file(&file) == 0)
		{
			if (file.st_size < sizeof(shm_structure))
				need_truncate = true;
		}
	}

	bad_list_clients_global = (shm_structure *) cl_mmap (0, sizeof(shm_structure), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd_clients_global, 0);

	if (bad_list_clients_global == MAP_FAILED)
	{
		close(shm_fd_clients_global);
		shm_fd_clients_global = -1;
		pthread_mutex_unlock(&mtx_shared);
		umask(old_umask);
		return -2;
	}

	if (first || need_truncate)
	{
		if (ftruncate(shm_fd_clients_global, sizeof(shm_structure)))
			LOG(L_ERR, "ftruncate() failed, errno=%d", errno);

		pthread_rwlockattr_t attr;
		int rc = pthread_rwlockattr_init(&attr);
		if (rc)
		{
			LOG(L_ERR, "pthread_rwlockattr_init()=%d", rc);
			goto fail;
		}
		rc = pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
		if (rc)
		{
			LOG(L_ERR, "pthread_rwlockattr_setpshared()=%d", rc);
			goto fail;
		}
		rc = pthread_rwlock_init(&bad_list_clients_global->rwlock, &attr);
		if (rc)
		{
			LOG(L_ERR, "pthread_rwlock_init()=%d", rc);
			goto fail;
		}
		goto end;
fail:
		cl_munmap(bad_list_clients_global, sizeof(shm_structure));
		bad_list_clients_global = NULL;
		close(shm_fd_clients_global);
		shm_fd_clients_global = -1;
		pthread_mutex_unlock(&mtx_shared);
		umask(old_umask);
		return -2;
end:	;
	}

	if (first)
	{
		int rc = pthread_rwlock_wrlock(&bad_list_clients_global->rwlock);
		if (rc)
			LOG(L_ERR, "pthread_rwlock_wrlock()=%d", rc);
		else
		{
			clear_bad_users_list();
			rc = pthread_rwlock_unlock(&bad_list_clients_global->rwlock);
			if (rc)
				LOG(L_ERR, "pthread_rwlock_unlock()=%d", rc);
		}
	}

	pthread_mutex_unlock(&mtx_shared);
	umask(old_umask);
	return 0;
}

/*
   As init_bad_users_list_client, but without
   creation, initiation and truncation
*/
int init_bad_users_list_client_without_init(void)
{
	pthread_mutex_lock(&mtx_shared);
	if ((shm_fd_clients_global = cl_shm_open(O_RDWR, 0600)) < 0)
	{
		pthread_mutex_unlock(&mtx_shared);
		return -1;
	}

	bad_list_clients_global = (shm_structure *)cl_mmap(0, sizeof(shm_structure), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd_clients_global, 0);

	if (bad_list_clients_global == MAP_FAILED)
	{
		close(shm_fd_clients_global);
		shm_fd_clients_global = -1;
		pthread_mutex_unlock(&mtx_shared);
		return -2;
	}

	pthread_mutex_unlock(&mtx_shared);
	return 0;
}

int remove_bad_users_list_client(void)
{
	pthread_mutex_lock(&mtx_shared);
	if (bad_list_clients_global && bad_list_clients_global != MAP_FAILED)
		cl_munmap(bad_list_clients_global, sizeof(shm_structure));
	if (shm_fd_clients_global >= 0)
	{
		close(shm_fd_clients_global);
	}
	pthread_mutex_unlock(&mtx_shared);
	return 0;
}

int32_t is_user_in_bad_list_client_persistent(const char *username)
{
	int32_t fnd = -1;

	if (!bad_list_clients_global || bad_list_clients_global == MAP_FAILED)
	{
		LOG(L_ERR|L_LVE, "(%s): FAILED as bad_list is not inited: %p", username, bad_list_clients_global);
		return fnd;
	}

	LOG(L_LVE, "(%s): before search from %ld num", username, bad_list_clients_global->item_count);

	int rc = governor_rwlock_timedrdlock(&bad_list_clients_global->rwlock, 1);
	if (rc)
		LOG(L_ERRSENTRY|L_LVE, "failed to check bad_list, username '%s', timedrdlock()=%d", username, rc);
	else
	{
		bool found = false;
		long i;
		for (i=0; i < bad_list_clients_global->item_count; i++)
		{
			LOG(L_LVE, "(%s): %ld/%ld before check against(%s)", username, i, bad_list_clients_global->item_count, bad_list_clients_global->items[i].username);
			if (!strncmp(bad_list_clients_global->items[i].username, username, USERNAMEMAXLEN))
			{
				fnd = bad_list_clients_global->items[i].uid;
				found = true;
				LOG(L_LVE, "(%s): %ld/%ld FOUND - uid %d", username, i, bad_list_clients_global->item_count, fnd);
				break;
			}
		}
		rc = pthread_rwlock_unlock(&bad_list_clients_global->rwlock);
		if (rc)
			LOG(L_ERR|L_LVE, "pthread_rwlock_unlock()=%d", rc);
		if (!found)
		{
			fnd = 0;
			LOG(L_LVE, "(%s): cannot find it in bad_list", username);
		}
	}

	return fnd;
}

void printf_bad_list_client_persistent(void)
{
	printf(" USER             NUMBER\n");
	if (bad_list_clients_global && bad_list_clients_global != MAP_FAILED)
	{
		int rc = governor_rwlock_timedrdlock(&bad_list_clients_global->rwlock, 10);
		if (rc)
			LOG(L_ERR|L_DBTOP, "governor_rwlock_timedrdlock()=%d", rc);
		else
		{
			long i;
			for (i=0; i < bad_list_clients_global->item_count; i++)
				printf(" %-16s %ld\n", bad_list_clients_global->items[i].username, i);
			rc = pthread_rwlock_unlock(&bad_list_clients_global->rwlock);
			if (rc)
				LOG(L_ERR|L_DBTOP, "pthread_rwlock_unlock()=%d", rc);
		}
	}
}

