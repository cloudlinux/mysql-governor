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
#include <semaphore.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>

#include "log.h"
#include "data.h"
#include "dbgovernor_string_functions.h"
#include "shared_memory.h"
#include "dbuser_map.h"

//#ifdef TEST
#include <sys/syscall.h>
#include <stdarg.h>
//#endif

#define MAX_ITEMS_IN_TABLE 100000

#define SHARED_MEMORY_NAME_PRIVATE "/var/lve/dbgovernor-shm/governor_bad_users_list"

/*
    Custom cl_shm_open is used, instead of system shm_open,
    and bad users list will be located in the custom location -
    /var/lve/dbgovernor-shm instead of /dev/shm
*/
static const char *shared_memory_name = SHARED_MEMORY_NAME_PRIVATE;

#define cl_stat_shared_memory_file(st) stat(shared_memory_name, (st))

int cl_shm_open (int oflag, mode_t mode)
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

typedef struct __items_structure {
	char username[USERNAMEMAXLEN];
	int32_t uid;
} items_structure;

typedef struct __shm_structure {
	sem_t sem;
	long numbers;
	items_structure items[MAX_ITEMS_IN_TABLE];
} shm_structure;

shm_structure *bad_list = NULL;
int shm_fd = -1;

int init_bad_users_list_utility(void) {

	if ((shm_fd = cl_shm_open((O_RDWR), 0600)) < 0) {
		return -1;
	}

	if ((bad_list = (shm_structure *) cl_mmap (0, sizeof (shm_structure),
			(PROT_READ | PROT_WRITE), MAP_SHARED,
			shm_fd, 0)) == MAP_FAILED) {
		close(shm_fd);
		shm_fd = -1;
		return -1;
	}

	if (sem_wait(&bad_list->sem) == 0) {
		clear_bad_users_list();
		sem_post(&bad_list->sem);
	}

	return 0;
}

int remove_bad_users_list_utility(void) {
	if (bad_list && (bad_list != MAP_FAILED))
	{
		cl_munmap ((void *) bad_list, sizeof (shm_structure));
	}
	if (shm_fd >= 0)
	{
		close(shm_fd);
		shm_fd = -1;
	}
	return 0;
}

/*
   uid/gid will not be changed by chown function with -1 value
   But POSIX says that their types are integer, no mention of signed or unsigned
   And on the Linux they are unsigned in fact
*/
#define UNINITED_UID ((uid_t)-1)
#define UNINITED_GID ((gid_t)-1)
static uid_t mysql_uid = UNINITED_UID;
static gid_t mysql_gid = UNINITED_GID;

static void init_mysql_uidgid(struct governor_config *cfg_ptr)
{
	struct passwd *passwd = getpwnam("mysql");
	if (passwd)
	{
		mysql_uid = passwd->pw_uid;
	}
	struct group *group = getgrnam("mysql");
	if (group)
	{
		mysql_gid = group->gr_gid;
	}
}

int init_bad_users_list(void) {
	//if(shared_memory_name) shm_unlink(shared_memory_name);
	//sem_unlink(SHARED_MEMORY_SEM);
	int rc;
	mode_t old_umask = umask(0);
	struct governor_config data_cfg;
	get_config_data(&data_cfg);

	if (mysql_uid == UNINITED_UID || mysql_gid == UNINITED_GID)
	{
		init_mysql_uidgid(&data_cfg);
	}
	int first = 0;
	if ((shm_fd = cl_shm_open((O_CREAT | O_EXCL | O_RDWR), 0600)) > 0)
	{
		first = 1;
	}
	else if ((shm_fd = cl_shm_open(O_RDWR, 0600)) < 0)
	{
		umask(old_umask);
		WRITE_LOG (NULL, 0, "cl_shm_open(%s) failed with %d code - EXITING",
				data_cfg.log_mode, shared_memory_name, errno);
		return -1;
	}
	else
	{
		struct stat file;
		if (cl_stat_shared_memory_file(&file) == 0)
		{
			first = file.st_size < sizeof(shm_structure) ? 1 : first;
		}
	}

	/* Make chown even if file existed before open - to fix possible previous errors */
	rc = fchown(shm_fd, mysql_uid, mysql_gid);
	if (rc)
	{
		WRITE_LOG (NULL, 0, "chown(%s, %d, %d) failed with %d code - IGNORING",
				data_cfg.log_mode, shared_memory_name, (int)mysql_uid, (int)mysql_gid, errno);
	}
	rc = fchmod(shm_fd, S_IRUSR | S_IWUSR);
	if (rc)
	{
		WRITE_LOG (NULL, 0, "chmod(%s, %o) failed with %d code - IGNORING",
				data_cfg.log_mode, shared_memory_name, S_IRUSR | S_IWUSR, errno);
	}

	if (first)
	{
		rc = ftruncate(shm_fd, sizeof(shm_structure));
		if (rc)
		{
			WRITE_LOG (NULL, 0, "truncate(%s, %u) failed with %d code - IGNORING",
					data_cfg.log_mode, shared_memory_name, (unsigned)sizeof(shm_structure), errno);
		}
	}

	if ((bad_list = (shm_structure *) cl_mmap (0, sizeof (shm_structure),
			(PROT_READ | PROT_WRITE), MAP_SHARED,
			shm_fd, 0)) == MAP_FAILED)
	{
		WRITE_LOG (NULL, 0, "cl_map(%s) failed with %d code - EXITING",
				data_cfg.log_mode, shared_memory_name, errno);
		close(shm_fd);
		shm_fd = -1;
		umask(old_umask);
		return -1;
	}

	if (first)
	{
		if (sem_init(&bad_list->sem, 1, 1) < 0)
		{
			WRITE_LOG (NULL, 0, "sem_init(%s) failed with %d code - EXITING",
					data_cfg.log_mode, shared_memory_name, errno);
			cl_munmap ((void *) bad_list, sizeof (shm_structure));
			close(shm_fd);
			shm_fd = -1;
			umask(old_umask);
			return -1;
		}
	}

	umask(old_umask);

	if (sem_wait(&bad_list->sem) == 0)
	{
		clear_bad_users_list();
		sem_post(&bad_list->sem);
	}

	return 0;
}

int init_bad_users_list_if_not_exitst(void) {
	if (!bad_list || (bad_list == MAP_FAILED)) {
		return init_bad_users_list();
	}
	return 0;
}

void clear_bad_users_list(void) {
	if (!bad_list || (bad_list == MAP_FAILED))
		return;
	bad_list->numbers = 0;
	memset((void *) bad_list->items, 0, sizeof(bad_list->items));
}

int remove_bad_users_list(void) {
	if (bad_list && (bad_list != MAP_FAILED))
	{
		cl_munmap ((void *) bad_list, sizeof (shm_structure));
	}
	if (shm_fd >= 0)
	{
		close(shm_fd);
		shm_fd = -1;
	}
	bad_list = NULL;
	return 0;
}

static int is_user_in_list(const char *username, struct governor_config *cfgptr) {
	if (!bad_list || (bad_list == MAP_FAILED))
	{
		FREEZE_EXT_LOG("%s(%s): EXIT as bad_list is NOT INITED %p", __FUNCTION__, username, bad_list);
		return -1;
	}
	long index;
	for (index = 0; index < bad_list->numbers; index++) {
		FREEZE_EXT_LOG("%s(%s): %ld/%ld: before check against(%s)", __FUNCTION__, username,
				index, bad_list->numbers, bad_list->items[index].username);
		if (!strncmp(bad_list->items[index].username, username, USERNAMEMAXLEN-1))
		{
			FREEZE_EXT_LOG("%s(%s): %ld/%ld: FOUND(%s)", __FUNCTION__, username,
					index, bad_list->numbers, bad_list->items[index].username);
			return 1;
		}
	}
	FREEZE_EXT_LOG("%s(%s): NOT FOUND from %ld", __FUNCTION__, username, bad_list->numbers);
	return 0;
}

#ifndef LIBGOVERNOR
int add_user_to_list(const char *username, int is_all) {
	struct governor_config data_cfg;
	get_config_data(&data_cfg);

	if (!bad_list || (bad_list == MAP_FAILED))
	{
		FREEZE_EXT_LOG("%s(%s, %d): FAILED as bad_list is NOT INITED %p", __FUNCTION__, username, is_all, bad_list);
		return -1;
	}

	// First check if the user is already in the list
	// before any locks and heavy operation on the map
	if (is_user_in_list(username, &data_cfg))
	{
		FREEZE_EXT_LOG("%s(%s, %d): EXIT as is_user_in_list FOUND it", __FUNCTION__, username, is_all);
		return 0;
	}

	int uid = BAD_LVE;
	if (lock_read_map() == 0) {
		uid = get_uid(username);
		unlock_rdwr_map();
		FREEZE_EXT_LOG("%s(%s, %d): get_uid ret %d", __FUNCTION__, username, is_all, uid);
	}
	else
	{
		FREEZE_EXT_LOG("%s(%s, %d): lock_read_map failed so NO CALL to get_uid and uid left BAD_LVE %d", __FUNCTION__, username, is_all, uid);
	}
	if (is_all && uid == BAD_LVE) {
		FREEZE_EXT_LOG("%s(%s, %d): set uid to 0 due to is_all!=0 and uid==BAD_LVE", __FUNCTION__, username, is_all);
		uid = 0;
	}

	if ((bad_list->numbers + 1) == MAX_ITEMS_IN_TABLE)
	{
		FREEZE_EXT_LOG("%s(%s, %d): FAILED as must add it but NO SPACE", __FUNCTION__, username, is_all);
		return -2;
	}

	if (sem_wait(&bad_list->sem) == 0) {
		FREEZE_EXT_LOG("%s(%s, %d): adding it with uid %d to %ld pos", __FUNCTION__, username, is_all, uid, bad_list->numbers);
		strlcpy(bad_list->items[bad_list->numbers].username, username, USERNAMEMAXLEN);
		bad_list->items[bad_list->numbers++].uid = uid;
		sem_post(&bad_list->sem);
	}
	else
	{
		FREEZE_EXT_LOG("%s(%s, %d): FAILED as must add it but sem_wait FAILED %d", __FUNCTION__, username, is_all, errno);
		return -3;
	}

	return 0;
}
#endif

int delete_user_from_list(char *username) {
	if (!bad_list || (bad_list == MAP_FAILED))
		return -1;
	long index;
	for (index = 0; index < bad_list->numbers; index++) {
		if (!strncmp(bad_list->items[index].username, username, USERNAMEMAXLEN-1)) {
			if (sem_wait(&bad_list->sem) == 0) {
				if (index == (bad_list->numbers - 1)) {
					bad_list->numbers--;
					sem_post(&bad_list->sem);
					return 0;
				} else {
					memmove(
							bad_list->items + index,
							bad_list->items + (index + 1),
							sizeof(items_structure) * (bad_list->numbers
									- index - 1));

					bad_list->numbers--;
					sem_post(&bad_list->sem);
					return 0;
				}
				//sem_post(sem);
			}
		}
	}
	return -2;
}

int delete_allusers_from_list(void) {
	if (!bad_list || (bad_list == MAP_FAILED))
		return -1;
	if (sem_wait(&bad_list->sem) == 0) {
		clear_bad_users_list();
		sem_post(&bad_list->sem);
		return 0;
	}
	return -2;
}

long get_users_list_size(void) {
	if (!bad_list || (bad_list == MAP_FAILED))
		return 0;
	return bad_list->numbers;
}

void printf_bad_users_list(void) {
	if (!bad_list || (bad_list == MAP_FAILED))
		return;
	long index;
	for (index = 0; index < bad_list->numbers; index++) {
		printf("%ld) user - %s, uid - %d\n", index,
				bad_list->items[index].username, bad_list->items[index].uid);
	}
	return;
}

int32_t is_user_in_bad_list_cleint(char *username) {
	int shm_fd_clents = 0;
	int32_t fnd = 0;
	shm_structure *bad_list_clents;
	if ((shm_fd_clents = cl_shm_open(O_RDWR, 0600)) < 0) {
		return 0;
	}
	if ((bad_list_clents
			= (shm_structure *) cl_mmap (0, sizeof (shm_structure),
					PROT_READ | PROT_WRITE, MAP_SHARED,
					shm_fd_clents,
					0)) == MAP_FAILED) {
		close(shm_fd_clents);
		return 0;
	}

	if (bad_list_clents) {
		int trys = 1;
		while (trys) {
			if (sem_trywait(&bad_list_clents->sem) == 0) {
				long index;
				for (index = 0; index < bad_list_clents->numbers; index++) {
					if (!strncmp(bad_list_clents->items[index].username,
							username,
							USERNAMEMAXLEN)) {
						fnd = bad_list_clents->items[index].uid;
						break;
					}
				}
				trys = 0;
				sem_post(&bad_list_clents->sem);
			} else {
				if (errno == EAGAIN) {
					trys++;
					if (trys == 400) {
						break;
					}
				} else {
					trys = 0;
				}

			}
		}
	}

	cl_munmap ((void *) bad_list_clents, sizeof (shm_structure));
	close(shm_fd_clents);
	return fnd;
}

int user_in_bad_list_cleint_show(void) {
	int shm_fd_clents = 0;
	int fnd = 0;
	mode_t old_umask = umask(0);
	shm_structure *bad_list_clents;
	if ((shm_fd_clents = cl_shm_open(O_RDWR, 0600)) < 0) {
		umask(old_umask);
		return 0;
	}
	if ((bad_list_clents
			= (shm_structure *) cl_mmap (0, sizeof (shm_structure),
					PROT_READ | PROT_WRITE, MAP_SHARED,
					shm_fd_clents,
					0)) == MAP_FAILED) {
		close(shm_fd_clents);
		umask(old_umask);
		return 0;
	}

	umask(old_umask);
	int trys = 1;

	if (bad_list_clents) {
		while (trys) {
			if (sem_trywait(&bad_list_clents->sem) == 0) {
				long index;
				for (index = 0; index < bad_list_clents->numbers; index++) {
					printf("%s\n", bad_list_clents->items[index].username);
				}
				trys = 0;
				sem_post(&bad_list_clents->sem);
			} else {
				if (errno == EAGAIN) {
					trys++;
					if (trys == 400)
						break;
				} else {
					trys = 0;
				}

			}
		}
	}

	cl_munmap ((void *) bad_list_clents, sizeof (shm_structure));
	close(shm_fd_clents);
	return fnd;
}

int shm_fd_clents_global = -1;
shm_structure *bad_list_clents_global = NULL;
pthread_mutex_t mtx_shared = PTHREAD_MUTEX_INITIALIZER;

int init_bad_users_list_client(void) {
	mode_t old_umask = umask(0);
	pthread_mutex_lock(&mtx_shared);
	int first = 0, need_truncate = 0;
	if ((shm_fd_clents_global = cl_shm_open((O_CREAT | O_EXCL | O_RDWR), 0600)) > 0)
	{
		first = 1;
	}
	else if ((shm_fd_clents_global = cl_shm_open(O_RDWR, 0600)) < 0)
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
                        need_truncate = file.st_size < sizeof(shm_structure) ? 1 : need_truncate;
		}
	}

	bad_list_clents_global = (shm_structure *) cl_mmap (0, sizeof(shm_structure), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd_clents_global, 0);

	if (bad_list_clents_global == MAP_FAILED)
	{
		close(shm_fd_clents_global);
		shm_fd_clents_global = -1;
		pthread_mutex_unlock(&mtx_shared);
		umask(old_umask);
		return -2;
	}

	if (first || need_truncate) {
		ftruncate(shm_fd_clents_global, sizeof(shm_structure));

		if (sem_init(&bad_list_clents_global->sem, 1, 1) < 0)
		{
			cl_munmap ((void *) bad_list_clents_global, sizeof (shm_structure));
			bad_list_clents_global = NULL;
			close(shm_fd_clents_global);
			shm_fd_clents_global = -1;
			pthread_mutex_unlock(&mtx_shared);
			return -2;
		}
	}

	if (first) {
		if (sem_wait(&bad_list_clents_global->sem) == 0) {
			clear_bad_users_list();
			sem_post(&bad_list_clents_global->sem);
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
int init_bad_users_list_client_without_init(void) {
	pthread_mutex_lock(&mtx_shared);
	if ((shm_fd_clents_global = cl_shm_open(O_RDWR, 0600)) < 0)
	{
		pthread_mutex_unlock(&mtx_shared);
		return -1;
	}

	bad_list_clents_global = (shm_structure *) cl_mmap (0, sizeof(shm_structure), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd_clents_global, 0);

	if (bad_list_clents_global == MAP_FAILED)
	{
		close(shm_fd_clents_global);
		shm_fd_clents_global = -1;
		pthread_mutex_unlock(&mtx_shared);
		return -2;
	}

	pthread_mutex_unlock(&mtx_shared);
	return 0;

}

int remove_bad_users_list_client(void) {
	pthread_mutex_lock(&mtx_shared);
	if (bad_list_clents_global && (bad_list_clents_global != MAP_FAILED))
		cl_munmap ((void *) bad_list_clents_global, sizeof (shm_structure));
	if (shm_fd_clents_global >= 0)
	{
		close(shm_fd_clents_global);
	}
	pthread_mutex_unlock(&mtx_shared);
	return 0;
}

int32_t is_user_in_bad_list_cleint_persistent(char *username) {
	int32_t fnd = -1;

	if (!bad_list_clents_global || (bad_list_clents_global == MAP_FAILED))
	{
		print_message_log("%s(%s): FAILED as bad_list is not inited: %p", __FUNCTION__, username, bad_list_clents_global);
		return fnd;
	}

	print_message_log("%s(%s): before search from %ld num", __FUNCTION__, username, bad_list_clents_global->numbers);
	int trys = 1;
	while (trys) {
		if (sem_trywait(&bad_list_clents_global->sem) == 0) {
			long index;
			int found = 0;
			for (index = 0; index < bad_list_clents_global->numbers; index++)
			{
				print_message_log("%s(%s): %ld/%ld before check against(%s)",
						__FUNCTION__, username, index, bad_list_clents_global->numbers, 
						bad_list_clents_global->items[index].username );
				if (!strncmp(bad_list_clents_global->items[index].username, username, USERNAMEMAXLEN))
				{
					fnd = bad_list_clents_global->items[index].uid;
					print_message_log("%s (%s): %ld/%ld FOUND - uid %d",
							    __FUNCTION__, username, index, bad_list_clents_global->numbers, fnd );
					found = 1;
					break;
				}
			}
			trys = 0;
			sem_post(&bad_list_clents_global->sem);
			if (!found)
			{
				fnd = 0;
				print_message_log("%s(%s): cannot find it in bad_list", __FUNCTION__, username);
			}
		}
		else {
			if (errno == EAGAIN) {
				trys++;
				if (trys == 400) {
					print_message_log("%s(%s): FAILED - %d failures to acquire semaphore", __FUNCTION__, username, trys);
					break;
				}
			} else {
				print_message_log("%s(%s): FAILED - sem_trywait failed with errno %d", __FUNCTION__, username, errno);
				trys = 0;
			}
		}
	}
	return fnd;
}

void printf_bad_list_cleint_persistent(void) {
	printf(" USER             NUMBER\n");

	if (bad_list_clents_global && (bad_list_clents_global != MAP_FAILED)) {
		int trys = 1;
		while (trys) {
			if (sem_trywait(&bad_list_clents_global->sem) == 0) {
				long index = 0;
				for (index = 0; index < bad_list_clents_global->numbers; index++) {
					printf(" %-16s %ld\n",
							bad_list_clents_global->items[index].username,
							index);
				}
				trys = 0;
				sem_post(&bad_list_clents_global->sem);
			} else {
				if (errno == EAGAIN) {
					trys++;
					if (trys == 400) {
						break;
					}
				} else {
					trys = 0;
				}

			}
		}
	}

	return;
}


static FILE *mysqld_message_log;

void governor_init_message_log(void)
{
    struct stat fstat;
    mysqld_message_log = stat("/usr/share/lve/dbgovernor/extlog-mysqld.flag", &fstat) ?
				NULL : fopen("/var/log/dbgovernor-debug.log","a");
}

void print_message_log(char *format, ...)
{
	char dt[20]; // space enough for DD/MM/YYYY HH:MM:SS and terminator
	struct tm tm;
	time_t current_time;
	char data[8192];
	va_list ptr;

	if (!mysqld_message_log)
		return;

	current_time = time(NULL);
	tm = *localtime(&current_time); // convert time_t to struct tm
	strftime(dt, sizeof dt, "%d/%m/%Y %H:%M:%S", &tm); // format

	va_start(ptr, format);
	vsprintf(data, format, ptr);
	va_end(ptr);
	fprintf(mysqld_message_log, "%s: PID %d TID %d %s\n", dt, getpid(), gettid_p(), data);
}

