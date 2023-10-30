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

#include "data.h"
#include "dbgovernor_string_functions.h"
#include "shared_memory.h"
#include "dbuser_map.h"

#ifdef TEST
#include <sys/syscall.h>
#include <stdarg.h>
#endif

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
int shm_fd = 0;

int init_bad_users_list_utility(void) {

	if ((shm_fd = cl_shm_open((O_RDWR), 0755)) < 0) {
		return -1;
	}

	if ((bad_list = (shm_structure *) cl_mmap (0, sizeof (shm_structure),
			(PROT_READ | PROT_WRITE), MAP_SHARED,
			shm_fd, 0)) == MAP_FAILED) {
		close(shm_fd);
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
	close(shm_fd);
	return 0;
}

int init_bad_users_list(void) {
	//if(shared_memory_name) shm_unlink(shared_memory_name);
	//sem_unlink(SHARED_MEMORY_SEM);
	mode_t old_umask = umask(0);

	int first = 0;
	if ((shm_fd = cl_shm_open((O_CREAT | O_EXCL | O_RDWR),
			0755)) > 0)
	{
		first = 1;
	}
	else if ((shm_fd = cl_shm_open(O_RDWR, 0755))
			< 0)
	{
		umask(old_umask);
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

	uid_t mysql_user_uid = 0;
	gid_t mysql_user_gid = 0;

	if (unix_socket_address)
	{
		// change permissions only for governor executable files
		struct stat socket_stat;
		if (stat(unix_socket_address, &socket_stat) == 0)
		{
			// find socket change owner and permissions for shared memory
			if (fchown(shm_fd, socket_stat.st_uid, socket_stat.st_gid) != 0)
			{
				// log error
				fprintf(stderr, "chown error: %s\n", strerror(errno));
			}
			else if (fchmod(shm_fd, 0600) != 0)
			{
				// log error
				fprintf(stderr, "chmod error: %s\n", strerror(errno));
			}
			mysql_user_uid = socket_stat.st_uid;
			mysql_user_gid = socket_stat.st_gid;
		}
		else
		{
			// log error - can`t find
			fprintf(stderr, "Use standard access to user's list\n");
		}
	}
	else
	{
		// change permissions only for governor executable files
		struct stat socket_stat;
		if (stat("/var/lib/mysql/mysql.sock", &socket_stat) == 0)
		{
			// find socket change owner and permissions for shared memory
			if (fchown(shm_fd, socket_stat.st_uid, socket_stat.st_gid) != 0)
			{
				// log error
				fprintf(stderr, "chown error: %s\n", strerror(errno));
			}
			else if (fchmod(shm_fd, 0600) != 0)
			{
				// log error
				fprintf(stderr, "chmod error: %s\n", strerror(errno));
			}
			mysql_user_uid = socket_stat.st_uid;
			mysql_user_gid = socket_stat.st_gid;
		}
		else
		{
			// log error - can`t find
			fprintf(stderr, "Use standard access to user's list\n");
		}
	}

	if (first)
	{
		ftruncate(shm_fd, sizeof(shm_structure));
	}

	if ((bad_list = (shm_structure *) cl_mmap (0, sizeof (shm_structure),
			(PROT_READ | PROT_WRITE), MAP_SHARED,
			shm_fd, 0)) == MAP_FAILED)
	{
		close(shm_fd);
		umask(old_umask);
		return -1;
	}

	if (first)
	{
		if (sem_init(&bad_list->sem, 1, 1) < 0)
		{
			cl_munmap ((void *) bad_list, sizeof (shm_structure));
			close(shm_fd);
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
	close(shm_fd);
	return 0;
}

int is_user_in_list(const char *username) {
	if (!bad_list || (bad_list == MAP_FAILED))
		return -1;
	long index;
	for (index = 0; index < bad_list->numbers; index++) {
		if (!strncmp(bad_list->items[index].username, username, USERNAMEMAXLEN))
			return 1;
	}
	return 0;
}

#ifndef LIBGOVERNOR
int add_user_to_list(const char *username, int is_all) {
	if (!bad_list || (bad_list == MAP_FAILED))
		return -1;
	int uid = BAD_LVE;
	if (lock_read_map() == 0) {
		uid = get_uid(username);
		unlock_rdwr_map();
	}
	if (is_all && uid == BAD_LVE) {
		uid = 0;
	}
	if (!is_user_in_list(username)) {
		if ((bad_list->numbers + 1) == MAX_ITEMS_IN_TABLE)
			return -2;
		if (sem_wait(&bad_list->sem) == 0) {
			strlcpy(bad_list->items[bad_list->numbers].username, username,
			USERNAMEMAXLEN);
			bad_list->items[bad_list->numbers++].uid = uid;
			sem_post(&bad_list->sem);
		}
	}
	return 0;
}
#endif

int delete_user_from_list(char *username) {
	if (!bad_list || (bad_list == MAP_FAILED))
		return -1;
	long index;
	for (index = 0; index < bad_list->numbers; index++) {
		if (!strncmp(bad_list->items[index].username, username, USERNAMEMAXLEN)) {
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
	if ((shm_fd_clents = cl_shm_open(O_RDWR, 0755)) < 0) {
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
	if ((shm_fd_clents = cl_shm_open(O_RDWR, 0755)) < 0) {
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

int shm_fd_clents_global = 0;
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

int remove_bad_users_list_client(void) {
	pthread_mutex_lock(&mtx_shared);
	if (bad_list_clents_global && (bad_list_clents_global != MAP_FAILED))
		cl_munmap ((void *) bad_list_clents_global, sizeof (shm_structure));
	close(shm_fd_clents_global);
	pthread_mutex_unlock(&mtx_shared);
	return 0;
}

int32_t is_user_in_bad_list_cleint_persistent(char *username) {
	print_message_log("GOVERNOR: is_user_in_bad_list_cleint_persistent user %s", username);
	int32_t fnd = 0;

	print_message_log("GOVERNOR: is_user_in_bad_list_cleint_persistent user %s map %p=%d",
				username, bad_list_clents_global, bad_list_clents_global != MAP_FAILED);
	if (bad_list_clents_global && (bad_list_clents_global != MAP_FAILED)) {
		print_message_log("GOVERNOR: is_user_in_bad_list_cleint_persistent user %s numbers %d",
                                       username, bad_list_clents_global->numbers);
		int trys = 1;
		while (trys) {
			if (sem_trywait(&bad_list_clents_global->sem) == 0) {
				long index = 0;
				for (index = 0; index < bad_list_clents_global->numbers; index++) {
					print_message_log("GOVERNOR: is_user_in_bad_list_cleint_persistent user %s user at index %d - %s, uid %d",
						username, index, bad_list_clents_global->items[index].username,
						bad_list_clents_global->items[index].uid);
					if (!strncmp(
							bad_list_clents_global->items[index].username,
							username, USERNAMEMAXLEN)) {
						fnd = bad_list_clents_global->items[index].uid;
						break;
					}
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

#ifdef TEST
#ifndef GETTID
pid_t gettid_p(void) {return syscall(__NR_gettid);}
#endif

void _print_message_log(char *format, ...)
{
	char data[8192];
	FILE *fp = fopen("/var/log/dbgovernor-debug.log","a");
	if(fp){

		char dt[20]; // space enough for DD/MM/YYYY HH:MM:SS and terminator
		struct tm tm;
		time_t current_time;

		current_time = time(NULL);
		tm = *localtime(&current_time); // convert time_t to struct tm
		strftime(dt, sizeof dt, "%d/%m/%Y %H:%M:%S", &tm); // format

		va_list ptr;
		va_start(ptr, format);
		vsprintf(data, format, ptr);
		va_end(ptr);
		fprintf(fp, "%s: TID %d %s\n", dt, gettid_p(), data);
		fclose(fp);
	}
}
#endif

