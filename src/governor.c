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
#include <sys/wait.h>
#include <dirent.h>
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
#include "wrappers.h"
#include "tid_table.h"
#include "parce_proc_fs.h"
#include "log.h"
#include "governor_config.h"
#include "calc_stats.h"
#include "tick_generator.h"
#include "governor_server.h"
#include "mysql_connector_common.h"
#include "commands.h"
#include "dbtop_server.h"
#include "shared_memory.h"
#include "dbuser_map.h"
#include "slow_queries.h"
#include "version.h"

#ifdef SYSTEMD_FLAG
#include <systemd/sd-daemon.h>
#endif

#define BUF_SIZE_III 100

#define MACRO_CHECK_ZERO(x)			if (!st->x._current)	LOG(L_ERR, "default " # x "  = 0")
#define MACRO_CHECK_ZERO_SHORT(x)	if (!st->x._short)		LOG(L_ERR, "short default " # x "  = 0")
#define MACRO_CHECK_ZERO_MID(x)		if (!st->x._mid)		LOG(L_ERR, "mid default " # x "  = 0")
#define MACRO_CHECK_ZERO_LONG(x)	if (!st->x._long)		LOG(L_ERR, "long default " # x "  = 0")

/* Lock a file region (private; public interfaces below) */

static int lockReg_III(int fd_III, int cmd_III, int type_III, int whence_III,
		int start_III, off_t len_III)
{
	struct flock fl;

	fl.l_type = type_III;
	fl.l_whence = whence_III;
	fl.l_start = start_III;
	fl.l_len = len_III;

	return fcntl(fd_III, cmd_III, &fl);
}

int /* Lock a file region using nonblocking F_SETLK */
lockRegion_III(int fd_III, int type_III, int whence_III, int start_III,
		int len_III)
{
	return lockReg_III(fd_III, F_SETLK, type_III, whence_III, start_III,
			len_III);
}

int /* Lock a file region using blocking F_SETLKW */
lockRegionWait_III(int fd_III, int type_III, int whence_III, int start_III,
		int len_III)
{
	return lockReg_III(fd_III, F_SETLKW, type_III, whence_III, start_III,
			len_III);
}

/* Test if a file region is lockable. Return 0 if lockable, or
 PID of process holding incompatible lock, or -1 on error. */

pid_t regionIsLocked_III(int fd_III, int type_III, int whence_III,
		int start_III, int len_III)
{
	struct flock fl;

	fl.l_type = type_III;
	fl.l_whence = whence_III;
	fl.l_start = start_III;
	fl.l_len = len_III;

	if (fcntl(fd_III, F_GETLK, &fl) == -1)
		return -1;

	return (fl.l_type == F_UNLCK) ? 0 : fl.l_pid;
}

int createPidFile_III(const char *pidFile_III, int flags_III)
{
	char buffer[_DBGOVERNOR_BUFFER_2048];
	int fd;
	char buf[BUF_SIZE_III];

	fd = open(pidFile_III, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1)
	{
		return -1;
	}

	/* Set the close-on-exec file descriptor flag */

	/* Instead of the following steps, we could (on Linux) have opened the
	 file with O_CLOEXEC flag. However, not all systems support open()
	 O_CLOEXEC (which was only standardized in SUSv4), so instead we use
	 fcntl() to set the close-on-exec flag after opening the file */

	flags_III = fcntl(fd, F_GETFD); /* Fetch flags */
	if (flags_III == -1)
	{
		close(fd);
		return -1;
	}

	flags_III |= FD_CLOEXEC; /* Turn on FD_CLOEXEC */

	if (fcntl(fd, F_SETFD, flags_III) == -1) /* Update flags */
	{
		close(fd);
		return -1;
	}

	if (lockRegion_III(fd, F_WRLCK, SEEK_SET, 0, 0) == -1)
	{
		close(fd);
		return -1;
	}

	if (ftruncate(fd, 0) == -1)
	{
		close(fd);
		return -1;
	}

	snprintf(buf, BUF_SIZE_III, "%ld\n", (long) getpid());
	if (write(fd, buf, strlen(buf)) != strlen(buf))
	{
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

void becomeDaemon(int self_supporting)
{
	struct governor_config data_cfg;

	get_config_data(&data_cfg);

	/* Start daemon */
	if (self_supporting)
	{
		switch (fork())
		{
			case -1:
				fprintf(stderr, "Can't start daemon\n");
				fflush(stderr);
				exit(EXIT_FAILURE);
				break;
			case 0:
				break;
			default:
				config_free();
				_exit(EXIT_SUCCESS);
				break;
		}
	}

#ifndef SYSTEMD_FLAG
	/* Set session leader */
	if (setsid() == -1)
	{
		LOG(L_ERR, "Can't start setsid");
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		fprintf(stderr, "Can't start setsid\n");
		fflush(stderr);
		exit(EXIT_FAILURE);
	}
#endif
	/* Create new daemon as session leader */
	if (self_supporting)
	{
		switch (fork())
		{
			case -1:
				LOG(L_ERR, "Can't start daemon");
				close_log();
				close_restrict_log();
				close_slow_queries_log();
				config_free();
				fprintf(stderr, "Can't start daemon\n");
				fflush(stderr);
				exit(EXIT_FAILURE);
				break;
			case 0:
				break;
			default:
				config_free();
				_exit(EXIT_SUCCESS);
				break;
		}
	}
	umask(0);
	if ((chdir("/")) < 0)
	{
		LOG(L_ERR, "Child chdir error");
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		fprintf(stderr, "Child chdir error\n");
		fflush(stderr);
		exit(EXIT_FAILURE);
	}
	/* Create pid file of programm */
	if (createPidFile_III(PID_PATH, 0) == -1)
	{
		LOG(L_ERR, "Unable to create PID file");
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		fprintf(stderr, "Unable to create PID file\n");
		fflush(stderr);
		exit(EXIT_FAILURE);
	}

	int fd;
	const char * fd_dname = "/proc/self/fd/";
	struct dirent * fd_dp;
	DIR * fd_dir = opendir(fd_dname);

	/* Go through /proc/<cur-pid>/fd/ directory to find out
	** all open descriptors and close them (except of logs)
	*/
	if (fd_dir)
	{
		while ((fd_dp = readdir(fd_dir)) != NULL)
		{
			fd = atoi(fd_dp->d_name);
			if (!fd)
			{
				continue;
			}

			if (get_log())
			{
					FILE *tmp_fd = get_log();
					if (fd == fileno(tmp_fd))
						continue;
			}
			if (get_restrict_log())
			{
					FILE *tmp_fd = get_restrict_log();
					if (fd == fileno(tmp_fd))
						continue;
			}
			if (get_slow_queries_log())
			{
					FILE *tmp_fd = get_slow_queries_log();
					if (fd == fileno(tmp_fd))
						continue;
			}
			close(fd);
		}
		closedir(fd_dir);
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	open("/dev/null", O_RDONLY);
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);
}

int install_signals_handlers(void)
{
	signal(SIGPIPE, SIG_IGN);
	//Since we can create childs of the demon, we would need to close them correctly
	//sigset (SIGCHLD, &whenchildwasdie);
	//Option, give the child to the init process
	signal(SIGCHLD, SIG_IGN);
	return 0;
}

void check_for_zero(stats_limit_cfg * st)
{
	MACRO_CHECK_ZERO (cpu);
	MACRO_CHECK_ZERO (read);
	MACRO_CHECK_ZERO (write);

	MACRO_CHECK_ZERO_SHORT (cpu);
	MACRO_CHECK_ZERO_SHORT (read);
	MACRO_CHECK_ZERO_SHORT (write);

	MACRO_CHECK_ZERO_MID (cpu);
	MACRO_CHECK_ZERO_MID (read);
	MACRO_CHECK_ZERO_MID (write);

	MACRO_CHECK_ZERO_LONG (cpu);
	MACRO_CHECK_ZERO_LONG (read);
	MACRO_CHECK_ZERO_LONG (write);
}

#ifndef NOGOVERNOR

static void print_long_cfg(FILE *f, T_LONG val)
{
	fprintf(f, "current = %ld", val._current);
	if (val._short >= 0)
		fprintf(f, ", short = %ld", val._short);
	if (val._mid >= 0)
		fprintf(f, ", mid = %ld", val._mid);
	if (val._long >= 0)
		fprintf(f, ", long = %ld", val._long);
	fprintf(f, "\n");
}

static void print_stats_cfg(FILE *f, const stats_limit_cfg *s)
{
	fprintf(f, "cpu ");
	print_long_cfg(f, s->cpu);
	fprintf(f, "read ");
	print_long_cfg(f, s->read);
	fprintf(f, "write ");
	print_long_cfg(f, s->write);
}

static void print_account_limits(gpointer key, gpointer value, gpointer user_data)
{
	FILE *log = get_log();
	fprintf(log, "%s -- ", (const char *) key);
	print_stats_cfg(log, value);
	fprintf(log, "\n");
}

static void print_config(const void *icfg)
{
	const struct governor_config *cfg = (const struct governor_config *) icfg;
	FILE *log = get_log();
	if ((cfg->log_mode == DEBUG_MODE) && (log != NULL))
	{
		char buffer[512] = { 0 };
		fprintf(log, "db_login %s\n", cfg->db_login);
		fprintf(log, "db_password %s\n", cfg->db_password);
		fprintf(log, "host %s\n", cfg->host);
		fprintf(log, "log %s\n", cfg->log);
		fprintf(log, "log_mode %s\n", mode_type_enum_to_str(cfg->log_mode, buffer, sizeof(buffer)-1));
		fprintf(log, "restrict_log %s\n", cfg->restrict_log);
		fprintf(log, "separator %c\n", cfg->separator);
		fprintf(log, "level1 %u, level2 %u, level3 %u, level4 %u\n",
			cfg->level1, cfg->level2, cfg->level3, cfg->level4);
		fprintf(log, "timeout %u\n", cfg->timeout);
		fprintf(log, "interval_short %u\n", cfg->interval_short);
		fprintf(log, "interval_mid %u\n", cfg->interval_mid);
		fprintf(log, "interval_long %u\n", cfg->interval_long);
		fprintf(log, "restrict log format %u\n", cfg->restrict_format);

		fprintf(log, "\ndefault\n");
		print_stats_cfg(log, &cfg->default_limit);

		g_hash_table_foreach(cfg->account_limits, (GHFunc) print_account_limits, "");
		fprintf(log, "\n");
	}
}

static void prepare_log_for_mysqld(const struct governor_config *cfg, const char *path)
{
	uid_t mysql_uid = get_mysql_uid();
	gid_t mysql_gid = get_mysql_gid();
	if (mysql_uid == UNINITED_UID || mysql_gid == UNINITED_GID)	// possibly not inited yet
	{
		init_mysql_uidgid();
		mysql_uid = get_mysql_uid();
		mysql_gid = get_mysql_gid();
	}
	if (mysql_uid == UNINITED_UID || mysql_gid == UNINITED_GID)
	{
		LOG(L_ERR|L_LIFE, "can't check '%s' file: possibly 'mysql' user doesn't exist. Please install MySQL and restart Governor", path);
		goto fail;
	}
	mode_t required_mode = S_IRUSR|S_IWUSR|S_IRGRP;
	struct stat st;
	bool exists = !stat(path, &st);
	if (exists && S_ISDIR(st.st_mode))
	{
		LOG(L_ERR|L_LIFE, "failed to create '%s': directory exists at this path. Please remove the directory", path);
		goto fail;
	}
	bool createdNow = false;
	if (!exists)
	{
		LOG(L_LIFE, "'%s' not found, creating", path);
		int fd = open(path, O_CREAT|O_WRONLY, required_mode);
		if (fd < 0)
		{
			LOG(L_ERR|L_LIFE, "failed to create '%s', errno=%d", path, errno);
			goto fail;
		}
		close(fd);
		exists = !stat(path, &st);
		if (!exists)
		{
			LOG(L_ERR|L_LIFE, "failed to create '%s'", path);
			goto fail;
		}
		createdNow = true;
	}
	if (st.st_uid != mysql_uid || st.st_gid != mysql_gid)
	{
		if (!createdNow)
			LOG(L_LIFE, "'%s' has wrong owner, changing UID %u->%u, GID %u->%u", path, (unsigned)st.st_uid, (unsigned)mysql_uid, (unsigned)st.st_gid, (unsigned)mysql_gid);
		if (chown(path, mysql_uid, mysql_gid))
		{
			LOG(L_ERR|L_LIFE, "chown() failed, errno=%d", errno);
			goto fail;
		}
	}
	if ((st.st_mode & required_mode) != required_mode)
	{
		LOG(L_LIFE, "'%s' has wrong mode, changing %o->%o", path, (unsigned)st.st_mode, (unsigned)required_mode);
		if (chmod(path, required_mode))
		{
			LOG(L_ERR|L_LIFE, "chmod() failed, errno=%d", errno);
			goto fail;
		}
	}
	return;
fail:
	LOG(L_LIFE, "make sure that '%s' file exists and has proper ownership (mysql.mysql) and permissions (0%o)", path, (unsigned)required_mode);
}

void initGovernor(void)
{
	// init global structures
	if (!config_init(CONFIG_PATH))
	{
		fprintf(stderr, "Unable to read config file: %s\n", CONFIG_PATH);
		fflush(stderr);
		exit(EXIT_FAILURE);
	}

	// Set signal handlers
	if (install_signals_handlers() < 0)
	{
		fprintf(stderr, "Can't install signal catcher\n");
		fflush(stderr);
		config_free();
		exit(EXIT_FAILURE);
	}

	struct governor_config data_cfg;
	get_config_data(&data_cfg);

	// Open error log
	if (open_log(data_cfg.log))
	{
		fprintf(stderr, "Can't open log file\n");
		fflush(stderr);
		config_free();
		exit(EXIT_FAILURE);
	}
	print_config(&data_cfg);

	check_for_zero(&data_cfg.default_limit);

	// Open restrict log if exists
	if (data_cfg.restrict_log)
		open_restrict_log(data_cfg.restrict_log);

	// Open slow queries log if exists
	if (data_cfg.slow_queries_log)
		open_slow_queries_log(data_cfg.slow_queries_log);

	// Setup logging - enable tags, etc.
	init_log_ex(data_cfg.log_mode == DEBUG_MODE);

	// When "mysqld" calls "libgovernor.so" functions,
	// they try to write to a separate log, "/var/log/dbgovernor-mysqld.log".
	// But "mysqld" doesn't have rights to create files in "/var/log/".
	// We need to ensure that there exists such a file with proper permissisons.
	prepare_log_for_mysqld(&data_cfg, MYSQLD_EXTLOG_PATH);
}

void trackingDaemon(void)
{
	int status = 0;
	becomeDaemon(0);

bg_loop: ;
	config_destroy_lock();
	config_free();
	initGovernor();


	pid_t pid_daemon = fork();

	if (pid_daemon > 0)
	{
		// config_free();
		wait(&status);

		LOG(L_ERR, "Failed governor daemon, restart daemon");

		int max_file_descriptor = sysconf(FOPEN_MAX), file_o;
		struct stat buf_stat;

		for (file_o = 2; file_o < max_file_descriptor; file_o++)
		{
			if (!fstat(file_o, &buf_stat))
			{
				close(file_o);
			}
		}
		sleep(60);
		goto bg_loop;
	}
}

int main(int argc, char *argv[])
{
	int ret;
	pthread_t thread, thread_governor, thread_dbtop, thread_prcd,
			thread_user_map, thread_slow_query, therad_renew_dbusermap;
	int only_print = 0;

	struct governor_config data_cfg;

	if (argc > 1)
	{
		if (strcmp(argv[argc - 1], "-v") == 0 || strcmp(argv[argc - 1],
				"--version") == 0) {
			printf("governor-mysql version %s\n", GOVERNOR_CUR_VER);
			exit(0);
		} else if (strcmp(argv[argc - 1], "-c") == 0 || strcmp(argv[argc - 1],
				"--config") == 0)
		{
			only_print = 1;
		} else
		{
			printf("governor-mysql starting error\n");
			exit(-1);
		}
	}

#ifndef TEST
	config_destroy_lock();
	initGovernor();
	get_config_data(&data_cfg);

	if (only_print)
	{
		if (geteuid() == 0)
		{
			print_config_full();
		} else
		{
			printf("governor-mysql version %s\n", GOVERNOR_CUR_VER);
		}
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		exit(0);
	}

#ifdef SYSTEMD_FLAG
	becomeDaemon (0);
	sd_notify (0, "READY=1");
#else
	if (data_cfg.daemon_monitor)
	{
		if (fork() == 0)
			trackingDaemon();
		else
			exit(EXIT_SUCCESS);
	} else
	{
		becomeDaemon(1);
	}
#endif
#else
	config_destroy_lock ();
	initGovernor ();
	get_config_data (&data_cfg);
	umask (0);
	if ((chdir ("/")) < 0)
	{
		LOG(L_ERR, "Child chdir error");
		close_log ();
		close_restrict_log ();
		close_slow_queries_log ();
		config_free ();
		fprintf (stderr, "Child chdir error\n");
		fflush (stderr);
		exit (EXIT_FAILURE);
	}
#endif

	get_config_data(&data_cfg);
	if (init_mysql_function() < 0)
	{
		LOG(L_ERR|L_MYSQL, "Can't load mysql functions");
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		exit(EXIT_FAILURE);
	}

	int trying_to_connect = 0;
	while (1)
	{
		get_config_data(&data_cfg);
		if (db_connect(data_cfg.host, data_cfg.db_login, data_cfg.db_password,
			"information_schema", argc, argv) < 0)
		{
			trying_to_connect++;
			if (trying_to_connect > 3)
			{
				LOG(L_ERR|L_MYSQL, "Can't connect to mysql. Please check that mysql is running otherwise"
				" check host, login and password in /etc/container/mysql-governor.xml file");
				/* To avoid too frequent service restart when mysql is not available */
				sleep(60);
				delete_mysql_function();
				close_log();
				close_restrict_log();
				close_slow_queries_log();
				config_free();
				remove("/usr/share/lve/dbgovernor/governor_connected");
				exit(EXIT_FAILURE);
			} else
			{
				LOG(L_ERR|L_MYSQL, "Can't connect to mysql. Try to reconnect");
				/* To avoid too frequent reconnect tries when mysql is not available */
				sleep(20);
			}
		} else
		{
			LOG(L_LIFE|L_MYSQL, "Governor successfully connected to mysql");
			creat("/usr/share/lve/dbgovernor/governor_connected", 0600);
			break;
		}
	}

	get_config_data(&data_cfg);
	if (!check_mysql_version())
	{
		LOG(L_ERR, "Incorrect mysql version");
		db_close();
		delete_mysql_function();
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		remove("/usr/share/lve/dbgovernor/cll_lve_installed");
		exit(EXIT_FAILURE);
	} else
	{
		creat("/usr/share/lve/dbgovernor/cll_lve_installed", 0600);
	}

	//unfreeze_all();
	//unfreeze_lve();
	config_add_work_user(get_work_user());

	LOG(L_LIFE, "Started");
	LOG(L_LIFE, "Governor work without LVE (%s)", data_cfg.is_gpl ? "yes" : "no");

	init_tid_table();
	dbgov_init();
	init_accounts_and_users();
	//Work cycle
	create_socket();

	if (!activate_plugin())
	{
		if (!data_cfg.is_gpl)
		{
			remove_bad_users_list();
		}
		db_close();
		delete_mysql_function();
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		exit(EXIT_FAILURE);
	}

	if (!data_cfg.is_gpl)
	{
		if (init_bad_users_list() < 0)
		{
			LOG(L_ERR, "Can't init BAD list, work in monitor only mode");
			get_config()->use_lve = 0;
			governor_enable_reconn();
		}
		else
		{
			LOG(L_LIFE, "BAD list init successfully");
			governor_enable_reconn_lve();
		}
	}
	else
	{
		LOG(L_LIFE, "No LVE, work in monitor only mode");
		governor_enable_reconn();
	}

	LOG(L_LIFE|L_DMN, "creating thread");
	ret = pthread_create(&thread, NULL, get_data_from_client, NULL);
	if (ret >= 0)
		LOG(L_LIFE|L_DMN, "thread created");
	else
	{
		LOG(L_ERR|L_LIFE|L_DMN, "failed to create thread, exiting");
		if (!data_cfg.is_gpl)
		{
			remove_bad_users_list();
		}
		db_close();
		delete_mysql_function();
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		exit(EXIT_FAILURE);
	}

	LOG(L_LIFE|L_SRV, "creating thread");
	ret = pthread_create(&thread_governor, NULL, send_governor, NULL);
	if (ret >= 0)
		LOG(L_LIFE|L_SRV, "thread created");
	else
	{
		LOG(L_ERR|L_LIFE|L_SRV, "failed to create thread, exiting");
		pthread_cancel(thread);
		if (!data_cfg.is_gpl)
		{
			remove_bad_users_list();
		}
		db_close();
		delete_mysql_function();
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		exit(EXIT_FAILURE);
	}

	LOG(L_LIFE|L_DBTOP, "creating thread");
	ret = pthread_create(&thread_dbtop, NULL, run_server, NULL);
	if (ret >= 0)
		LOG(L_LIFE|L_DBTOP, "thread created");
	else
	{
		LOG(L_ERR|L_LIFE|L_DBTOP, "failed to create thread, exiting");
		pthread_cancel(thread);
		pthread_cancel(thread_governor);
		if (!data_cfg.is_gpl)
		{
			remove_bad_users_list();
		}
		db_close();
		delete_mysql_function();
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		exit(EXIT_FAILURE);
	}

	LOG(L_LIFE|L_MON, "creating thread");
	ret = pthread_create(&thread_prcd, NULL, process_data_every_second, NULL);
	if (ret >= 0)
		LOG(L_LIFE|L_MON, "thread created");
	else
	{
		LOG(L_ERR|L_LIFE|L_MON, "failed to create thread, exiting");
		pthread_cancel(thread);
		pthread_cancel(thread_governor);
		pthread_cancel(thread_dbtop);
		if (!data_cfg.is_gpl)
		{
			remove_bad_users_list();
		}
		db_close();
		delete_mysql_function();
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		exit(EXIT_FAILURE);
	}

	LOG(L_LIFE|L_USRMAP, "creating thread");
	ret = pthread_create(&thread_user_map, NULL, parse_map_file_every_hour, NULL);
	if (ret >= 0)
		LOG(L_LIFE|L_USRMAP, "thread created");
	else
	{
		LOG(L_ERR|L_LIFE|L_USRMAP, "failed to create thread, exiting");
		pthread_cancel(thread);
		pthread_cancel(thread_governor);
		pthread_cancel(thread_dbtop);
		pthread_cancel(thread_prcd);
		if (!data_cfg.is_gpl)
		{
			remove_bad_users_list();
		}
		db_close();
		delete_mysql_function();
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		exit(EXIT_FAILURE);
	}

	if (data_cfg.slow_queries)
	{
		LOG(L_LIFE|L_SLOW, "creating thread");
		ret = pthread_create(&thread_slow_query, NULL, parse_slow_query, NULL);
		if (ret >= 0)
			LOG(L_LIFE|L_SLOW, "thread created");
		else
		{
			LOG(L_ERR|L_LIFE|L_SLOW, "failed to create thread, exiting");
			pthread_cancel(thread);
			pthread_cancel(thread_governor);
			pthread_cancel(thread_dbtop);
			pthread_cancel(thread_prcd);
			pthread_cancel(thread_user_map);
			if (!data_cfg.is_gpl && data_cfg.use_lve)
			{
				remove_bad_users_list();
			}
			db_close();
			delete_mysql_function();
			close_log();
			close_restrict_log();
			close_slow_queries_log();
			config_free();
			exit(EXIT_FAILURE);
		}
	}


	LOG(L_LIFE|L_USRMAPRQ, "creating thread");
	ret = pthread_create(&therad_renew_dbusermap, NULL, renew_map_on_request, NULL);
	if (ret >= 0)
		LOG(L_LIFE|L_USRMAPRQ, "thread created");
	else
	{
		LOG(L_ERR|L_LIFE|L_USRMAPRQ, "failed to create thread, exiting");
		pthread_cancel(thread);
		pthread_cancel(thread_governor);
		pthread_cancel(thread_dbtop);
		pthread_cancel(thread_prcd);
		pthread_cancel(thread_user_map);
		if (data_cfg.slow_queries)
		{
			pthread_cancel(thread_slow_query);
		}
		if (!data_cfg.is_gpl && data_cfg.use_lve)
		{
			remove_bad_users_list();
		}
		db_close();
		delete_mysql_function();
		close_log();
		close_restrict_log();
		close_slow_queries_log();
		config_free();
		exit(EXIT_FAILURE);
	}


	pthread_detach(thread_governor);
	pthread_detach(thread_dbtop);
	pthread_detach(thread_prcd);
	pthread_detach(thread_user_map);
	if (data_cfg.slow_queries) {
		pthread_detach(thread_slow_query);
	}
	pthread_detach(therad_renew_dbusermap);
	pthread_join(thread, NULL);
	LOG(L_LIFE|L_DMN, "thread finished, exiting");

	pthread_cancel(thread_governor);
	pthread_cancel(thread_dbtop);
	pthread_cancel(thread_prcd);
	pthread_cancel(thread_user_map);
	if (data_cfg.slow_queries)
	{
		pthread_cancel(thread_slow_query);
	}
	pthread_cancel(therad_renew_dbusermap);
	if (!data_cfg.is_gpl)
	{
		remove_bad_users_list();
	}

	restore_all_max_user_conn(data_cfg.log_mode);
	free_accounts_and_users();
	free_tid_table();

	LOG(L_LIFE, "Stopped");
	db_close();
	delete_mysql_function();
	close_log();
	close_restrict_log();
	close_slow_queries_log();
	config_free();

	return 0;
}

#endif
