/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef _GOVERNOR_CONFIG_H_
#define _GOVERNOR_CONFIG_H_ 1
#include <glib.h>
#include <stdio.h>
#include "xml.h"
#include "data.h"

struct governor_config
{
	char *db_login;
	char *db_password;
	stats_limit_cfg default_limit;
	GHashTable *account_limits;
	char *host;
	char *log;
	MODE_TYPE log_mode;
	char *restrict_log;
	char separator;
	unsigned level1, level2, level3, level4;	// in seconds
	unsigned timeout;		// in seconds
	unsigned interval_short;	// in seconds
	unsigned interval_mid;	// in seconds
	unsigned interval_long;	// in seconds
	char *training_log;
	unsigned training_interval;
	unsigned restrict_format;
	char *exec_script;
	int use_lve;
	int statistic_mode;
	int logqueries_use;
	int daemon_monitor;
	int max_user_connections;
	int killuser;
	int is_gpl;
	int separate_lve;
	int all_lve;
	int slow_queries;
	int restrict_mode;
	unsigned l_unlimit;		// in seconds
	char *slow_queries_log;
	char *debug_user;
	int save_statistic_uid;
	int improved_accuracy;

	pid_t sentry_pid;	   // PID of external sentry daemon
	char *sentry_dsn;	   // DSN for Sentry
	char *sentry_sock;	   // path to unix socket for external sentry daemon
	SENTRY_MODE sentry_mode;
};

stats_limit_cfg *config_get_account_limit (const char *account_id,
					stats_limit_cfg * cfgin);
void config_free (void);
struct governor_config *config_init (const char *path);
int save_duplicate_config (xml_data* xml);
void reread_config (void);
void config_destroy_lock (void);
void config_add_work_user (const char *user_name);
//struct governor_config * get_config();
void get_config_data (struct governor_config *data);
struct governor_config *get_config (void);
void print_config_full(void);
const char *mode_type_enum_to_str(MODE_TYPE tp, char *mode_str, size_t size);
void config_reset_sentry();
void config_set_sentry_pid(pid_t pid);

#endif
