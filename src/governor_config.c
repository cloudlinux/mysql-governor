/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>

#include <dlfcn.h>

#include "governor_config.h"
#include "log.h"

pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

struct governor_config *cfg = NULL;

static void _set_val(T_LONG * limit, long *value)
{
	if (value[0] > 0 || value[0] == -1)
		limit->_current = value[0];
	if (value[1] > 0 || value[1] == -1)
		limit->_short = value[1];
	if (value[2] > 0 || value[2] == -1)
		limit->_mid = value[2];
	if (value[3] > 0 || value[3] == -1)
		limit->_long = value[3];
}

static MODE_TYPE mode_type_str_to_enum(const char *mode_str)
{
	if (mode_str == NULL)
	{
		fprintf(stderr, "Error: mode attribute is absent\n");
		exit(-1);
	}

	if (!strcasecmp(mode_str, "TEST"))
		return TEST_MODE;

	if (!strcasecmp(mode_str, "PRODUCTION"))
		return PRODUCTION_MODE;

	if (!strcasecmp(mode_str, "DEBUG"))
		return DEBUG_MODE;

	if (!strcasecmp(mode_str, "ERROR"))
		return ERROR_MODE;

	if (!strcasecmp(mode_str, "RESTRICT"))
		return RESTRICT_MODE;

	if (!strcasecmp(mode_str, "NORESTRICT"))
		return NORESTRICT_MODE;

	if (!strcasecmp(mode_str, "IGNORE"))
		return IGNORE_MODE;

	if (!strcasecmp(mode_str, "OLD"))
		return OLD_RESTRICT_MODE;

	if (!strcasecmp(mode_str, "NEW"))
		return NEW_RESTRICT_MODE;

	fprintf(stderr, "Error: invalid mode %s\n", mode_str);
	exit(-1);
}

const char * mode_type_enum_to_str(MODE_TYPE tp, char *mode_str, size_t size)
{
	if (tp == TEST_MODE)
	{
		snprintf(mode_str, size, "TEST");
		return mode_str;
	}
	if (tp == PRODUCTION_MODE)
	{
		snprintf(mode_str, size, "PRODUCTION");
		return mode_str;
	}
	if (tp == DEBUG_MODE)
	{
		snprintf(mode_str, size, "DEBUG");
		return mode_str;
	}
	if (tp == ERROR_MODE)
	{
		snprintf(mode_str, size, "ERROR");
		return mode_str;
	}
	if (tp == RESTRICT_MODE)
	{
		snprintf(mode_str, size, "RESTRICT");
		return mode_str;
	}
	if (tp == NORESTRICT_MODE)
	{
		snprintf(mode_str, size, "NORESTRICT");
		return mode_str;
	}
	if (tp == IGNORE_MODE)
	{
		snprintf(mode_str, size, "IGNORE");
		return mode_str;
	}
	if (tp == OLD_RESTRICT_MODE)
	{
		snprintf(mode_str, size, "OLD RESTRICT MODE");
		return mode_str;
	}
	if (tp == NEW_RESTRICT_MODE)
	{
		snprintf(mode_str, size, "NEW RESTRICT MODE");
		return mode_str;
	}
	snprintf(mode_str, size, "WOW!!!");
	return mode_str;
}

int getRestrictFormat(const char *mode)
{
	if (mode)
	{
		if (!strcasecmp(mode, "SHORT"))
			return 0;
		if (!strcasecmp(mode, "MEDIUM"))
			return 1;
		if (!strcasecmp(mode, "LONG"))
			return 2;
		if (!strcasecmp(mode, "VERYLONG"))
			return 3;
		if (!strcasecmp(mode, "CHECKTICKS"))
			return 4;
	}
	return 2;
}

static const char *getRestrictFormatStr(int tp, char *mode_str, size_t size)
{
	if (tp == 0)
	{
		snprintf(mode_str, size, "SHORT");
		return mode_str;
	}
	if (tp == 1)
	{
		snprintf(mode_str, size, "MEDIUM");
		return mode_str;
	}
	if (tp == 2)
	{
		snprintf(mode_str, size, "LONG");
		return mode_str;
	}
	if (tp == 3)
	{
		snprintf(mode_str, size, "VERYLONG");
		return mode_str;
	}
	if (tp == 4)
	{
		snprintf(mode_str, size, "CHECKTICKS");
		return mode_str;
	}
	snprintf(mode_str, size, "WOW!!!");
	return mode_str;
}

static unsigned get_seconds(const char *value, char unit)
{
	unsigned val = 0;

	if (sscanf(value, "%u", &val) != 1)
	{
		fprintf(stderr, "Error while parsing period\n");
		exit(-1);
	}

	switch (unit)
	{
		case 's':
		case 'S':
			return val;
		case 'm':
		case 'M':
			return val * 60;
		case 'h':
		case 'H':
			return val * 60 * 60;
		case 'd':
		case 'D':
			return val * 60 * 60 * 24;
		default:
			return val;
	}
}

#define MAX_VAL_LEN 10

// Function converts string like "2d10h30m45s" (where d - days, h - hours, m - minutes, s - seconds)
// to equivalent total number of seconds
static unsigned parse_period(const char *period)
{
	char value[MAX_VAL_LEN + 1];
	char unit;
	int index, pos = 0;
	unsigned result = 0;

	for (index = 0; index < strlen(period); index++)
	{
		if (isdigit (period[index]))
		{
			if (pos >= MAX_VAL_LEN)
			{
				fprintf(stderr, "Error: value of period is too large\n");
				exit(-1);
			}
			value[pos] = period[index];
			pos++;
		} else
		{
			unit = period[index];
			value[pos] = '\0';
			pos = 0;
			result += get_seconds(value, unit);
		}
	}
	if (!result)
	{
		result = atoi(period);
	}

	return result;
}

static void set_stats_limit(void *inner_xml, stats_limit_cfg * st,
		xml_data *xml)
{
	const char *ptr = getElemAttr(inner_xml, "name");
	const char *ptr_periods = NULL;
	long value[4];

	ptr_periods = getElemAttr(inner_xml, "current");
	value[0] = (ptr_periods == NULL) ? (-1) : atof(ptr_periods);
	if (ptr_periods == NULL)
	{
		releaseElemValue(ptr);
		releaseConfigData(xml);
		fprintf(stderr, "Error: attribute 'current' is absent\n");
		exit(-1);
	}
	releaseElemValue(ptr_periods);

	ptr_periods = getElemAttr(inner_xml, "short");
	value[1] = (ptr_periods == NULL) ? (-1) : atof(ptr_periods);
	releaseElemValue(ptr_periods);

	ptr_periods = getElemAttr(inner_xml, "mid");
	value[2] = (ptr_periods == NULL) ? (-1) : atof(ptr_periods);
	releaseElemValue(ptr_periods);

	ptr_periods = getElemAttr(inner_xml, "long");
	value[3] = (ptr_periods == NULL) ? (-1) : atof(ptr_periods);
	releaseElemValue(ptr_periods);

	if (strcmp(ptr, "slow") == 0)
		_set_val(&st->slow, value);
	else if (strcmp(ptr, "cpu") == 0)
		_set_val(&st->cpu, value);
	else if (strcmp(ptr, "read") == 0)
		_set_val(&st->read, value);
	else if (strcmp(ptr, "write") == 0)
		_set_val(&st->write, value);
	else
		fprintf(stderr, "Unknown limit setting: %s\n", ptr);

	releaseElemValue(ptr);
}

static int check_liblve(void)
{
	void *lve_library_handle = NULL;

	lve_library_handle = dlopen("liblve.so.0", RTLD_LAZY);
	if (lve_library_handle)
	{
		dlclose(lve_library_handle);
		return 0;
	} else
	{
		return 1;
	}
}

stats_limit_cfg *
config_get_account_limit(const char *account_id, stats_limit_cfg * cfgin)
{
	int rc = pthread_rwlock_rdlock(&rwlock);

	stats_limit_cfg *ptr = g_hash_table_lookup(cfg->account_limits, account_id);
	if (ptr)
	{
		memcpy(cfgin, ptr, sizeof(stats_limit_cfg));
		rc = pthread_rwlock_unlock(&rwlock);
		return cfgin;
	}

	memcpy(cfgin, &cfg->default_limit, sizeof(stats_limit_cfg));
	rc = pthread_rwlock_unlock(&rwlock);
	return cfgin;
}

void config_free(void)
{
	if (cfg)
	{
		if (cfg->debug_user)
			free(cfg->debug_user);
		if (cfg->account_limits)
			g_hash_table_unref(cfg->account_limits);
		if (cfg->db_login)
			free(cfg->db_login);
		if (cfg->db_password)
			free(cfg->db_password);
		if (cfg->host)
			free(cfg->host);
		if (cfg->log)
			free(cfg->log);
		if (cfg->restrict_log)
			free(cfg->restrict_log);
		if (cfg->slow_queries_log)
			free(cfg->slow_queries_log);
		free(cfg);
	}
}

void config_add_work_user(const char *user_name)
{
	if (user_name && (user_name[0] != 0))
	{
		stats_limit_cfg *ptr = g_hash_table_lookup(cfg->account_limits,
				user_name);
		if (!ptr)
		{
			stats_limit_cfg *l = calloc(1, sizeof(stats_limit_cfg));

			// inheritance of limits from default
			memcpy(l, &cfg->default_limit, sizeof(Stats));

			l->account_flag = FALSE;
			l->mode = IGNORE_MODE;

			g_hash_table_replace(cfg->account_limits,
					(gpointer) strdup(user_name), l);
		}
	}
}

struct governor_config *
config_init(const char *path)
{
	char xml_parse_error[MAX_XML_PATH] = { 0 };
	void *tmp_xml = NULL, *tmp_xml_limit = NULL;
	const char *ptr;
	xml_data *xml = parseConfigData(path, (char *) xml_parse_error,
			MAX_XML_PATH - 1);
	if (xml == NULL)
	{
		fprintf(stderr, "Error reading config file %s\n", xml_parse_error);
		exit(-1);
	}

	cfg = calloc(1, sizeof(struct governor_config));

	cfg->is_gpl = check_liblve();
	cfg->account_limits = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify) free, (GDestroyNotify) free);

	tmp_xml = FindElementWithName(xml, NULL, "log");
	if (tmp_xml == NULL)
	{
		releaseConfigData(xml);
		fprintf(stderr, "No log path\n");
		exit(-1);
	}
	ptr = getElemAttr(tmp_xml, "file");
	cfg->log = strdup(ptr ? ptr : "");
	releaseElemValue(ptr);
	ptr = getElemAttr(tmp_xml, "mode");
	cfg->log_mode = (ptr == NULL) ? ERROR_MODE : mode_type_str_to_enum(ptr);
	releaseElemValue(ptr);

	tmp_xml = FindElementWithName(xml, NULL, "intervals");
	if (tmp_xml == NULL)
	{
		releaseConfigData(xml);
		fprintf(stderr, "No 'intervals' parameter\n");
		exit(-1);
	}
	ptr = getElemAttr(tmp_xml, "short");
	cfg->interval_short = (ptr == NULL) ? 5 : atoi(ptr);
	releaseElemValue(ptr);
	ptr = getElemAttr(tmp_xml, "mid");
	cfg->interval_mid = (ptr == NULL) ? 15 : atoi(ptr);
	releaseElemValue(ptr);
	ptr = getElemAttr(tmp_xml, "long");
	cfg->interval_long = (ptr == NULL) ? 30 : atoi(ptr);
	releaseElemValue(ptr);

	tmp_xml = FindElementWithName(xml, NULL, "lve");
	cfg->use_lve = 0;
	cfg->all_lve = 0;
	cfg->separate_lve = 0;
	cfg->improved_accuracy = 1;
	if (tmp_xml != NULL)
	{
		ptr = getElemAttr(tmp_xml, "use");
		if (ptr)
		{
			if (!strcasecmp(ptr, "On") || !strcasecmp(ptr, "Single"))
			{
				cfg->use_lve = 1;
			}
			if (!strcasecmp(ptr, "AbUsers"))
			{
				cfg->use_lve = 1;
				cfg->separate_lve = 1;
			}
			if (!strcasecmp(ptr, "All"))
			{
				cfg->use_lve = 1;
				cfg->all_lve = 1;
				cfg->separate_lve = 1;
			}
		}
		releaseElemValue(ptr);
		ptr = getElemAttr(tmp_xml, "improved_accuracy");
		if (ptr)
		{
			if (!strcasecmp(ptr, "Off"))
				cfg->improved_accuracy = 0;
		}
		releaseElemValue(ptr);
	}

	tmp_xml = FindElementWithName(xml, NULL, "statistic");
	cfg->statistic_mode = 1;
	cfg->save_statistic_uid = 0;
	if (tmp_xml != NULL)
	{
		ptr = getElemAttr(tmp_xml, "mode");
		if (ptr)
		{
			if (!strcasecmp(ptr, "Off"))
			{
				cfg->statistic_mode = 0;
			}
		}
		releaseElemValue(ptr);
		ptr = getElemAttr(tmp_xml, "save_uid");
		if (ptr)
		{
			if (!strcasecmp(ptr, "On"))
			{
				cfg->save_statistic_uid = 1;
			}
		}
		releaseElemValue(ptr);
	}

	tmp_xml = FindElementWithName(xml, NULL, "debug_user");
	cfg->debug_user = NULL;
	if (tmp_xml != NULL)
	{
		ptr = getElemAttr(tmp_xml, "name");
		if (ptr)
		{
			cfg->debug_user = strdup(ptr);
		}
		releaseElemValue(ptr);
	}

	tmp_xml = FindElementWithName(xml, NULL, "logqueries");
	cfg->logqueries_use = 0;
	if (tmp_xml != NULL)
	{
		ptr = getElemAttr(tmp_xml, "use");
		if (ptr)
		{
			if (!strcasecmp(ptr, "On"))
			{
				cfg->logqueries_use = 1;
			}
			if (!strcasecmp(ptr, "Before"))
			{
				cfg->logqueries_use = 2;
			}
		}
		releaseElemValue(ptr);
	}

	tmp_xml = FindElementWithName(xml, NULL, "daemon");
	cfg->daemon_monitor = 1;
	if (tmp_xml != NULL)
	{
		ptr = getElemAttr(tmp_xml, "monitor");
		if (ptr)
		{
			if (!strcasecmp(ptr, "Off"))
			{
				cfg->daemon_monitor = 0;
			}
		}
		releaseElemValue(ptr);
	}

	tmp_xml = FindElementWithName(xml, NULL, "slow_queries");
	cfg->slow_queries = 0;
	if (tmp_xml != NULL)
	{
		ptr = getElemAttr(tmp_xml, "run");
		if (ptr)
		{
			if (!strcasecmp(ptr, "On"))
			{
				cfg->slow_queries = 1;
			}
		}
		releaseElemValue(ptr);
		ptr = getElemAttr(tmp_xml, "log");
		if (ptr)
		{
			cfg->slow_queries_log = strdup(ptr);
		} else
		{
			cfg->slow_queries_log = NULL;
		}
		releaseElemValue(ptr);
	}

	tmp_xml = FindElementWithName(xml, NULL, "restrict_mode");
	cfg->restrict_mode = 1;
	cfg->l_unlimit = parse_period("60s");
	if (tmp_xml != NULL)
	{
		ptr = getElemAttr(tmp_xml, "use");
		if (ptr)
		{
			if (!strcasecmp(ptr, "period"))
			{
				cfg->restrict_mode = 0;
			}
		}
		releaseElemValue(ptr);
		ptr = getElemAttr(tmp_xml, "unlimit");
		if (ptr != NULL)
		{
			cfg->l_unlimit = parse_period(ptr);
		}
		releaseElemValue(ptr);
	}

	cfg->killuser = 0;
	cfg->max_user_connections = 30;

	tmp_xml = FindElementWithName(xml, NULL, "restrict");
	if (tmp_xml == NULL)
	{
		releaseConfigData(xml);
		fprintf(stderr, "No 'restrict' parameter\n");
		exit(-1);
	}
	ptr = getElemAttr(tmp_xml, "log");
	if (ptr)
	{
		cfg->restrict_log = strdup(ptr);
	}
	else
	{
		cfg->restrict_log = NULL;
	}
	releaseElemValue(ptr);

	ptr = getElemAttr(tmp_xml, "killuser");
	if (ptr)
	{
		if (!strcasecmp(ptr, "on"))
		{
			cfg->killuser = 1;
		}
	}
	releaseElemValue(ptr);

	ptr = getElemAttr(tmp_xml, "user_max_connections");
	if (ptr)
	{
		cfg->max_user_connections = atoi(ptr);
		if (cfg->max_user_connections < 0)
			cfg->max_user_connections = 30;
	}
	releaseElemValue(ptr);

	ptr = getElemAttr(tmp_xml, "format");
	cfg->restrict_format = getRestrictFormat(ptr);
	releaseElemValue(ptr);

	ptr = getElemAttr(tmp_xml, "level1");
	cfg->level1 = (ptr == NULL) ? parse_period("60s") : parse_period(ptr);
	releaseElemValue(ptr);
	ptr = getElemAttr(tmp_xml, "level2");
	cfg->level2 = (ptr == NULL) ? parse_period("15m") : parse_period(ptr);
	releaseElemValue(ptr);
	ptr = getElemAttr(tmp_xml, "level3");
	cfg->level3 = (ptr == NULL) ? parse_period("1h") : parse_period(ptr);
	releaseElemValue(ptr);
	ptr = getElemAttr(tmp_xml, "level4");
	cfg->level4 = (ptr == NULL) ? parse_period("1d") : parse_period(ptr);
	releaseElemValue(ptr);
	ptr = getElemAttr(tmp_xml, "timeout");
	cfg->timeout = (ptr == NULL) ? parse_period("1h") : parse_period(ptr);
	releaseElemValue(ptr);

	ptr = getElemAttr(tmp_xml, "script");
	if (ptr)
	{
		cfg->exec_script = strdup(ptr);
		if (cfg->exec_script)
		{
			if (!cfg->exec_script[0])
			{
				free(cfg->exec_script);
				cfg->exec_script = NULL;
			} else
			{
				int status_script;
				struct stat buffer_script;
				status_script = stat(cfg->exec_script, &buffer_script);
				if (status_script)
				{
					fprintf(stderr,
							"Wrong script name - %s. Work without script\n",
							cfg->exec_script);
					free(cfg->exec_script);
					cfg->exec_script = NULL;
				} else
				{
					if (S_ISDIR (buffer_script.st_mode))
					{
						fprintf(stderr, "Script is directory - %s\n",
								cfg->exec_script);
						free(cfg->exec_script);
						cfg->exec_script = NULL;
					}
				}
			}
		}
	} else
	{
		cfg->exec_script = NULL;
	}
	releaseElemValue(ptr);

	tmp_xml = FindElementWithName(xml, NULL, "connector");
	if (tmp_xml == NULL)
	{
		releaseConfigData(xml);
		fprintf(stderr, "No connector parameter");
		exit(-1);
	}
	ptr = getElemAttr(tmp_xml, "login");
	cfg->db_login = strdup(!ptr ? "" : ptr);
	releaseElemValue(ptr);
	ptr = getElemAttr(tmp_xml, "password");
	cfg->db_password = strdup(!ptr ? "" : ptr);
	releaseElemValue(ptr);
	ptr = getElemAttr(tmp_xml, "host");
	cfg->host = strdup(!ptr ? "" : ptr);
	releaseElemValue(ptr);
	ptr = getElemAttr(tmp_xml, "prefix_separator");
	cfg->separator = !ptr ? '_' : *(ptr);
	releaseElemValue(ptr);

	tmp_xml = FindElementWithName(xml, NULL, "default");
	if (tmp_xml == NULL)
	{
		releaseConfigData(xml);
		fprintf(stderr, "No default limits");
		exit(-1);
	}

	//clear default limits
	memset(&cfg->default_limit, 0, sizeof(cfg->default_limit));
	cfg->default_limit.mode = RESTRICT_MODE;

	for (tmp_xml_limit = getNextChild(tmp_xml, "limit", NULL); tmp_xml_limit; tmp_xml_limit = getNextChild(tmp_xml, "limit", tmp_xml_limit))
	{
		set_stats_limit(tmp_xml_limit, &cfg->default_limit, xml);
	}
	cfg->default_limit.mode = RESTRICT_MODE;
	cfg->default_limit.account_flag = true;

	for (tmp_xml = getNextChild(xml->root, "user", NULL); tmp_xml; tmp_xml = getNextChild(tmp_xml, "user", tmp_xml))
	{
		const char *account = getElemAttr(tmp_xml, "name");
		const char *mysql_name = getElemAttr(tmp_xml, "mysql_name");
		if ((account == NULL) && (mysql_name == NULL))
		{
			releaseConfigData(xml);
			fprintf(stderr,
					"Error: both 'name' and 'mysql_name' attributes are absent\n");
			exit(-1);
		}
		if ((account != NULL) && (mysql_name != NULL))
		{
			releaseElemValue(account);
			releaseElemValue(mysql_name);
			releaseConfigData(xml);
			fprintf(stderr,
					"Error: both 'name' and 'mysql_name' attributes are present\n");
			exit(-1);
		}
		stats_limit_cfg *l = calloc(1, sizeof(stats_limit_cfg));

		// inheritance of limits from default
		memcpy(l, &cfg->default_limit, sizeof(stats_limit_cfg));

		l->account_flag = account != NULL;
		ptr = getElemAttr(tmp_xml, "mode");
		l->mode = (ptr == NULL) ? RESTRICT_MODE : mode_type_str_to_enum(ptr);
		releaseElemValue(ptr);
		for (tmp_xml_limit = getNextChild(tmp_xml, "limit", NULL); tmp_xml_limit; tmp_xml_limit = getNextChild(tmp_xml, "limit", tmp_xml_limit))
		{
			set_stats_limit(tmp_xml_limit, l, xml);
		}
		g_hash_table_replace(cfg->account_limits,
				(gpointer) strdup((account == NULL) ? mysql_name : account), l);
		releaseElemValue(account);
		releaseElemValue(mysql_name);
	}

	if (save_duplicate_config(xml))
	{
		fprintf(stderr, "Error save duplicate config file %s\n",
				DUPLICATE_CONFIG_PATH);
	}

	releaseConfigData(xml);
	return cfg;
}

/**
 * Save duplicate config file without connector tag
 */
int save_duplicate_config(xml_data *xml)
{
	void *tmp_xml;
	tmp_xml = FindElementWithName(xml, NULL, "connector");
	if (tmp_xml != NULL)
	{
		removeNode(tmp_xml);
	} else
	{
		fprintf(stderr, "No connector tag in xml struct\n");
	}

	if (saveXML(xml, DUPLICATE_CONFIG_PATH) < 0)
	{
		fprintf(stderr, "Error saveXML(%p) duplicate config file %s\n", xml, DUPLICATE_CONFIG_PATH);
		return 1;
	}
	return 0;
}

struct governor_config *
get_config(void)
{
	return cfg;
}

void get_config_data(struct governor_config *data)
{
	int rc;

	rc = pthread_rwlock_rdlock(&rwlock);
	*data = *cfg;
	rc = pthread_rwlock_unlock(&rwlock);
}

void reread_config(void)
{
	int rc;

	rc = pthread_rwlock_wrlock(&rwlock);
	config_free();
	config_init(CONFIG_PATH);
	rc = pthread_rwlock_unlock(&rwlock);
}

void config_destroy_lock(void)
{
	pthread_rwlock_destroy(&rwlock);
	pthread_rwlock_init(&rwlock, NULL);
}

static void print_account_configs(gpointer key, gpointer value, gpointer user_data)
{
	char buffer[512] = { 0 };
	const stats_limit_cfg *ptr = (const stats_limit_cfg *) value;
	printf("%s_CPU_CUR %ld\n", (char *) key, ptr->cpu._current);
	printf("%s_CPU_SHORT %ld\n", (char *) key, ptr->cpu._short);
	printf("%s_CPU_MID %ld\n", (char *) key, ptr->cpu._mid);
	printf("%s_CPU_LONG %ld\n", (char *) key, ptr->cpu._long);

	printf("%s_READ_CUR %ld\n", (char *) key, ptr->read._current);
	printf("%s_READ_SHORT %ld\n", (char *) key, ptr->read._short);
	printf("%s_READ_MID %ld\n", (char *) key, ptr->read._mid);
	printf("%s_READ_LONG %ld\n", (char *) key, ptr->read._long);

	printf("%s_WRITE_CUR %ld\n", (char *) key, ptr->write._current);
	printf("%s_WRITE_SHORT %ld\n", (char *) key, ptr->write._short);
	printf("%s_WRITE_MID %ld\n", (char *) key, ptr->write._mid);
	printf("%s_WRITE_LONG %ld\n", (char *) key, ptr->write._long);

	printf("%s_SLOW_CUR %ld\n", (char *) key, ptr->slow._current);
	printf("%s_SLOW_SHORT %ld\n", (char *) key, ptr->slow._short);
	printf("%s_SLOW_MID %ld\n", (char *) key, ptr->slow._mid);
	printf("%s_SLOW_LONG %ld\n", (char *) key, ptr->slow._long);

	printf("%s_ACC_TP %s\n", (char *) key, ptr->account_flag ? "ACCOUNT" : "MYSQL_USER");
	printf("%s_MODE %s\n", (char *) key, mode_type_enum_to_str(ptr->mode, buffer, sizeof(buffer)-1));
}

void print_config_full(void)
{
	char buffer[512] = { 0 };
	printf("CONFIG DUMP:\n");
	printf("CONNECTOR_HOST %s\n", (cfg->host ? cfg->host : "NULL"));
	printf("CONNECTOR_LOGIN %s\n", (cfg->db_login ? cfg->db_login : "NULL"));
	printf("CONNECTOR_PASSWORD %s\n",
			(cfg->db_password ? cfg->db_password : "NULL"));
	printf("CONNECTOR_PREFFIX_SEPARATOR %c\n", cfg->separator);
	printf("INTERVALS_SHORT %d\n", cfg->interval_short);
	printf("INTERVALS_MID %d\n", cfg->interval_mid);
	printf("INTERVALS_LONG %d\n", cfg->interval_long);
	if (cfg->use_lve && !(cfg->all_lve + cfg->separate_lve))
	{
		snprintf(buffer, sizeof(buffer)-1, "Single or On");
	}
	if (cfg->use_lve && cfg->all_lve && cfg->separate_lve)
	{
		snprintf(buffer, sizeof(buffer)-1, "All");
	}
	if (cfg->use_lve && !cfg->all_lve && cfg->separate_lve)
	{
		snprintf(buffer, sizeof(buffer)-1, "AbUsers");
	}
	printf("LVE %s, USE_LVE %d, ALL_LVE %d, SEP_LVE %d IMPROVED_ACCURACY %d\n", buffer, cfg->use_lve,
			cfg->all_lve, cfg->separate_lve, cfg->improved_accuracy);
	printf("LOG %s, MODE %s\n", cfg->log ? cfg->log : "NULL",
			mode_type_enum_to_str(cfg->log_mode, buffer, sizeof(buffer)-1));
	printf("RESTRICT_LEVEL_1 %d\n", cfg->level1);
	printf("RESTRICT_LEVEL_2 %d\n", cfg->level2);
	printf("RESTRICT_LEVEL_3 %d\n", cfg->level3);
	printf("RESTRICT_LEVEL_4 %d\n", cfg->level4);
	printf("RESTRICT_TIMEOUT %d\n", cfg->timeout);
	printf("RESTRICT_LOG %s, RESTRICT_FORMAT %s\n",
			(cfg->restrict_log ? cfg->restrict_log : "NULL"),
			getRestrictFormatStr(cfg->restrict_format, buffer, sizeof(buffer)-1));
	printf("RESTRICT_SCRIPT %s\n", cfg->exec_script);
	printf("RESTRICT_KILLUSER %s\n", (cfg->killuser ? "ON" : "OFF"));
	printf("RESTRICT_USER_MAX_CONNECTION %d\n", cfg->max_user_connections);
	printf("RESTRICTMODE %s, RESTRICTMODE_ULIMIT %d\n",
			(cfg->restrict_mode ? "limit" : "period"), cfg->l_unlimit);
	printf("SLOWQUERIES %s, SLOWQUERIES_LOG %s\n",
			(cfg->slow_queries ? "ON" : "OFF"),
			(cfg->slow_queries_log ? cfg->slow_queries_log : "NULL"));
	printf("STATISTICMODE %s, STATISTIC_MODE_SAVEUID %s\n",
			(cfg->statistic_mode ? "ON" : "OFF"),
			(cfg->save_statistic_uid ? "ON" : "OFF"));
	printf("LOGQUERIES %s\n", (!cfg->logqueries_use ? "OFF" : (cfg->logqueries_use == 1 ? "ON" : "BEFORE")));
	printf("DEBUG_USER %s\n", (cfg->debug_user ? cfg->debug_user : "NULL"));
	printf("DAEMON_MONITOR %s\n", (cfg->daemon_monitor ? "ON" : "OFF"));
	printf("IS_GPL %d\n", cfg->is_gpl);

	printf("DEFAULT_CPU_CUR %ld\n", cfg->default_limit.cpu._current);
	printf("DEFAULT_CPU_SHORT %ld\n", cfg->default_limit.cpu._short);
	printf("DEFAULT_CPU_MID %ld\n", cfg->default_limit.cpu._mid);
	printf("DEFAULT_CPU_LONG %ld\n", cfg->default_limit.cpu._long);

	printf("DEFAULT_READ_CUR %ld\n", cfg->default_limit.read._current);
	printf("DEFAULT_READ_SHORT %ld\n", cfg->default_limit.read._short);
	printf("DEFAULT_READ_MID %ld\n", cfg->default_limit.read._mid);
	printf("DEFAULT_READ_LONG %ld\n", cfg->default_limit.read._long);

	printf("DEFAULT_WRITE_CUR %ld\n", cfg->default_limit.write._current);
	printf("DEFAULT_WRITE_SHORT %ld\n", cfg->default_limit.write._short);
	printf("DEFAULT_WRITE_MID %ld\n", cfg->default_limit.write._mid);
	printf("DEFAULT_WRITE_LONG %ld\n", cfg->default_limit.write._long);

	printf("DEFAULT_SLOW_CUR %ld\n", cfg->default_limit.slow._current);
	printf("DEFAULT_SLOW_SHORT %ld\n", cfg->default_limit.slow._short);
	printf("DEFAULT_SLOW_MID %ld\n", cfg->default_limit.slow._mid);
	printf("DEFAULT_SLOW_LONG %ld\n", cfg->default_limit.slow._long);

	printf("DEFAULT_ACC_TP %s\n", (cfg->default_limit.account_flag ? "ACCOUNT" : "MYSQL_USER"));
	printf("DEFAULTMODE %s\n", mode_type_enum_to_str(cfg->default_limit.mode, buffer, sizeof(buffer)-1));

	g_hash_table_foreach(cfg->account_limits, (GHFunc) print_account_configs, "");
}
