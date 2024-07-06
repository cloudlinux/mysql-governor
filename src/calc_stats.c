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
#include <math.h>
#include <pwd.h>

#include "stats.h"
#include "user_account.h"
#include "fifo_stats.h"
#include "data.h"
#include "calc_stats.h"
#include "tick_generator.h"
#include "tid_table.h"
#include "log.h"
#include "governor_config.h"
#include "log-decoder.h"
#include "commands.h"
#include "dbuser_map.h"
#include "shared_memory.h"

typedef struct __statistics_restrict_info
{
	int number_of_restricts;
	int cause_of_restricts;
} statistics_restrict_info;

#define RESTRICT_BY_CPU 1
#define RESTRICT_BY_READ 2
#define RESTRICT_BY_WRITE 4

#define SEC2NANO 1000000000

static GHashTable *accounts = NULL, *users = NULL;

static GHashTable *DbGovStatistics = NULL;
static GHashTable *DbGovNumberOfRestricts = NULL;
static double old_tm_stats = 0.0;

pthread_mutex_t mtx_account = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mtx_counters = PTHREAD_MUTEX_INITIALIZER;

typedef struct __send_to_glib_info
{
	char *dbg;
	double tm;
	MODE_TYPE log_mode;
} send_to_glib_info;

#define is_stat_overlimit(x) GOVERNORS_FIELD_NAME \
is_stat_overlimit_## x(Stats *st, stats_limit_cfg *limit) \
{ \
	if ((st->cpu>(double)limit->cpu._## x/100.0)&&(limit->cpu._## x>=0)) return CPU_PARAM; \
	if ((st->read>limit->read._## x)&&(limit->read._## x>=0)) return READ_PARAM; \
	if ((st->write>limit->write._## x)&&(limit->write._## x>=0)) return WRITE_PARAM; \
	return NORESTRICT_PARAM2; \
}

void
init_accounts_and_users (void)
{
	accounts = g_hash_table_new (g_str_hash, g_str_equal);
	users = g_hash_table_new (g_str_hash, g_str_equal);
	init_user_account_table ();
}

void
free_accounts_and_users (void)
{
	if (accounts)
	{
		g_hash_table_foreach (accounts, (GHFunc) free_account, NULL);
		g_hash_table_unref (accounts);
	}
	if (users)
	{
		g_hash_table_foreach (users, (GHFunc) free_user_stats, NULL);
		g_hash_table_unref (users);
	}
	free_user_account_table ();
}

Stats *add_new_stats(const username_t username, const Stats * st, long long tick_id)
{
	User_stats *us = (User_stats *) g_hash_table_lookup (users, username);
	struct governor_config data_cfg;
	get_config_data (&data_cfg);
	//pthread_mutex_lock(&mtx_account);
	if (!us)
	{
		us = add_user_stats (username, accounts, users);
	}

	if (data_cfg.debug_user && !us->account->need_dbg)
	{
		size_t len = strlen(data_cfg.debug_user);
		if (!strncmp(data_cfg.debug_user, us->account->id, len))
			us->account->need_dbg = 1;
	}
	/*if(check_if_user_restricted(username, accounts) && data_cfg.use_lve){
		return NULL;
		} */
	Stats *stt = NULL;
	if (us)
	{
		if (us->tick == tick_id)
		{
			stt = refresh_stats(st, us);
		}
		else
		{
			us->tick = get_current_tick();
			stt = push_stats(st, us);
		}
	}
	//pthread_mutex_unlock(&mtx_account);
	return stt;
}

void
add_empty_stats_for_uid (username_t username)
{
	lock_acc ();

	User_stats *us = (User_stats *) g_hash_table_lookup (users, username);
	if (!us)
	{
		add_user_stats (username, accounts, users);
	}
	unlock_acc ();
}

void
tick_empty_users (gpointer key, User_stats * us, void *data)
{
	if (is_new_tick (us->tick))
	{
		us->tick = get_current_tick ();
		Stats stats_holder;
		reset_stats (&stats_holder);
		push_stats (&stats_holder, us);
	}
}

void
calc_acc_stats (gpointer key, Account * ac, gpointer data)
{
	send_to_glib_info *internal_info __attribute__((unused)) = (send_to_glib_info *) data;	// cookie, passed through g_hash_table_foreach()

	int i = 0;
	const User_stats *us = (const User_stats *) g_ptr_array_index (ac->users, i++);
	const Stats *ptr = fifo_stats_get(us->stats, 0);

	ac->current = *ptr;
	ac->short_average = us->short_average;
	ac->mid_average = us->mid_average;
	ac->long_average = us->long_average;

	for (; i < ac->users->len; i++)
	{
		us = (const User_stats *) g_ptr_array_index (ac->users, i);
		ptr = fifo_stats_get(us->stats, 0);

		if (ac->need_dbg)
			LOG_RESTRICT("step 2-%d: process user stats %s, c %f, r %llu, w %llu", i, us->id ? us->id : "Unk", ptr->cpu, ptr->read, ptr->write);

		sum_stats (&ac->current, ptr);
		sum_stats (&ac->short_average, &us->short_average);
		sum_stats (&ac->mid_average, &us->mid_average);
		sum_stats (&ac->long_average, &us->long_average);
	}

	if (ac->need_dbg)
		LOG_RESTRICT("step 3: summary, c %f, r %llu, w %llu", ac->current.cpu, ac->current.read, ac->current.write);
}

is_stat_overlimit (current);
is_stat_overlimit (short);
is_stat_overlimit (mid);
is_stat_overlimit (long);

int
get_timeout (int *restrict_level, int penalty)
{
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	*restrict_level += penalty;
	if (*restrict_level > 3)
		*restrict_level = 3;
	if (*restrict_level < 0)
		*restrict_level = 0;
	switch (*restrict_level)
	{
		case 0:
			return data_cfg.level1;
		case 1:
			return data_cfg.level2;
		case 2:
			return data_cfg.level3;
		case 3:
			return data_cfg.level4;
		default:
			return data_cfg.level4;
	}
	return -1;
}

void
IncNumberOfRestricts (const char *username, int cause)
{
	statistics_restrict_info *DbGovNumberOfRestricts_ = NULL;
	if (DbGovNumberOfRestricts == NULL)
		DbGovNumberOfRestricts =
		g_hash_table_new_full (g_str_hash, g_str_equal, NULL, free);

	DbGovNumberOfRestricts_ =
		(statistics_restrict_info *) g_hash_table_lookup (DbGovNumberOfRestricts,
								username);
	if (DbGovNumberOfRestricts_ != NULL)
	{
		DbGovNumberOfRestricts_->number_of_restricts++;
		DbGovNumberOfRestricts_->cause_of_restricts |= cause;
	}
	else
	{
		DbGovNumberOfRestricts_ =
			(statistics_restrict_info *)
			malloc (sizeof (statistics_restrict_info));
		DbGovNumberOfRestricts_->number_of_restricts = 1;
		DbGovNumberOfRestricts_->cause_of_restricts = cause;
		g_hash_table_insert (DbGovNumberOfRestricts, (gpointer) username,
				(gpointer) DbGovNumberOfRestricts_);
	}
}

int
get_cause_of_restrict (GOVERNORS_FIELD_NAME _cur)
{
	switch (_cur)
	{
		case CPU_PARAM:
			return RESTRICT_BY_CPU;
		case READ_PARAM:
			return RESTRICT_BY_READ;
		case WRITE_PARAM:
			return RESTRICT_BY_WRITE;
		default:
			return 0;
	}
}

int
check_restrict (Account * ac)
{
	stats_limit_cfg cfg_buf;
	stats_limit_cfg *sl = config_get_account_limit (ac->id, &cfg_buf);
	int restrict_period = 0;
	GOVERNORS_FIELD_NAME _cur = is_stat_overlimit_current (&ac->current, sl);
	time_t now;
	time (&now);
	struct governor_config data_cfg;
	get_config_data (&data_cfg);
	char tmp_buf[_DBGOVERNOR_BUFFER_8192];

	if (_cur != NORESTRICT_PARAM2)
	{
		//Current restrict
		int old_restricted = ac->restricted;
		if ((ac->start_count + data_cfg.timeout) > now)
		{
			restrict_period = get_timeout (&ac->restricted, 1);
		}
		else
		{
			restrict_period = get_timeout (&ac->restricted, 0);
		}
		if (data_cfg.statistic_mode)
			IncNumberOfRestricts (ac->id, get_cause_of_restrict (_cur));
		ac->timeout = restrict_period;
		time (&ac->start_count);
		ac->info.field_restrict = CURRENT_PERIOD;
		ac->info.field_level_restrict = _cur;
		if (!old_restricted)
			account_restrict (ac, sl);
		LOG_RESTRICT_LIMITS(&ac->current, "%s", prepareRestrictDescription(tmp_buf, ac, sl));
		return 1;
	}
	else
	{
		GOVERNORS_FIELD_NAME _short = is_stat_overlimit_short (&ac->short_average, sl);
		if (_short != NORESTRICT_PARAM2)
		{
		//Short restrict
			int old_restricted = ac->restricted;
			if ((ac->start_count + data_cfg.timeout) > now)
			{
				restrict_period = get_timeout (&ac->restricted, 1);
			}
			else
			{
				restrict_period = get_timeout (&ac->restricted, 0);
			}
			if (data_cfg.statistic_mode)
				IncNumberOfRestricts (ac->id, get_cause_of_restrict (_cur));
			ac->timeout = restrict_period;
			time (&ac->start_count);
			ac->info.field_restrict = SHORT_PERIOD;
			ac->info.field_level_restrict = _short;
			if (!old_restricted)
				account_restrict (ac, sl);
			LOG_RESTRICT_LIMITS(&ac->short_average, "%s", prepareRestrictDescription(tmp_buf, ac, sl));
			return 1;
		}
		else
		{
			GOVERNORS_FIELD_NAME _mid = is_stat_overlimit_mid (&ac->mid_average,
										sl);
			if (_mid != NORESTRICT_PARAM2)
			{
				//Mid restrict
				int old_restricted = ac->restricted;
				if ((ac->start_count + data_cfg.timeout) > now)
				{
					restrict_period = get_timeout (&ac->restricted, 1);
				}
				else
				{
					restrict_period = get_timeout (&ac->restricted, 0);
				}
				if (data_cfg.statistic_mode)
					IncNumberOfRestricts (ac->id, get_cause_of_restrict (_cur));
				ac->timeout = restrict_period;
				time (&ac->start_count);
				ac->info.field_restrict = MID_PERIOD;
				ac->info.field_level_restrict = _mid;
				if (!old_restricted)
					account_restrict (ac, sl);
				LOG_RESTRICT_LIMITS(&ac->mid_average, "%s", prepareRestrictDescription(tmp_buf, ac, sl));
				return 1;
			}
			else
			{
				GOVERNORS_FIELD_NAME _long =
					is_stat_overlimit_long (&ac->long_average, sl);
				if (_long != NORESTRICT_PARAM2)
				{
					//Long restrict
					int old_restricted = ac->restricted;
					if ((ac->start_count + data_cfg.timeout) > now)
					{
						restrict_period = get_timeout (&ac->restricted, 1);
					}
					else
					{
						restrict_period = get_timeout (&ac->restricted, 0);
					}
					if (data_cfg.statistic_mode)
						IncNumberOfRestricts (ac->id,
							get_cause_of_restrict (_cur));
					ac->timeout = restrict_period;
					time (&ac->start_count);
					ac->info.field_restrict = LONG_PERIOD;
					ac->info.field_level_restrict = _long;
					if (!old_restricted)
						account_restrict (ac, sl);
					LOG_RESTRICT_LIMITS(&ac->long_average, "%s", prepareRestrictDescription(tmp_buf, ac, sl));
					return 1;
				}
			}
		}
	}
	return 0;
}

static int
check_restrict_limit (Account * ac)
{
	stats_limit_cfg cfg_buf;
	stats_limit_cfg *sl = config_get_account_limit (ac->id, &cfg_buf);
	int restrict_period = 0;
	GOVERNORS_FIELD_NAME ol_field;
	char tmp_buf[_DBGOVERNOR_BUFFER_8192];
	struct governor_config data_cfg;

	get_config_data (&data_cfg);

	ol_field = is_stat_overlimit_current (&ac->current, sl);
	if (ol_field != NORESTRICT_PARAM2)
	{
		//Current restrict
		restrict_period = data_cfg.l_unlimit;
		if (data_cfg.statistic_mode)
			IncNumberOfRestricts (ac->id, get_cause_of_restrict (ol_field));
		int old_restricted = ac->restricted;
		ac->restricted = 1000;
		ac->timeout = restrict_period;
		time (&ac->start_count);
		ac->info.field_restrict = CURRENT_PERIOD;
		ac->info.field_level_restrict = ol_field;
		LOG(L_MON|L_FRZ, "(cur): overlimited_field %d; restricted(old:%d; new:%d; period:%d; level:%d), stat_count:%ld",
			(int)ol_field, old_restricted, ac->restricted, restrict_period,
			ac->info.field_restrict, (long)ac->start_count);
		if (!old_restricted)
		{
			LOG(L_MON|L_FRZ, "(cur): Before account_restrict()");
			account_restrict (ac, sl);
		}
		else
		{
			LOG(L_MON|L_FRZ, "(cur): account_restrict() OMITTED due to old_restricted");
		}
		LOG_RESTRICT_LIMITS(&ac->current, "%s", prepareRestrictDescriptionLimit(tmp_buf, ac, sl));
		return 1;
	}

	ol_field = is_stat_overlimit_short (&ac->short_average, sl);
	if (ol_field != NORESTRICT_PARAM2)
	{
		//Short restrict
		restrict_period = data_cfg.l_unlimit;
		if (data_cfg.statistic_mode)
		{
			IncNumberOfRestricts (ac->id, get_cause_of_restrict (ol_field));
		}
		int old_restricted = ac->restricted;
		ac->restricted = 1000;
		ac->timeout = restrict_period;
		time (&ac->start_count);
		ac->info.field_restrict = SHORT_PERIOD;
		ac->info.field_level_restrict = ol_field;
		LOG(L_MON|L_FRZ, "(short): overlimited_field %d; restricted(old:%d; new:%d; period:%d; level:%d), stat_count:%ld",
			(int)ol_field, old_restricted, ac->restricted, restrict_period,
			ac->info.field_restrict, (long)ac->start_count);
		if (!old_restricted)
		{
			LOG(L_MON|L_FRZ, "(short): Before account_restrict()");
			account_restrict (ac, sl);
		}
		else
		{
			LOG(L_MON|L_FRZ, "(short): account_restrict() OMITTED due to old_restricted");
		}
		LOG_RESTRICT_LIMITS(&ac->short_average, "%s", prepareRestrictDescriptionLimit(tmp_buf, ac, sl));
		return 1;
	}

	ol_field = is_stat_overlimit_mid (&ac->mid_average, sl);
	if (ol_field != NORESTRICT_PARAM2)
	{
		//Mid restrict
		restrict_period = data_cfg.l_unlimit;
		if (data_cfg.statistic_mode)
		{
			IncNumberOfRestricts (ac->id, get_cause_of_restrict (ol_field));
		}
		int old_restricted = ac->restricted;
		ac->restricted = 1000;
		ac->timeout = restrict_period;
		time (&ac->start_count);
		ac->info.field_restrict = MID_PERIOD;
		ac->info.field_level_restrict = ol_field;
		LOG(L_MON|L_FRZ, "(mid): overlimited_field %d; restricted(old:%d; new:%d; period:%d; level:%d), stat_count:%ld",
			(int)ol_field, old_restricted, ac->restricted, restrict_period,
			ac->info.field_restrict, (long)ac->start_count);
		if (!old_restricted)
		{
			LOG(L_MON|L_FRZ, "(mid): Before account_restrict()");
			account_restrict (ac, sl);
		}
		else
		{
			LOG(L_MON|L_FRZ, "(mid): account_restrict() OMITTED due to old_restricted");
		}
		LOG_RESTRICT_LIMITS(&ac->mid_average, "%s", prepareRestrictDescriptionLimit(tmp_buf, ac, sl));
		return 1;
	}

	ol_field = is_stat_overlimit_long (&ac->long_average, sl);
	if (ol_field != NORESTRICT_PARAM2)
	{
		//Long restrict
		restrict_period = data_cfg.l_unlimit;
		if (data_cfg.statistic_mode)
		{
			IncNumberOfRestricts (ac->id, get_cause_of_restrict (ol_field));
		}
		int old_restricted = ac->restricted;
		ac->restricted = 1000;
		ac->timeout = restrict_period;
		time (&ac->start_count);
		ac->info.field_restrict = LONG_PERIOD;
		ac->info.field_level_restrict = ol_field;
		LOG(L_MON|L_FRZ, "(long): overlimited_field %d; restricted(old:%d; new:%d; period:%d; level:%d), stat_count:%ld",
			(int)ol_field, old_restricted, ac->restricted, restrict_period,
			ac->info.field_restrict, (long)ac->start_count);
		if (!old_restricted)
		{
			LOG(L_MON|L_FRZ, "(long): Before account_restrict()");
			account_restrict (ac, sl);
		}
		else
		{
			LOG(L_MON|L_FRZ, "(long): account_restrict() OMITTED due to old_restricted");
		}
		LOG_RESTRICT_LIMITS(&ac->long_average, "%s", prepareRestrictDescriptionLimit(tmp_buf, ac, sl));
		return 1;
	}

	return 0;
}

static void
account_analyze_limit (gpointer * key, Account * ac, void *data)
{
	stats_limit_cfg cfg_buf;
	stats_limit_cfg *sl = config_get_account_limit (ac->id, &cfg_buf);
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	if (data_cfg.all_lve || !data_cfg.use_lve)
		return;

	if (sl->mode != IGNORE_MODE)
	{
		if (0 == ac->timeout)
		{
		//I am not restricted, but I might be in penalty period. Restrict account if need
			if (check_restrict_limit (ac))
			{
				//If restricted, just exit
				return;
			}
		}
		time_t now;
		time (&now);
		if (ac->start_count > 0)
		{
			//check if account need to unrestrict
			int check_restrict_value = check_restrict_limit (ac);
			if (check_restrict_value)
			{
				time (&ac->start_count);
			}
			else if (0 != ac->timeout && ac->start_count + ac->timeout <= now)
			{
				//Unrestrict account
				ac->start_count = 0;
				ac->restricted = 0;
				ac->info.field_restrict = NO_PERIOD;
				ac->info.field_level_restrict = NORESTRICT_PARAM2;
				ac->timeout = 0;
				account_unrestrict (ac);
				LOG_RESTRICT("Restrict mode is over for user %s\n", ac->id);
			}
		}
	}
	return;
}

void
account_analyze (gpointer * key, Account * ac, void *data)
{
	stats_limit_cfg cfg_buf;
	stats_limit_cfg *sl = config_get_account_limit (ac->id, &cfg_buf);
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	if (data_cfg.all_lve || !data_cfg.use_lve)
		return;

	if (sl->mode != IGNORE_MODE)
	{
		if (0 == ac->timeout)
		{
			//I am not restricted, but I might be in penalty period. Restrict account if need
			if (check_restrict (ac))
			{
				//If restricted, just exit
				return;
			}
		}
		time_t now;
		time (&now);
		if (ac->start_count > 0)
		{
			//check if account need to unrestrict
			if (0 != ac->timeout && ac->start_count + ac->timeout <= now)
			{
				ac->timeout = 0;
				time (&ac->start_count);
				ac->info.field_restrict = NO_PERIOD;
				ac->info.field_level_restrict = NORESTRICT_PARAM;
				if (!check_restrict (ac))
					account_unrestrict (ac);
				else
					LOG_RESTRICT("No unrestrict yet for %s %d %ld\n", ac->id, ac->timeout, ac->start_count);
				//} else if (ac->start_count + data_cfg.timeout <= now) {
			}
			else if (((ac->start_count + data_cfg.timeout) <= now)
				&& (!ac->timeout))
			{
				//Check if penalty period ended
				ac->start_count = 0;
				ac->restricted = 0;
				ac->info.field_restrict = NO_PERIOD;
				ac->info.field_level_restrict = NORESTRICT_PARAM2;
				ac->timeout = 0;
				LOG_RESTRICT("Penalty period is over %s %d %ld\n", ac->id, ac->timeout, ac->start_count);
			}
		}
	}
}

void
add_user_stats_from_counter (gpointer key, Stat_counters * item,
			gpointer user_data)
{
	Stats st;
	const send_to_glib_info *internal_info = (send_to_glib_info *) user_data;
	const double *in_tm = (const double *) &internal_info->tm;
	calc_stats_difference_inner_from_counter ((long long) item->s.cpu,
							item->s.read, item->s.write,
							item->tm, &st, *in_tm);
	if (internal_info->dbg && !strncmp(internal_info->dbg, (const char *)key, strlen(internal_info->dbg)))
		LOG_RESTRICT("step 1: counters c %f, r %llu, w %llu, tm %f", item->s.cpu, item->s.read, item->s.write, (*in_tm - item->tm));
	add_new_stats((const char *) key, &st, get_current_tick());
	reset_counters((const char *) key);
}

static int
dbgov_was_user_activity (dbgov_statistics * dbgovst)
{
	if ((dbgovst->sum_cpu > 0.0 || dbgovst->sum_write > 0.0
		|| dbgovst->sum_read > 0.0 || dbgovst->cause)
		&& (dbgovst->ignored != IGNORE_MODE))
		return 1;
	else
		return 0;
}

static GHashTable *pwdusers = NULL;

static GHashTable *pwdload(void)
{
	GHashTable *r = NULL;
	FILE *stream = fopen("/etc/passwd", "r");
	size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	char buf[buflen];
	struct passwd pwbuf, *pwbufp;

	if (stream == NULL)
		return NULL;

	r = g_hash_table_new_full(g_str_hash, g_str_equal, free, free);

	while (!fgetpwent_r(stream, &pwbuf, buf, buflen, &pwbufp))
	{
		uid_t *val = (uid_t *) malloc(sizeof(uid_t));
		if (val)
			*val = pwbuf.pw_uid;
		g_hash_table_insert(r, (gpointer)strdup(pwbuf.pw_name), (gpointer)val);
	}

	if (!g_hash_table_size(r))
	{
		g_hash_table_unref(r);
		r = NULL;
	}

	fclose(stream);
	return r;
}

void
dbstat_print_table (gpointer key, dbgov_statistics * dbgov_statistics__,
		void *data)
{
	FILE *dbgov_stats =  (FILE *)data;
	struct governor_config data_cfg;

	int number_of_iterations = dbgov_statistics__->number_of_iterations;
	static const int mb_s = 1024*1024;

	get_config_data (&data_cfg);

	if (dbgov_was_user_activity (dbgov_statistics__))
	{
		if (data_cfg.save_statistic_uid)
		{
			gpointer pwdkey, pwdval;
			uid_t need_uid = -1;

			if (pwdusers == NULL)
				pwdusers = pwdload();

			if (pwdusers && g_hash_table_lookup_extended(pwdusers, dbgov_statistics__->username, &pwdkey, &pwdval))
				need_uid = *((uid_t *)pwdval);

			fprintf (dbgov_stats,
				"%s;%d;%f;%f;%f;%f;%f;%f;%d;%ld;%ld;%ld;%d;%d\n",
				dbgov_statistics__->username,
				(int) ceil ((double) dbgov_statistics__->
						max_simultaneous_requests /
						(double) number_of_iterations),
				fabs ((dbgov_statistics__->sum_cpu /
					number_of_iterations) * 100),
				(dbgov_statistics__->sum_write / number_of_iterations) / mb_s,
				(dbgov_statistics__->sum_read / number_of_iterations) / mb_s,
				fabs ((dbgov_statistics__->max_cpu) * 100),
				dbgov_statistics__->max_write / mb_s,
				dbgov_statistics__->max_read / mb_s,
				dbgov_statistics__->number_of_restricts,
				dbgov_statistics__->limit_cpu_on_period_end,
				(long) (dbgov_statistics__->limit_read_on_period_end / mb_s),
				(long) (dbgov_statistics__->limit_write_on_period_end / mb_s),
				dbgov_statistics__->cause,
				(int) need_uid);
		}
		else
		{
			fprintf (dbgov_stats, "%s;%d;%f;%f;%f;%f;%f;%f;%d;%ld;%ld;%ld;%d\n",
				dbgov_statistics__->username,
				(int) ceil ((double) dbgov_statistics__->
						max_simultaneous_requests /
						(double) number_of_iterations),
				fabs ((dbgov_statistics__->sum_cpu /
					number_of_iterations) * 100),
				(dbgov_statistics__->sum_write / number_of_iterations) / mb_s,
				(dbgov_statistics__->sum_read / number_of_iterations) / mb_s,
				fabs ((dbgov_statistics__->max_cpu) * 100),
				dbgov_statistics__->max_write / mb_s,
				dbgov_statistics__->max_read / mb_s,
				dbgov_statistics__->number_of_restricts,
				dbgov_statistics__->limit_cpu_on_period_end,
				(long) (dbgov_statistics__->limit_read_on_period_end / mb_s),
				(long) (dbgov_statistics__->limit_write_on_period_end / mb_s),
				dbgov_statistics__->cause);
		}
	}
}

int
fileSize (FILE * file)
{
	int _size;

	fseek (file, 0, SEEK_END);
	_size = ftell (file);
	fseek (file, 0, SEEK_SET);

	return _size;
}

int
WriteDbGovStatistics (void)
{
	FILE *dbgov_stats;
	char file[256], file_ts[256];
	int _size;

	time_t timestamp = time (NULL);
	sprintf (file, "%sgovernor_%ld.incomplete", PATH_TO_GOVERNOR_STATS,
		timestamp);
	sprintf (file_ts, "%sgovernor.%ld", PATH_TO_GOVERNOR_STATS, timestamp);

	dbgov_stats = fopen (file, "w");

	if (dbgov_stats != NULL)
	{
		g_hash_table_foreach (DbGovStatistics, (GHFunc) dbstat_print_table,
					dbgov_stats);
		_size = fileSize (dbgov_stats);
		fclose (dbgov_stats);

		if (pwdusers)
		{
			g_hash_table_unref(pwdusers);
			pwdusers = NULL;
		}

		if (_size > 0)
		{
			if (rename (file, file_ts) == 0)
				return 1;
		}
		else
			unlink (file);
	}

	return 0;
}

void
dbstat_add_to_table (gpointer key, Account * ac, void *data)
{
	stats_limit_cfg cfg_buf;
	dbgov_statistics *dbgov_statistics__ = NULL;
	dbgov_statistics__ =
		(dbgov_statistics *) g_hash_table_lookup (DbGovStatistics, ac->id);
	stats_limit_cfg *sl = config_get_account_limit (ac->id, &cfg_buf);
	int max_simultaneous_requests = get_cnt_threads (ac->id);

	long limit_cpu = sl->cpu._current;
	long limit_write = sl->write._current;
	long limit_read = sl->read._current;

	statistics_restrict_info *number_of_restricts = NULL;
	if (DbGovNumberOfRestricts)
		number_of_restricts =
			(statistics_restrict_info *)
			g_hash_table_lookup (DbGovNumberOfRestricts, ac->id);

	if (dbgov_statistics__ == NULL)
	{
		dbgov_statistics__ =
			(dbgov_statistics *) malloc (sizeof (dbgov_statistics));

		strncpy (dbgov_statistics__->username, ac->id, USERNAMEMAXLEN - 1);
		dbgov_statistics__->max_simultaneous_requests =
			max_simultaneous_requests;

		dbgov_statistics__->sum_cpu = ac->current.cpu;
		dbgov_statistics__->sum_write = ac->current.write;
		dbgov_statistics__->sum_read = ac->current.read;

		dbgov_statistics__->number_of_iterations = 1;

		dbgov_statistics__->max_cpu = ac->current.cpu;
		dbgov_statistics__->max_write = ac->current.write;
		dbgov_statistics__->max_read = ac->current.read;

		dbgov_statistics__->number_of_restricts =
			number_of_restricts ? number_of_restricts->number_of_restricts : 0;
		dbgov_statistics__->cause =
			number_of_restricts ? number_of_restricts->cause_of_restricts : 0;

		dbgov_statistics__->limit_cpu_on_period_end =
			limit_cpu < 0 ? 0 : limit_cpu;
		dbgov_statistics__->limit_read_on_period_end =
			limit_read < 0 ? 0 : limit_read;
		dbgov_statistics__->limit_write_on_period_end =
			limit_write < 0 ? 0 : limit_write;

		dbgov_statistics__->ignored = sl->mode;

		g_hash_table_insert (DbGovStatistics, ac->id, dbgov_statistics__);
	}
	else
	{
		dbgov_statistics__->max_simultaneous_requests +=
			max_simultaneous_requests;

		dbgov_statistics__->sum_cpu += ac->current.cpu;
		dbgov_statistics__->sum_write += ac->current.write;
		dbgov_statistics__->sum_read += ac->current.read;

		dbgov_statistics__->number_of_iterations++;

		dbgov_statistics__->max_cpu =
			ac->current.cpu >
			dbgov_statistics__->max_cpu ? ac->current.cpu : dbgov_statistics__->
			max_cpu;
		dbgov_statistics__->max_write =
			ac->current.write >
			dbgov_statistics__->max_write ? ac->current.
			write : dbgov_statistics__->max_write;
		dbgov_statistics__->max_read =
			ac->current.read >
			dbgov_statistics__->max_read ? ac->current.read : dbgov_statistics__->
			max_read;

		dbgov_statistics__->number_of_restricts =
			number_of_restricts ? number_of_restricts->number_of_restricts : 0;
		dbgov_statistics__->cause =
			number_of_restricts ? number_of_restricts->cause_of_restricts : 0;

		dbgov_statistics__->limit_cpu_on_period_end =
			limit_cpu < 0 ? 0 : limit_cpu;
		dbgov_statistics__->limit_read_on_period_end =
			limit_read < 0 ? 0 : limit_read;
		dbgov_statistics__->limit_write_on_period_end =
			limit_write < 0 ? 0 : limit_write;
		dbgov_statistics__->ignored = sl->mode;
	}
}

double
AddDbGovStatistics (double old_tm)
{
	struct timespec cur_tm;

	clock_gettime (CLOCK_REALTIME, &cur_tm);

	double new_tm = cur_tm.tv_sec + (double) cur_tm.tv_nsec / (double) SEC2NANO;

	if (old_tm == 0.0)
		old_tm = new_tm;

	if (new_tm - old_tm >= 1.0)
	{
		if (DbGovStatistics == NULL)
			DbGovStatistics =
				g_hash_table_new_full (g_str_hash, g_str_equal, NULL, free);

		g_hash_table_foreach (accounts, (GHFunc) dbstat_add_to_table, NULL);
	}

	if (new_tm - old_tm >= 60.0)
	{
		if (WriteDbGovStatistics ())
		{
			if (DbGovStatistics)
				g_hash_table_remove_all (DbGovStatistics);
			if (DbGovNumberOfRestricts)
				g_hash_table_remove_all (DbGovNumberOfRestricts);
			old_tm = new_tm;
		}
	}

	return old_tm;
}

void
process_accounts (double tm)
{
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	send_to_glib_info snd = { data_cfg.debug_user, tm, data_cfg.log_mode };

	increment_tick ();
	pthread_mutex_lock (&mtx_account);
	pthread_mutex_lock (&mtx_counters);
	g_hash_table_foreach (get_counters_table(), (GHFunc) add_user_stats_from_counter, (gpointer) &snd);
	pthread_mutex_unlock (&mtx_counters);
	g_hash_table_foreach (users, (GHFunc) tick_empty_users, NULL);

	g_hash_table_foreach (accounts, (GHFunc) calc_acc_stats, (gpointer) & snd);
	if (data_cfg.restrict_mode)
	{
		g_hash_table_foreach (accounts, (GHFunc) account_analyze_limit, NULL);
	}
	else
	{
		g_hash_table_foreach (accounts, (GHFunc) account_analyze, NULL);
	}
	if (data_cfg.statistic_mode)
		old_tm_stats = AddDbGovStatistics (old_tm_stats);
	pthread_mutex_unlock (&mtx_account);
}

void
calc_stats_difference (client_data * new, tid_table * old, Stats * st)
{
	calc_stats_difference_inner (new->cpu, new->read, new->write, old, st);
}

void
calc_stats_difference_inner (long long cpu, long long read,
				long long write, tid_table * old, Stats * st)
{
	struct timespec cur_tm;
	clock_gettime (CLOCK_REALTIME, &cur_tm);
	double old_tm = old->update_time + (double) old->nanoseconds
		/ (double) SEC2NANO;
	double new_tm = cur_tm.tv_sec + (double) cur_tm.tv_nsec / (double) SEC2NANO;
	if (new_tm > old_tm)
	{
		//st->cpu = ((double) (cpu - old->cpu) / (new_tm - old_tm))
		//              / ((double) sysconf(_SC_CLK_TCK)*(double)get_cpu_num ());
		double tm = new_tm - old_tm;
		if (tm < 1.0)
			tm = 1.0;

		if (cpu >= old->cpu)
		{
			//if((new_tm-old_tm)<((1.0/(double)sysconf(_SC_CLK_TCK))*5))
			//      st->cpu = 0.0;
			//else
			st->cpu = ((double) (cpu - old->cpu) / tm)
				/ ((double) sysconf (_SC_CLK_TCK));
		}
		else
		{
			st->cpu = 0.0;
		}
		if (read >= old->read)
		{
			st->read = ceil ((double) (read - old->read) / tm);
		}
		else
		{
			st->read = 0;
		}
		if (write >= old->write)
		{
			st->write = ceil ((double) (write - old->write) / tm);
		}
		else
		{
			st->write = 0;
		}
	}
	else
	{
		reset_stats (st);
	}
}

void
calc_stats_difference_inner_from_counter (long long cpu, long long read,
					long long write, double tm_in,
					Stats * st, double new_tm)
{
	double tm = new_tm - tm_in;
	if (tm > 0.0)
	{
		//st->cpu = ((double) (cpu - old->cpu) / (new_tm - old_tm))
		//              / ((double) sysconf(_SC_CLK_TCK)*(double)get_cpu_num ());
		if (tm < 1.0)
			tm = 1.0;
		if (cpu > 0)
		{
			//if((tm)<((1.0/(double)sysconf(_SC_CLK_TCK))*5))
			//      st->cpu = 0.0;
			//else
			st->cpu = ((double) (cpu) / (tm))
				/ ((double) sysconf (_SC_CLK_TCK));
		}
		else
		{
			st->cpu = 0.0;
		}
#ifdef TEST
		LOG(L_MON, "CPU %f  COUNTER cpu %lld, time %f, tm_i %f", st->cpu, cpu, tm, tm_in);
#endif
		if (read >= 0)
		{
			st->read = ceil ((double) (read) / (tm));
		}
		else
		{
			st->read = 0;
		}
		if (write >= 0)
		{
			st->write = ceil ((double) (write) / (tm));
		}
		else
		{
			st->write = 0;
		}
	}
	else
	{
		reset_stats (st);
	}
}

double calc_cpu_from_rusage(tid_table * item)
{
	double cpu = 0;
	int sys_us = (item->stime_end.tv_sec * 1000000 + item->stime_end.tv_usec) - (item->stime_begin.tv_sec * 1000000 + item->stime_begin.tv_usec);
	int user_us = (item->utime_end.tv_sec * 1000000 + item->utime_end.tv_usec) - (item->utime_begin.tv_sec * 1000000 + item->utime_begin.tv_usec);
	int cpu_us = sys_us + user_us;
	int hz = sysconf (_SC_CLK_TCK);
	cpu = cpu_us/(1000000.0/hz);
#ifdef TEST
	LOG(L_MON, "calc %s c:%lld(%f), r:%lld, w:%lld\n", item->username, item->cpu_end - item->cpu, cpu, item->read_end - item->read, item->write_end - item->write);
#endif
	return cpu;
}

void
calc_stats_difference_add_to_counters (client_data * new, tid_table * old)
{
	calc_stats_difference_inner_add_to_counters (new->cpu, new->read,
					new->write, old);
}

void
calc_stats_difference_inner_add_to_counters (double cpu, long long read,
					long long write, tid_table * old)
{
	pthread_mutex_lock (&mtx_counters);
	struct timespec cur_tm;
	clock_gettime (CLOCK_REALTIME, &cur_tm);
	double old_tm = old->update_time + (double) old->nanoseconds	/ (double) SEC2NANO;
	double new_tm = cur_tm.tv_sec + (double) cur_tm.tv_nsec		/ (double) SEC2NANO;
#ifdef TEST
	LOG(L_MON, "add_to-counters %s - dt - %f c %f, w %lld, r %lld, old c %lld, w %lld, r %lld",
		old->username, new_tm - old_tm, cpu, write, read, old->cpu, old->write, old->read);
#endif
	if (new_tm > old_tm)
	{
		double tmp_cpu = 0;
		long long tmp_read = 0;
		long long tmp_write = 0;
		if (cpu >= old->cpu)
		tmp_cpu = cpu - old->cpu;
		if (read >= old->read)
		tmp_read = read - old->read;
		if (write >= old->write)
		tmp_write = write - old->write;
		if ((new_tm - old_tm) > 1.0)
			increment_counters (old->username,
											tmp_cpu		/ (new_tm - old_tm),
				(long long) floor ((double)	tmp_read	/ (new_tm - old_tm)),
				(long long) floor ((double)	tmp_write	/ (new_tm - old_tm)),
				old_tm);
		else
			increment_counters (old->username, tmp_cpu, tmp_read, tmp_write,
				old_tm);
	}
	else
	{
		increment_counters (old->username, 0, 0, 0, old_tm);
	}
	pthread_mutex_unlock (&mtx_counters);
}

void
print_to_restrict_log_account_info (gpointer * key, Account * ac, void *data)
{
	LOG_RESTRICT("Screen item %s Cur: cpu %f, read %lld, write %lld | Shrt: cpu %f, read %lld, write %lld | Mid: cpu %f, read %lld, write %lld | Lng: cpu %f, read %lld, write %lld |",
		ac->id, ac->current.cpu, ac->current.read, ac->current.write,
		ac->short_average.cpu, ac->short_average.read,
		ac->short_average.write, ac->mid_average.cpu,
		ac->mid_average.read, ac->mid_average.write,
		ac->long_average.cpu, ac->long_average.read,
		ac->long_average.write);
}

void
print_to_restrict_log_stats (void *data)
{
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	time_t tm = time (NULL);
	LOG_RESTRICT("Begin screen %ld", tm);
	g_hash_table_foreach (accounts, (GHFunc) print_to_restrict_log_account_info, NULL);
	LOG_RESTRICT("End screen %ld", tm);
}

void
lock_acc (void)
{
	pthread_mutex_lock (&mtx_account);
}

void
unlock_acc (void)
{
	pthread_mutex_unlock (&mtx_account);
}

void *
get_accounts (void)
{
	return accounts;
}

//-----------------------------------------------------------------------------
int comapre_users_name(const char *username, const Account *ac)
{
	int i;
	for (i=0; i < ac->users->len; i++)
	{
		const User_stats *us = g_ptr_array_index(ac->users, i);
		if (!strncmp(us->id, username, USERNAMEMAXLEN))
			return 0;
	}
	return 1;
}

void
dbctl_restrict_set (gpointer key, Account * ac, void *data)
{
	int first = 0;
	DbCtlCommand *command = (DbCtlCommand *) data;
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	User_stats *us =
		(User_stats *) g_hash_table_lookup (users, command->options.username);
	if (!us)
	{
		us = add_user_stats (command->options.username, accounts, users);
		first = 1;
	}

	if (first == 1)
	{
		//us = (User_stats *)g_hash_table_lookup( users, command->options.username );
		if (us)
		{
			ac = us->account;
		}
	}

	if ((strncmp (ac->id, command->options.username, USERNAMEMAXLEN) == 0)
		|| (comapre_users_name (command->options.username, ac) == 0))
	{
		stats_limit_cfg cfg_buf;
		stats_limit_cfg *sl = config_get_account_limit (ac->id, &cfg_buf);
		int timeout_coeff = 0;
		GOVERNORS_FIELD_NAME _cur =
		is_stat_overlimit_current (&ac->current, sl);
		time_t now;

		int level = command->options.level;

		if (level == -1)
		{
			level = ac->restricted;
			timeout_coeff = -1;
		}
		else
		{
			level--;
			if (level < 0)
				level = 0;
		}

		time (&now);
		if (data_cfg.restrict_mode)
		{
			ac->timeout = data_cfg.l_unlimit;
			ac->restricted = 1000;
		}
		else
		{
			ac->timeout = get_timeout (&level, timeout_coeff);
			ac->restricted = level;
		}
		if (data_cfg.statistic_mode)
		{
			if (level >= 0)
			{
				IncNumberOfRestricts (ac->id,
					RESTRICT_BY_CPU | RESTRICT_BY_READ |
					RESTRICT_BY_WRITE);
			}
		}
		time (&ac->start_count);
		ac->info.field_restrict = CURRENT_PERIOD;
		ac->info.field_level_restrict = _cur;
		account_restrict (ac, sl);

		char restrict_buf[_DBGOVERNOR_BUFFER_8192];
		LOG_RESTRICT_LIMITS(&ac->current, "%s", data_cfg.restrict_mode ? prepareRestrictDescriptionLimit(restrict_buf, ac, sl) : prepareRestrictDescription(restrict_buf, ac, sl));
	}
}

void
reset_user_stats (gpointer ignored, User_stats * us)
{
	Stats *st_curr = fifo_stats_get (us->stats, 0);
	st_curr->cpu = 0.0;
	st_curr->write = 0;
	st_curr->read = 0;

	us->short_average.cpu = 0.0;
	us->mid_average.write = 0;
	us->long_average.read = 0;

	fifo_stats_push (us->stats, st_curr);
}

void
resetting_user_stats (Account * ac)
{
	//g_hash_table_foreach( ac->users, (GHFunc)free_user_stats, NULL );
	//g_hash_table_foreach( ac->users, (GHFunc)reset_user_stats, NULL );
	//g_hash_table_unref( ac->users );
	return;
}

void
dbctl_unrestrict_set (gpointer key, Account * ac, void *data)
{
	const DbCtlCommand *command = (const DbCtlCommand *) data;

	//  User_stats *us = (User_stats *)g_hash_table_lookup( users, command->options.username );
	//  if( !us ) us = add_user_stats( command->options.username, accounts, users );

	if (strcmp (ac->id, command->options.username) == 0)
	{
		ac->timeout = 0;
		ac->start_count = 0;
		ac->restricted = 0;

		ac->current.cpu = 0;
		ac->current.read = 0;
		ac->current.write = 0;

		ac->long_average.cpu = 0;
		ac->long_average.read = 0;
		ac->long_average.write = 0;

		ac->mid_average.cpu = 0;
		ac->mid_average.read = 0;
		ac->mid_average.write = 0;

		ac->short_average.cpu = 0;
		ac->short_average.read = 0;
		ac->short_average.write = 0;

		ac->info.field_restrict = 0;
		ac->info.field_level_restrict = 0;

		resetting_user_stats (ac);

		if (!check_restrict (ac))
			account_unrestrict (ac);
		else
			LOG_RESTRICT("No unrestrict yet for %s %d %ld\n", ac->id, ac->timeout, ac->start_count);
	}
}

void
dbctl_unrestrict_all_set (gpointer key, Account * ac, void *data)
{
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	if (ac->timeout)
		account_unrestrict (ac);

	ac->timeout = 0;
	ac->start_count = 0;
	ac->restricted = 0;

	ac->current.cpu = 0;
	ac->current.read = 0;
	ac->current.write = 0;

	ac->long_average.cpu = 0;
	ac->long_average.read = 0;
	ac->long_average.write = 0;

	ac->mid_average.cpu = 0;
	ac->mid_average.read = 0;
	ac->mid_average.write = 0;

	ac->short_average.cpu = 0;
	ac->short_average.read = 0;
	ac->short_average.write = 0;

	ac->info.field_restrict = 0;
	ac->info.field_level_restrict = 0;

	resetting_user_stats (ac);
}

void
add_all_users_to_list (gpointer key, Account * ac, void *data)
{
	User_stats *us;
	if (ac)
	{
		int i = 0;
		for (i = 0; i < ac->users->len; i++)
		{
			us = g_ptr_array_index (ac->users, i);
			if (us)
				add_user_to_list (us->id, 1);
		}
	}
}

void reinit_users_list(void)
{
	struct governor_config data_cfg;
	get_config_data(&data_cfg);

	if (lock_write_map () == 0)
	{
		if (!get_map_file (&data_cfg))
			LOG(L_ERR, "Failed read dbuser-map file");
		unlock_rdwr_map ();
	}

	GHashTable *ac = (GHashTable *) get_accounts ();
	if (ac == NULL)
	{
		LOG(L_ERR, "Failed to get accounts, service db_governor should be restarted");
		return;
	}

	if (!data_cfg.is_gpl)
	{
		lock_acc ();
		g_hash_table_foreach(ac, (GHFunc)dbctl_unrestrict_all_set, NULL);
		unlock_acc ();
	}

	delete_allusers_from_list ();

	if (data_cfg.all_lve)
		g_hash_table_foreach(ac, (GHFunc)add_all_users_to_list, NULL);

	LOG(L_MON, "Reinit users list completed");
}

gboolean
find_acount_cmp (gpointer key, Account * ac, void *data)
{
	User_stats *us;
	if (ac)
	{
		int i = 0;
		for (i = 0; i < ac->users->len; i++)
		{
			us = g_ptr_array_index (ac->users, i);
			if (us && !strncmp (us->id, (char *) data, USERNAMEMAXLEN))
				return 1;
		}
	}
	return 0;
}

int is_user_ignored(const char *user_name)
{
	pthread_mutex_lock(&mtx_account);
	const Account *ac = (const Account *) g_hash_table_find(accounts, (GHRFunc) find_acount_cmp, (gpointer)user_name);
	pthread_mutex_unlock(&mtx_account);
	stats_limit_cfg cfg_buf;
	const stats_limit_cfg *sl = config_get_account_limit(ac ? ac->id : user_name, &cfg_buf);
	if (sl->mode != IGNORE_MODE)
		return sl->slow._current;
	return 0;
}

