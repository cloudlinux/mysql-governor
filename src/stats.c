/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include "stats.h"
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include "governor_config.h"

#define COMPARE_MAX_3(x,y,z) (x>y)?((x>z)?x:z):((y>z)?y:z)

Account *
init_account (char *id)
{
	Account *ac = calloc (1, sizeof (Account));
	memset ((void *) ac, (int) 0, sizeof (Account));
	ac->id = id;
	ac->users = g_ptr_array_new ();
	return ac;
}

void
free_account (gpointer ignored, Account * ac)
{
	g_ptr_array_free (ac->users, TRUE);
	free (ac);
}

/*User_Stats*/
User_stats *
init_user_stats (const char *id, Account * ac)
{
	User_stats *us = calloc (1, sizeof (User_stats));
	memset ((void *) us, (int) 0, sizeof (User_stats));
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	us->id = id;
	us->account = ac;
	us->stats = fifo_stats_init (COMPARE_MAX_3
					(data_cfg.interval_long, data_cfg.interval_mid,
					data_cfg.interval_short));
	return us;
}

void
free_user_stats (gpointer ignored, User_stats * us)
{
	fifo_stats_free (us->stats);
	free (us);
}

void
reset_stats (Stats * dest)
{
	dest->cpu = 0;
	dest->read = 0;
	dest->write = 0;
}

void
sum_stats (Stats * dest, const Stats * nr)
{
	dest->cpu += nr->cpu;
	dest->read += nr->read;
	dest->write += nr->write;
}

void
call_diff_stats (Stats * st, User_stats * us)
{
}

void
save_stats (Stats * dst, Stats * st)
{
	dst->cpu = st->cpu;
	dst->read = st->read;
	dst->write = st->write;
}

Stats *
push_stats(const Stats * st, User_stats * us)
{
	int size, i;
	Stats *old;
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	old = fifo_stats_push (us->stats, st);
	fifo_stats_avg (us->stats, &us->long_average, data_cfg.interval_long);
	fifo_stats_avg (us->stats, &us->mid_average, data_cfg.interval_mid);
	fifo_stats_avg (us->stats, &us->short_average, data_cfg.interval_short);

	return old;
}

Stats *
refresh_stats (Stats * st, User_stats * us)
{
	char output_data[_DBGOVERNOR_BUFFER_8192];
	int size, i;
	Stats *old_value;
	struct governor_config data_cfg;
	get_config_data (&data_cfg);

	old_value = fifo_stats_refresh_last (us->stats, st);
	fifo_stats_avg (us->stats, &us->long_average, data_cfg.interval_long);
	fifo_stats_avg (us->stats, &us->mid_average, data_cfg.interval_mid);
	fifo_stats_avg (us->stats, &us->short_average, data_cfg.interval_short);

	return old_value;
}
