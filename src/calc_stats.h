/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef CALC_STATS_H_
#define CALC_STATS_H_

#include "data.h"
#include "tid_table.h"

#include "stats.h"

void clac_stats_difference (client_data * new, tid_table * old, Stats * st);
void clac_stats_difference_inner (long long cpu, long long read,
					long long write, tid_table * old,
					Stats * st);
void proceed_accounts (double tm);
Stats *add_new_stats (username_t username, Stats * st, long long tick_id);
void add_empty_stats_for_uid (username_t username);
void free_accounts_and_users (void);
void init_accounts_and_users (void);
void print_to_restrict_log_stats (void *data);
void lock_acc (void);
void unlock_acc (void);
void *get_accounts (void);

void clac_stats_difference_inner_from_counter (long long cpu, long long read,
					long long write, double tm_in,
					Stats * st, double new_tm);
void clac_stats_difference_add_to_counters (client_data * new,
					tid_table * old);
void clac_stats_difference_inner_add_to_counters (double cpu,
					long long read,
					long long write,
					tid_table * old);
int is_user_ignored (char *user_name);
double calc_cpu_from_rusage(tid_table * item);

//--- for dbctl ---------------------------------------------------------------
void dbctl_restrict_set (gpointer key, Account * ac, void *data);
void dbctl_unrestrict_set (gpointer key, Account * ac, void *data);
void dbctl_unrestrict_all_set (gpointer key, Account * ac, void *data);
void reinit_users_list (void);

#endif /* CALC_STATS_H_ */
