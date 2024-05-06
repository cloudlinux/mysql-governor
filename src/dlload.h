/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef DLLOAD_H_
#define DLLOAD_H_

#define M_mysql_store_result void * (*_mysql_store_result)(void *)
#define M_mysql_num_rows unsigned long long (*_mysql_num_rows)(void *)
#define M_mysql_free_result void (*_mysql_free_result)(void *)
#define M_mysql_fetch_lengths unsigned long * (*_mysql_fetch_lengths)(void *)
#define M_mysql_fetch_row char ** (*_mysql_fetch_row)(void *)
#define M_my_init char (*_my_init)(void)
#define M_load_defaults int (*_load_defaults)(const char *, const char **, int *, char ***)
#define M_mysql_init void * (*_mysql_init)(void *)
#define M_mysql_real_connect void * (*_mysql_real_connect)( \
	void *, \
	const char *, \
	const char *, \
	const char *, \
	const char *, \
	unsigned int, \
	const char *, \
	unsigned long)
#define M_mysql_options int (*_mysql_options)(void *mysql, int mysql_option, const char *)
#define M_mysql_query int (*_mysql_query)(void *mysql, const char *)
#define M_mysql_close void (*_mysql_close)(void *)
#define M_mysql_error const char * (*_mysql_error)(void *)
#define M_mysql_real_escape_string unsigned long (*_mysql_real_escape_string)(void *mysql, char *, const char *, unsigned long)
#define M_mysql_ping int (*_mysql_ping)(void *mysql)

int init_mysql_function (void);

void delete_mysql_function (void);

#endif /* DLLOAD_H_ */
