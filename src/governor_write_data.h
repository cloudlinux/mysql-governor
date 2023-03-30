/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef LIBGOVERNOR_H
#define LIBGOVERNOR_H

#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
    return 0 on success
    return 0 on first unsuccesful connect
    return <0 on not-first unsuccessful connects
*/
int connect_to_server(void);

/*
    return 0 on success
    return 1 on first unsuccesful connect
    return <0 on not-first unsuccessful connects
*/
int connect_to_server_ex(void);

int send_info_begin(char *username);
int send_info_end(char *username);
int close_sock(void);

int governor_load_lve_library(void);

int governor_init_lve(void);

void governor_destroy(void);

int governor_put_in_lve(char *user);

void governor_lve_thr_exit(void);

void governor_reserve_slot(void);

void governor_release_slot(void);

void governor_critical_section_begin(void);

void governor_critical_section_end(void);

//for backward compatible, linked and called
void governor_destroy_lve(void);
int governor_enter_lve(uint32_t *, char *);
void governor_lve_exit(uint32_t *);
int governor_enter_lve_light(uint32_t *);
//for backward compatible, linked and not called
void governor_lve_exit_null();
int governor_lve_enter_pid(pid_t);
int governor_is_in_lve();

#ifdef __cplusplus
}
#endif

#endif
