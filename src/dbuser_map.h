/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Shkatula Pavel <shpp@cloudlinux.com>
 */

#ifndef __DBUSER_MAP__
#define __DBUSER_MAP__

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "data.h"
#include "governor_config.h"

#define RLOCK F_RDLCK
#define WLOCK F_WRLCK

time_t last_modify_map(void);
int get_map_file(struct governor_config *data_cfg);
int get_uid(const username_t u);
char *get_account(const username_t u);

int lock_read_map(void);
int lock_write_map(void);
int unlock_rdwr_map(void);

void *parse_map_file_every_hour(void *data);
void trim(char *s);

#endif /* __DBUSER_MAP__ */
