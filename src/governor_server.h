/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef GOVERNOR_SERVER_H_
#define GOVERNOR_SERVER_H_

void create_socket (void);
void *get_data_from_client (void *data);
int get_soket (void);
void monitor_data_from_client (void *data);
void *process_data_every_second (void *data);

#endif /* GOVERNOR_SERVER_H_ */
