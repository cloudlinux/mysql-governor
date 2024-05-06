/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Shkatula Pavel <shpp@cloudlinux.com>
 */

#ifndef __DBCTL_SET__
#define __DBCTL_SET__

typedef struct split_str
{
	char *str;
} SplitStr;


int setDefault (char *cpu, char *read, char *write, char *slow);
int setUser (char *para, char *cpu, char *read, char *write, char *slow);
int deleteUser (char *user);
int ignoreUser (char *user);
int watchUser (char *user);
int setLveMode (char *mode);
int setLveAccuracy (char *mode);

int split (SplitStr ** s_s, char *str, char t);
void release_split (SplitStr * data, int cnt);

#endif /* __DBCTL_SET__ */
