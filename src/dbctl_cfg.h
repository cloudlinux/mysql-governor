/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Shkatula Pavel <shpp@cloudlinux.com>
 */

#ifndef __DBCTL_CFG__
#define __DBCTL_CFG__

#include <string.h>
#include <glib.h>

#include "xml.h"

typedef struct dbctl_limit_attr
{
	char l_name[256];
	char l_current[256];
	char l_short[256];
	char l_mid[256];
	char l_long[256];
} DbCtlLimitAttr;

typedef struct dbctl_found_tag
{
	char tag[256];
	GHashTable *attr;
	GPtrArray *limit_attr;
} DbCtlFoundTag;

typedef struct dbctl_print_list
{
	char *name;
	char *data;
} DbCtlPrintList;

void ReadCfg (char *file_name, char *tag);
void FreeCfg (void);
GPtrArray *GetCfg (void);

//---------------------------------------------------
void *SearchTagByName (xml_data *cfg, char *name_tag, char *name);

const char *GetUserName(const GHashTable *attr);
const char *GetAttr(const GHashTable *attr, const char *name_attr);
char *GetLimitAttr (GPtrArray * limit_attr, char *name_limit,
			char *name_attr);


char *GetLimitsForDefault(GPtrArray * tags, int flag, int json);
char *GetLimitsForUsers(GPtrArray * tags, DbCtlLimitAttr * cpu_def,
			DbCtlLimitAttr * read_def, DbCtlLimitAttr * write_def,
			int flag, int raw, int json);

xml_data *ParseXmlCfg (char *file_name);

//---------------------------------------------------
void rewrite_cfg (xml_data *xml);
void reread_cfg_cmd (void);
void reinit_users_list_cmd (void);

void found_tag_data_destroyed (gpointer data);
void found_tag_key_destroyed (gpointer data);

#endif // _CFG_H
