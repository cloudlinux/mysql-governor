/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Shkatula Pavel <shpp@cloudlinux.com>
 */

#include <glib.h>

#include "xml.h"
#include "data.h"
#include <stdio.h>
#include <stdlib.h>

#include "dbctl_cfg.h"
#include "dbctl_conn.h"
#include "wrappers.h"
#include "dbgovernor_string_functions.h"

GPtrArray *FoundTag = NULL;
#define SIZEOF_OUTPUT_BUFFER 512

char *
get_mb_str(char *s, char *buf, int flag)
{
	long long divider = 1024 * 1024;
	if (flag == 1)
	{
		divider = 1024;
	} else if (flag == 2)
	{
		divider = 1;
	}
	long long mb = (atoll(s));
	if(mb != -1)
	{
		mb = mb / divider;
	}

	snprintf(buf, SIZEOF_OUTPUT_BUFFER - 1, "%lld", (mb < -1 ? 0 : mb));

	return buf;
}

char *
GetAttr(GHashTable * attr, char *name_attr)
{
	char *value = NULL;
	if (value = (char *) g_hash_table_lookup(attr, name_attr))
		return value;
	else
		return NULL;
}

char *
GetLimitAttr(GPtrArray * limit_attr, char *name_limit, char *name_attr)
{
	int i = 0;

	for (; i < limit_attr->len; i++)
	{
		DbCtlLimitAttr *attr = g_ptr_array_index (limit_attr, i);
		if (strcmp(attr->l_name, name_limit) == 0)
		{
			if (strcmp(name_attr, "current") == 0)
				return attr->l_current;
			else if (strcmp(name_attr, "short") == 0)
				return attr->l_short;
			else if (strcmp(name_attr, "mid") == 0)
				return attr->l_mid;
			else if (strcmp(name_attr, "long") == 0)
				return attr->l_long;
		}
	}

	return "0";
}

char *
GetUserName(GHashTable * attr)
{
	char *value = NULL;
	if (value = (char *) g_hash_table_lookup(attr, "name"))
		return value;
	else
		return NULL;
}

char *
GetUserMysqlName(GHashTable * attr)
{
	char *value = NULL;
	if (value = (char *) g_hash_table_lookup(attr, "mysql_name"))
		return value;
	else
		return NULL;
}

xml_data *ParseXmlCfg(char *file_name)
{
	char error_buf[MAX_XML_PATH] = { 0 };
	xml_data *ptr = parseConfigData(file_name, error_buf, MAX_XML_PATH - 1);
	if (!ptr)
	{
		fprintf(stderr, "Error reading config file %s\n", error_buf);
		exit(-1);
	}
	return ptr;
}

void found_tag_key_destroyed(gpointer data)
{
	free(data);
}

void found_tag_data_destroyed(gpointer data)
{
	free(data);
}

void ReadCfg(char *file_name, char *tag)
{
	FoundTag = g_ptr_array_new();

	char xml_parse_error[MAX_XML_PATH] = { 0 };
	void *tmp_xml = NULL, *tmp_xml_attr = NULL, *tmp_xml_limit = NULL;
	xml_data *xml = parseConfigData(file_name, xml_parse_error,
			MAX_XML_PATH - 1);
	if (xml == NULL)
	{
		fprintf(stderr, "Error reading config file %s\n", xml_parse_error);
		exit(-1);
	}

	for (tmp_xml = getNextChild(xml->root, tag, NULL); tmp_xml; tmp_xml = getNextChild(xml->root, tag, tmp_xml))
	{
		DbCtlFoundTag *found_tag = (DbCtlFoundTag *) malloc(sizeof(DbCtlFoundTag));
		strncpy(found_tag->tag, tag, sizeof(found_tag->tag) - 1);
		found_tag->attr = g_hash_table_new_full(g_str_hash, g_str_equal,
				(GDestroyNotify) found_tag_key_destroyed,
				(GDestroyNotify) found_tag_data_destroyed);
		found_tag->limit_attr = NULL;
		for (tmp_xml_attr = getNextAttr(tmp_xml, NULL); tmp_xml_attr; tmp_xml_attr = getNextAttr(tmp_xml, tmp_xml_attr))
		{
			g_hash_table_insert(found_tag->attr,
					getAttributeName(tmp_xml_attr),
					getAttributeValue(tmp_xml_attr));
		}
		found_tag->limit_attr = g_ptr_array_new();
		for (tmp_xml_limit = getNextChild(tmp_xml, "limit", NULL); tmp_xml_limit; tmp_xml_limit = getNextChild(tmp_xml, "limit", tmp_xml_limit))
		{
			DbCtlLimitAttr *dbctl_l_attr = (DbCtlLimitAttr *) calloc(1, sizeof(DbCtlLimitAttr));
			const char *attr_value = NULL;
			attr_value = getElemAttr(tmp_xml_limit, "name");
			if (attr_value)
			{
				strncpy(dbctl_l_attr->l_name, attr_value,
						sizeof(dbctl_l_attr->l_name) - 1);
				releaseElemValue(attr_value);
			}
			attr_value = getElemAttr(tmp_xml_limit, "current");
			if (attr_value)
			{
				strncpy(dbctl_l_attr->l_current, attr_value,
						sizeof(dbctl_l_attr->l_current) - 1);
				releaseElemValue(attr_value);
			}
			attr_value = getElemAttr(tmp_xml_limit, "short");
			if (attr_value)
			{
				strncpy(dbctl_l_attr->l_short, attr_value,
						sizeof(dbctl_l_attr->l_short) - 1);
				releaseElemValue(attr_value);
			}
			attr_value = getElemAttr(tmp_xml_limit, "mid");
			if (attr_value)
			{
				strncpy(dbctl_l_attr->l_mid, attr_value,
						sizeof(dbctl_l_attr->l_mid) - 1);
				releaseElemValue(attr_value);
			}
			attr_value = getElemAttr(tmp_xml_limit, "long");
			if (attr_value)
			{
				strncpy(dbctl_l_attr->l_long, attr_value,
						sizeof(dbctl_l_attr->l_long) - 1);
				releaseElemValue(attr_value);
			}
			g_ptr_array_add(found_tag->limit_attr, dbctl_l_attr);
		}
		g_ptr_array_add(FoundTag, found_tag);
	}

	releaseConfigData(xml);
}

GPtrArray *
GetCfg(void)
{
	return FoundTag;
}

void FreeCfg(void)
{
	int i = 0;
	for (; i < FoundTag->len; i++)
	{
		DbCtlFoundTag *found_tag_ = g_ptr_array_index (FoundTag, i);
		if (found_tag_->attr)
			g_hash_table_destroy(found_tag_->attr);
		if (found_tag_->limit_attr)
		{
			int j = 0;
			for (j = 0; j < found_tag_->limit_attr->len; j++)
			{
				DbCtlLimitAttr *ptr =
						g_ptr_array_index (found_tag_->limit_attr, j);
				free(ptr);
			}
			g_ptr_array_free(found_tag_->limit_attr, TRUE);
		}
		free(found_tag_);
	}
	g_ptr_array_free(FoundTag, TRUE);
	FoundTag = NULL;
}

//-------------------------------------------------
gint ComparePrintByName(gpointer a, gpointer b)
{
	DbCtlPrintList *x = (DbCtlPrintList *) a;
	DbCtlPrintList *y = (DbCtlPrintList *) b;

	return strcmp(x->name, y->name);
}

char *
GetLimitsForDefault(GPtrArray * tags, int flag, int json)
{
	DbCtlFoundTag *found_tag_ = g_ptr_array_index (tags, 0);
	if (!found_tag_->limit_attr)
		return "Error\n";

	return GetLimitsForUsers(tags, NULL, NULL, NULL, flag, 0, json);
}

static void PrepareLimitsForJson(DbCtlPrintList *print_list_t, int flag, const char *name,
					int cpu_curr, int cpu_short, int cpu_mid, int cpu_long,
					long long read_curr, long long read_short, long long read_mid, long long read_long,
					long long write_curr, long long write_short, long long write_mid, long long write_long )
{
	print_list_t->name = g_strdup_printf("%s", name);
	print_list_t->data = g_strdup_printf(
		"\"%s\": { \"%s\": %d, \"%s\": %d, \"%s\": %d, \"%s\": %d }, "
		"\"%s\": { \"%s\": %lli, \"%s\": %lli, \"%s\": %lli, \"%s\": %lli }, "
		"\"%s\": { \"%s\": %lli, \"%s\": %lli, \"%s\": %lli, \"%s\": %lli }",
		"cpu", "current", cpu_curr, "short", cpu_short, "mid", cpu_mid, "long", cpu_long,
		"read", "current", read_curr, "short", read_short, "mid", read_mid, "long", read_long,
		"write", "current", write_curr, "short", write_short, "mid", write_mid, "long", write_long);
}

static void PrepareLimitsForOutput(DbCtlPrintList *print_list_t, int flag, const char *name,
					int cpu_curr, int cpu_short, int cpu_mid, int cpu_long,
					long long read_curr, long long read_short, long long read_mid, long long read_long,
					long long write_curr, long long write_short, long long write_mid, long long write_long )
{
	if (flag)
	{
		gchar *tmp_param[8] = { 0 };
		tmp_param[0] = g_strdup_printf("%i", read_curr);
		tmp_param[1] = g_strdup_printf("%i", read_short);
		tmp_param[2] = g_strdup_printf("%i", read_mid);
		tmp_param[3] = g_strdup_printf("%i", read_long);
		tmp_param[4] = g_strdup_printf("%i", write_curr);
		tmp_param[5] = g_strdup_printf("%i", write_short);
		tmp_param[6] = g_strdup_printf("%i", write_mid);
		tmp_param[7] = g_strdup_printf("%i", write_long);
		print_list_t->name = g_strdup_printf("%s", name);
		print_list_t->data = g_strdup_printf(
				"\t%d/%d/%d/%d\t%s/%s/%s/%s\t%s/%s/%s/%s", cpu_curr,
				cpu_short, cpu_mid, cpu_long,
				(read_curr < 1 && flag != 2 && read_curr!=-1) ? "<1" : tmp_param[0],
				(read_short < 1 && flag != 2 && read_short!=-1) ? "<1" : tmp_param[1],
				(read_mid < 1 && flag != 2 && read_mid!=-1) ? "<1" : tmp_param[2],
				(read_long < 1 && flag != 2 && read_long!=-1) ? "<1" : tmp_param[3],
				(write_curr < 1 && flag != 2 && write_curr!=-1) ? "<1" : tmp_param[4],
				(write_short < 1 && flag != 2 && write_short!=-1) ? "<1" : tmp_param[5],
				(write_mid < 1 && flag != 2 && write_mid!=-1) ? "<1" : tmp_param[6],
				(write_long < 1 && flag != 2 && write_long!=-1) ? "<1" : tmp_param[7]);
		g_free(tmp_param[0]);
		g_free(tmp_param[1]);
		g_free(tmp_param[2]);
		g_free(tmp_param[3]);
		g_free(tmp_param[4]);
		g_free(tmp_param[5]);
		g_free(tmp_param[6]);
		g_free(tmp_param[7]);
	} else
	{
		char *buffer_cpu = (char *) alloca (25 * sizeof (char));
		char *buffer_read = (char *) alloca (29 * sizeof (char));
		char *buffer_write = (char *) alloca (29 * sizeof (char));

		snprintf(buffer_cpu, 24, "%d/%d/%d/%d", cpu_curr, //cpu
				cpu_short, cpu_mid, cpu_long);
		gchar *tmp_param[4] = { 0 };
		tmp_param[0] = g_strdup_printf("%i", read_curr);
		tmp_param[1] = g_strdup_printf("%i", read_short);
		tmp_param[2] = g_strdup_printf("%i", read_mid);
		tmp_param[3] = g_strdup_printf("%i", read_long);
		snprintf(buffer_read, 28, "%s/%s/%s/%s",
				(read_curr < 1 && read_curr!=-1) ? "<1" : tmp_param[0],
				(read_short < 1 && read_short!=-1) ? "<1" : tmp_param[1],
				(read_mid < 1 && read_mid!=-1) ? "<1" : tmp_param[2],
				(read_long < 1 && read_long!=-1) ? "<1" : tmp_param[3]);
		g_free(tmp_param[0]);
		g_free(tmp_param[1]);
		g_free(tmp_param[2]);
		g_free(tmp_param[3]);
		tmp_param[0] = g_strdup_printf("%i", write_curr);
		tmp_param[1] = g_strdup_printf("%i", write_short);
		tmp_param[2] = g_strdup_printf("%i", write_mid);
		tmp_param[3] = g_strdup_printf("%i", write_long);

		snprintf(buffer_write, 28, "%s/%s/%s/%s",
				(write_curr < 1 && write_curr!=-1) ? "<1" : tmp_param[0],
				(write_short < 1 && write_short!=-1) ? "<1" : tmp_param[1],
				(write_mid < 1 && write_mid!=-1) ? "<1" : tmp_param[2],
				(write_long < 1 && write_long!=-1) ? "<1" : tmp_param[3]);
		g_free(tmp_param[0]);
		g_free(tmp_param[1]);
		g_free(tmp_param[2]);
		g_free(tmp_param[3]);

		print_list_t->name = g_strdup_printf("%-16s", name);
		print_list_t->data = g_strdup_printf("  %-25s  %-29s     %-29s", buffer_cpu, buffer_read, buffer_write);
	}
}

char *
GetLimitsForUsers(GPtrArray * tags, DbCtlLimitAttr * cpu_def,
			DbCtlLimitAttr * read_def, DbCtlLimitAttr * write_def,
			int flag, int raw, int json)
{
	char mb_buffer[SIZEOF_OUTPUT_BUFFER] = { 0 };
	int i = 0;

	DbCtlPrintList *print_list_t = NULL;
	GList *arr_print_list = NULL;
	for (; i < (cpu_def ? tags->len : 1); i++)
	{
		DbCtlFoundTag *found_tag_ = g_ptr_array_index (tags, i);
		char *name = cpu_def ? GetUserName(found_tag_->attr) : "default";
		char *mode = cpu_def ? GetAttr(found_tag_->attr, "mode") : "monitor";

		if (strcmp(mode, "ignore") != 0)
		{
			int
				cpu_curr = atoi(GetLimitAttr(found_tag_->limit_attr, "cpu", "current")),
				cpu_short = atoi(GetLimitAttr(found_tag_->limit_attr, "cpu","short")),
				cpu_mid = atoi(GetLimitAttr(found_tag_->limit_attr, "cpu", "mid")),
				cpu_long = atoi(GetLimitAttr(found_tag_->limit_attr, "cpu", "long"));

			long long
				read_curr_real_size = atoll(GetLimitAttr(found_tag_->limit_attr, "read", "current")),
				read_short_real_size = atoll(GetLimitAttr(found_tag_->limit_attr, "read", "short")),
				read_mid_real_size = atoll(GetLimitAttr(found_tag_->limit_attr, "read", "mid")),
				read_long_real_size = atoll(GetLimitAttr(found_tag_->limit_attr, "read", "long"));

			long long
				write_curr_real_size = atoll(GetLimitAttr(found_tag_->limit_attr, "write", "current")),
				write_short_real_size = atoll(GetLimitAttr(found_tag_->limit_attr, "write", "short")),
				write_mid_real_size = atoll(GetLimitAttr(found_tag_->limit_attr, "write", "mid")),
				write_long_real_size = atoll(GetLimitAttr(found_tag_->limit_attr, "write", "long"));

			long long
				read_curr = atoll(get_mb_str(GetLimitAttr(found_tag_->limit_attr, "read", "current"), mb_buffer, flag)),
				read_short = atoll(get_mb_str(GetLimitAttr(found_tag_->limit_attr, "read", "short"), mb_buffer, flag)),
				read_mid = atoll(get_mb_str(GetLimitAttr(found_tag_->limit_attr, "read", "mid"), mb_buffer, flag)),
				read_long = atoll(get_mb_str(GetLimitAttr(found_tag_->limit_attr, "read", "long"), mb_buffer, flag));

			long long
				write_curr = atoll(get_mb_str(GetLimitAttr(found_tag_->limit_attr, "write", "current"), mb_buffer, flag)),
				write_short = atoll(get_mb_str(GetLimitAttr(found_tag_->limit_attr, "write", "short"), mb_buffer, flag)),
				write_mid = atoll(get_mb_str(GetLimitAttr(found_tag_->limit_attr, "write", "mid"), mb_buffer, flag)),
				write_long = atoll(get_mb_str(GetLimitAttr(found_tag_->limit_attr, "write", "long"), mb_buffer, flag));

			/* In raw mode do not substitite absent limits with default, just return -1 */
			if (raw)
			{
				if (cpu_def)
				{
					if (cpu_curr == 0)
						cpu_curr = -1;
					if (cpu_short == 0)
						cpu_short = -1;
					if (cpu_mid == 0)
						cpu_mid = -1;
					if (cpu_long == 0)
						cpu_long = -1;
				}

				if (read_def)
				{
					if (read_curr == 0)
						read_curr = -1;
					if (read_short == 0)
						read_short = -1;
					if (read_mid == 0)
						read_mid = -1;
					if (read_long == 0)
						read_long = -1;
				}

				if (write_def)
				{
					if (write_curr == 0)
						write_curr = -1;
					if (write_short == 0)
						write_short = -1;
					if (write_mid == 0)
						write_mid = -1;
					if (write_long == 0)
						write_long = -1;
				}

			} // end of if (raw)
			else
			{
				if (cpu_def)
				{
					if (cpu_curr == 0)
						cpu_curr = atoi(cpu_def->l_current);
					if (cpu_short == 0)
						cpu_short = atoi(cpu_def->l_short);
					if (cpu_mid == 0)
						cpu_mid = atoi(cpu_def->l_mid);
					if (cpu_long == 0)
						cpu_long = atoi(cpu_def->l_long);
				}

				if (read_def)
				{
					if (read_curr == 0 && read_curr_real_size <= 0 && read_curr_real_size!=-1)
						read_curr = atoll(
								get_mb_str(read_def->l_current, mb_buffer, flag));
					if (read_short == 0 && read_short_real_size <= 0 && read_short_real_size!=-1)
						read_short = atoll(
								get_mb_str(read_def->l_short, mb_buffer, flag));
					if (read_mid == 0 && read_mid_real_size <= 0 && read_mid_real_size!=-1)
						read_mid = atoll(
								get_mb_str(read_def->l_mid, mb_buffer, flag));
					if (read_long == 0 && read_long_real_size <= 0 && read_long_real_size!=-1)
						read_long = atoll(
								get_mb_str(read_def->l_long, mb_buffer, flag));
				}

				if (write_def)
				{
					if (write_curr == 0 && write_curr_real_size <= 0 && write_curr_real_size!=-1)
						write_curr = atoll(
								get_mb_str(write_def->l_current, mb_buffer, flag));
					if (write_short == 0 && write_short_real_size <= 0 && write_short_real_size!=-1)
						write_short = atoll(
								get_mb_str(write_def->l_short, mb_buffer, flag));
					if (write_mid == 0 && write_mid_real_size <= 0 && write_mid_real_size!=-1)
						write_mid = atoll(
								get_mb_str(write_def->l_mid, mb_buffer, flag));
					if (write_long == 0 && write_long_real_size <= 0 && write_long_real_size!=-1)
						write_long = atoll(
								get_mb_str(write_def->l_long, mb_buffer, flag));
				}

			} // end of else of if (raw)

			if (name == NULL)
				name = GetUserMysqlName(found_tag_->attr);

			print_list_t = (DbCtlPrintList *) g_malloc(sizeof(DbCtlPrintList));
			if (json)
			{
				PrepareLimitsForJson(print_list_t, flag, name,
					cpu_curr, cpu_short, cpu_mid, cpu_long,
					read_curr, read_short, read_mid, read_long,
					write_curr, write_short, write_mid, write_long );
			}
			else
			{
				PrepareLimitsForOutput(print_list_t, flag, name,
					cpu_curr, cpu_short, cpu_mid, cpu_long,
					read_curr, read_short, read_mid, read_long,
					write_curr, write_short, write_mid, write_long );
			}
			arr_print_list = g_list_append(arr_print_list, print_list_t);
		}
	}

	arr_print_list = g_list_sort(arr_print_list,
			(GCompareFunc) ComparePrintByName);
	GList *print_list_l = NULL;
	for (print_list_l = g_list_first(arr_print_list); print_list_l != NULL; print_list_l = g_list_next (print_list_l))
	{
		DbCtlPrintList *print_list_l_ = (DbCtlPrintList *) print_list_l->data;
		if (json)
		{
			printf("%s\"%s\": { %s }", cpu_def?", ":"", print_list_l_->name, print_list_l_->data);
		}
		else
		{
			printf("%s%s\n", print_list_l_->name, print_list_l_->data);
		}
		g_free(print_list_l_->name);
		g_free(print_list_l_->data);
		g_free(print_list_l_);
	}

	if (arr_print_list)
	{
		g_list_free(arr_print_list);
	}

	return NULL;
}

void *SearchTagByName(xml_data *cfg, char *name_tag, char *name)
{
	void *tmp_xml = NULL;
	const char *attrValue = NULL;

	for (tmp_xml = getNextChild(cfg->root, name_tag, NULL); tmp_xml; tmp_xml = getNextChild(cfg->root, name_tag, tmp_xml))
	{
		if (!name)
		{
			return tmp_xml;
		}

		attrValue = getElemAttr(tmp_xml, "name");
		if (attrValue && !strcmp(attrValue, name))
		{
			releaseElemValue(attrValue);
			return tmp_xml;
		}
		releaseElemValue(attrValue);
		attrValue = getElemAttr(tmp_xml, "mysql_name");
		if (attrValue && !strcmp(attrValue, name))
		{
			releaseElemValue(attrValue);
			return tmp_xml;
		}
		releaseElemValue(attrValue);
	}

	return NULL;
}

void rewrite_cfg(xml_data *xml)
{
	if (saveXML(xml, CONFIG_PATH) < 0)
		fprintf(stderr, "Can't save config file %s\n", CONFIG_PATH);
}

#include <time.h>
static const struct timespec ts_10ms = { 0, 10000000 };

void reread_cfg_cmd(void)
{
	FILE *in = NULL;
	FILE *out = NULL;
	int _socket = -1;

	if (opensock(&_socket, &in, &out))
	{
		client_type_t ctt = DBCTL;
		fwrite(&ctt, sizeof(client_type_t), 1, out);
		fflush(out);

		DbCtlCommand command;
		command.command = REREAD_CFG;
		strcpy(command.parameter, "");
		strcpy(command.options.username, "");
		command.options.cpu = 0;
		command.options.level = 0;
		command.options.read = 0;
		command.options.write = 0;
		command.options.timeout = 0;
		command.options.user_max_connections = 0;

		fwrite_wrapper(&command, sizeof(DbCtlCommand), 1, out);
		fflush(out);

		//until the governor closes the socket
		inputAvailable(in, 5);
		//delay 10ms
		nanosleep(&ts_10ms, NULL);

		closesock(_socket, in, out);
	} else
	{
		closesock(_socket, in, out);
	}
}

void reinit_users_list_cmd(void)
{
	FILE *in = NULL;
	FILE *out = NULL;
	int _socket = -1;

	if (opensock(&_socket, &in, &out))
	{
		client_type_t ctt = DBCTL;
		fwrite(&ctt, sizeof(client_type_t), 1, out);
		fflush(out);

		DbCtlCommand command;
		command.command = REINIT_USERS_LIST;
		strcpy(command.parameter, "");
		strcpy(command.options.username, "");
		command.options.cpu = 0;
		command.options.level = 0;
		command.options.read = 0;
		command.options.write = 0;
		command.options.timeout = 0;
		command.options.user_max_connections = 0;

		fwrite_wrapper(&command, sizeof(DbCtlCommand), 1, out);
		fflush(out);

		//until the governor closes the socket
		inputAvailable(in, 5);
		//delay 10ms
		nanosleep(&ts_10ms, NULL);

		closesock(_socket, in, out);
	} else
	{
		closesock(_socket, in, out);
	}
}
