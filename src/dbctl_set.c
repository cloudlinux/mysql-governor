/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Shkatula Pavel <shpp@cloudlinux.com>
 */

#include <stdio.h>
#include <glib.h>
#include <ctype.h>

#include "xml.h"
#include "data.h"
#include "calc_stats.h"
#include "shared_memory.h"

#include "dbctl_cfg.h"
#include "dbctl_set.h"

#include "dbctl_rest.h"

void get_mb(char **s)
{
	long long mb = (long long) (atoll(*s))
			* (long long) (1024 * 1024);
	if (mb < 0)
		mb = -1;
	sprintf(*s, "%lld", mb);
}

void get_kb(char **s)
{
	long long kb = (long long) (atoll(*s))
			* (long long) (1024);
	if (kb < 0)
		kb = -1;
	sprintf(*s, "%lld", kb);
}

void get_bb(char **s)
{
	long long bb = (long long) (atoll(*s));
	if (bb < 0)
		bb = -1;
	sprintf(*s, "%lld", bb);
}

int split(SplitStr ** s_s, char *str, char t)
{
	int j = 0, cnt = 0;
	for (; j < strlen(str); j++)
		if (str[j] == ',')
			cnt++;

	cnt++;

	if (t == '\n')
		cnt = 1;
	else if (cnt < 4)
		return 0;

	(*s_s) = malloc(cnt * sizeof(SplitStr));
	int str_ind[cnt];

	int i = 0, ind = 0;
	if (cnt == 4)
	{
		for (; i < strlen(str); i++)
		{
			if (str[i] == t)
			{
				str_ind[ind] = i;
				ind++;
			}
		}
		str_ind[ind] = strlen(str);
	} else
		str_ind[ind] = strlen(str);

	int ind_pre = 0;
	for (ind = 0; ind < cnt; ind++)
	{
		int len_m = ((str_ind[ind] - ind_pre) + 1);
		(*s_s)[ind].str = (char *) calloc(1, (len_m + 8) * sizeof(char));
		strncpy((*s_s)[ind].str, str + ind_pre, str_ind[ind] - ind_pre);
		ind_pre = str_ind[ind] + 1;
	}

	return cnt;
}

void release_split(SplitStr * data, int cnt)
{
	if (cnt && data)
	{
		int index = 0;
		for (index = 0; index < cnt; index++)
		{
			if (data[index].str)
				free(data[index].str);
		}
		free(data);
	}
}

int checkCorrectAttrs(void *child, char *s)
{
	void *limit = NULL;
	const char *attr = NULL, *inner_attr = NULL;
	int cnt = 0;

	for (limit = getNextChild(child, "limit", NULL); limit; limit = getNextChild(child, "limit", limit))
	{
		attr = getElemAttr(limit, "name");
		if (attr && !strcmp(attr, s))
		{
			inner_attr = getElemAttr(limit, "current");
			if (!inner_attr)
			{
				cnt++;
			}
			releaseElemValue(inner_attr);
			if (strcmp("slow", s) != 0)
			{
				inner_attr = getElemAttr(limit, "short");
				if (!inner_attr)
				{
					cnt++;
				}
				releaseElemValue(inner_attr);
				inner_attr = getElemAttr(limit, "mid");
				if (!inner_attr)
				{
					cnt++;
				}
				releaseElemValue(inner_attr);
				inner_attr = getElemAttr(limit, "long");
				if (!inner_attr)
				{
					cnt++;
				}
				releaseElemValue(inner_attr);
			}
		}
		releaseElemValue(attr);
	}

	if (cnt == 4)
		return 1;
	else if (strcmp("slow", s) == 0)
		return cnt;
	else
		return 0;
}

void *removeBadLimit(void *child, char *s)
{
	void *limit = NULL;
	const char *attr = NULL;

	for (limit = getNextChild(child, "limit", NULL); limit; limit = getNextChild(child, "limit", limit))
	{
		attr = getElemAttr(limit, "name");
		if (!strcmp(attr, s))
		{
			removeNode(limit);
		}
		releaseElemValue(attr);
	}

	return child;
}

void *setLimitAttr(void *limit, char *s)
{
	int cnt = 0;
	if (!s)
		return limit;

	SplitStr *data = NULL;
	int res = 0;
	const char *slowAttr = getElemAttr(limit, "name");
	if (cnt = split(&data, s, ','))
	{
		const char *nameAttr = slowAttr;

		if (!strcmp(nameAttr, "read") || !strcmp(nameAttr, "write"))
		{
			int l = 0;
			for (; l < 4; l++)
			{
				int limit_l = strnlen(data[l].str, 100);
				if (limit_l)
				{
					char units = data[l].str[limit_l - 1];
					if (units == 'b')
					{
						data[l].str[limit_l - 1] = '\0';
						if (isprint(data[l].str[0]))
							get_bb(&data[l].str);
					} else if (units == 'k')
					{
						data[l].str[limit_l - 1] = '\0';
						if (isprint(data[l].str[0]))
							get_kb(&data[l].str);
					} else if (units == 'm')
					{
						data[l].str[limit_l - 1] = '\0';
						if (isprint(data[l].str[0]))
							get_mb(&data[l].str);
					} else
					{
						if (isprint(data[l].str[0]))
							get_mb(&data[l].str);
					}
				} else
				{
					if (isprint(data[l].str[0]))
						get_mb(&data[l].str);
				}
			}
		}

		if (isprint(data[0].str[0]))
			setAttr(limit, "current", data[0].str);
		if (isprint(data[1].str[0]))
			setAttr(limit, "short", data[1].str);
		if (isprint(data[2].str[0]))
			setAttr(limit, "mid", data[2].str);
		if (isprint(data[3].str[0]))
			setAttr(limit, "long", data[3].str);
		int index = 0;
		for (index = 0; index < cnt; index++)
		{
			if (data[index].str)
				free(data[index].str);
		}

	} else if (slowAttr && strcmp(slowAttr, "slow") == 0)
	{
		if (cnt = split(&data, s, '\n'))
		{
			if (isprint(data[0].str[0]))
				setAttr(limit, "current", data[0].str);
			int index = 0;
			for (index = 0; index < cnt; index++)
			{
				if (data[index].str)
					free(data[index].str);
			}

		} else
			puts("Error format parameter!");
	} else
		puts("Error format parameter!");
	releaseElemValue(slowAttr);

	free(data);

	return limit;
}

void *addLimit(xml_data *xml, void *child, char *n, char *s)
{
	void *limit = setNodeWithAttr(xml, child, "limit", NULL, "name", n);

	return setLimitAttr(limit, s);
}

int setDefault(char *cpu, char *read, char *write, char *slow)
{
	char xml_parse_error[MAX_XML_PATH] = { 0 };
	xml_data *cfg = parseConfigData((char *) CONFIG_PATH, xml_parse_error,
			MAX_XML_PATH - 1);
	if (cfg == NULL)
	{
		fprintf(stderr, "Error reading config file %s\n", xml_parse_error);
		return 0;
	}

	void * child = SearchTagByName(cfg, "default", NULL);
	void *limit = NULL;

	if (child == NULL)
	{
		child = setNode(cfg, NULL, "default", NULL);

		if (cpu)
			addLimit(cfg, child, "cpu", cpu);
		if (read)
			addLimit(cfg, child, "read", read);
		if (write)
			addLimit(cfg, child, "write", write);
		if (slow)
			addLimit(cfg, child, "slow", slow);

		if (checkCorrectAttrs(child, "cpu"))
			limit = removeBadLimit(child, "cpu");
		if (checkCorrectAttrs(child, "read"))
			limit = removeBadLimit(child, "read");
		if (checkCorrectAttrs(child, "write"))
			limit = removeBadLimit(child, "write");
		if (checkCorrectAttrs(child, "slow"))
			limit = removeBadLimit(child, "slow");
	} else
	{
		if (cpu)
		{
			int cnt_attr = 0;
			for (limit = getNextChild(child, "limit", NULL); limit; limit = getNextChild(child, "limit", limit))
			{
				const char *nameAttr = getElemAttr(limit, "name");
				if (!strcmp(nameAttr, "cpu"))
				{
					setLimitAttr(limit, cpu);
					cnt_attr++;
				}
				releaseElemValue(nameAttr);
			}
			if (!cnt_attr)
				limit = addLimit(cfg, child, "cpu", cpu);
			if (checkCorrectAttrs(child, "cpu"))
				limit = removeBadLimit(child, "cpu");
		}

		if (read)
		{
			int cnt_attr = 0;
			for (limit = getNextChild(child, "limit", NULL); limit; limit = getNextChild(child, "limit", limit))
			{
				const char *nameAttr = getElemAttr(limit, "name");
				if (!strcmp(nameAttr, "read"))
				{
					setLimitAttr(limit, read);
					cnt_attr++;
				}
				releaseElemValue(nameAttr);
			}
			if (!cnt_attr)
				limit = addLimit(cfg, child, "read", read);
			if (checkCorrectAttrs(child, "read"))
				limit = removeBadLimit(child, "read");
		}

		if (write)
		{
			int cnt_attr = 0;
			for (limit = getNextChild(child, "limit", NULL); limit; limit = getNextChild(child, "limit", limit))
			{
				const char *nameAttr = getElemAttr(limit, "name");
				if (!strcmp(nameAttr, "write"))
				{
					setLimitAttr(limit, write);
					cnt_attr++;
				}
				releaseElemValue(nameAttr);
			}
			if (!cnt_attr)
				limit = addLimit(cfg, child, "write", write);
			if (checkCorrectAttrs(child, "write"))
				limit = removeBadLimit(child, "write");
		}

		if (slow)
		{
			int cnt_attr = 0;
			for (limit = getNextChild(child, "limit", NULL); limit; limit = getNextChild(child, "limit", limit))
			{
				const char *nameAttr = getElemAttr(limit, "name");
				if (!strcmp(nameAttr, "slow"))
				{
					setLimitAttr(limit, slow);
					cnt_attr++;
				}
				releaseElemValue(nameAttr);
			}
			if (!cnt_attr)
				limit = addLimit(cfg, child, "slow", slow);
			if (checkCorrectAttrs(child, "slow"))
				limit = removeBadLimit(child, "slow");
		}
	}

	rewrite_cfg(cfg);
	releaseConfigData(cfg);
	reread_cfg_cmd();

	return 1;
}

int setUser(char *para, char *cpu, char *read, char *write, char *slow)
{
	char xml_parse_error[MAX_XML_PATH] = { 0 };
	xml_data *cfg = parseConfigData((char *) CONFIG_PATH, xml_parse_error,
			MAX_XML_PATH - 1);
	if (cfg == NULL)
	{
		fprintf(stderr, "Error reading config file %s\n", xml_parse_error);
		return 0;
	}

	void * child = SearchTagByName(cfg, "user", para);
	void *limit = NULL;

	if (child == NULL)
	{
		child = setNodeWithAttr(cfg, NULL, "user", NULL, "name", para);
		setAttr(child, "mode", "restrict");

		if (cpu)
			limit = addLimit(cfg, child, "cpu", cpu);
		if (read)
			limit = addLimit(cfg, child, "read", read);
		if (write)
			limit = addLimit(cfg, child, "write", write);
		if (slow)
			limit = addLimit(cfg, child, "slow", slow);

		if (checkCorrectAttrs(child, "cpu"))
			limit = removeBadLimit(child, "cpu");
		if (checkCorrectAttrs(child, "read"))
			limit = removeBadLimit(child, "read");
		if (checkCorrectAttrs(child, "write"))
			limit = removeBadLimit(child, "write");
		if (checkCorrectAttrs(child, "slow"))
			limit = removeBadLimit(child, "slow");
	} else
	{
		if (cpu)
		{
			int cnt_attr = 0;
			for (limit = getNextChild(child, "limit", NULL); limit; limit = getNextChild(child, "limit", limit))
			{
				const char *nameAttr = getElemAttr(limit, "name");
				if (!strcmp(nameAttr, "cpu"))
				{
					setLimitAttr(limit, cpu);
					cnt_attr++;
				}
				releaseElemValue(nameAttr);
			}
			if (!cnt_attr)
				limit = addLimit(cfg, child, "cpu", cpu);
			if (checkCorrectAttrs(child, "cpu"))
				limit = removeBadLimit(child, "cpu");
		}

		if (read)
		{
			int cnt_attr = 0;
			for (limit = getNextChild(child, "limit", NULL); limit; limit = getNextChild(child, "limit", limit))
			{
				const char *nameAttr = getElemAttr(limit, "name");
				if (!strcmp(nameAttr, "read"))
				{
					setLimitAttr(limit, read);
					cnt_attr++;
				}
				releaseElemValue(nameAttr);
			}
			if (!cnt_attr)
				limit = addLimit(cfg, child, "read", read);
			if (checkCorrectAttrs(child, "read"))
				limit = removeBadLimit(child, "read");
		}

		if (write)
		{
			int cnt_attr = 0;
			for (limit = getNextChild(child, "limit", NULL); limit; limit = getNextChild(child, "limit", limit))
			{
				const char *nameAttr = getElemAttr(limit, "name");
				if (!strcmp(nameAttr, "write"))
				{
					setLimitAttr(limit, write);
					cnt_attr++;
				}
				releaseElemValue(nameAttr);
			}
			if (!cnt_attr)
				limit = addLimit(cfg, child, "write", write);
			if (checkCorrectAttrs(child, "write"))
				limit = removeBadLimit(child, "write");
		}

		if (slow)
		{
			int cnt_attr = 0;
			for (limit = getNextChild(child, "limit", NULL); limit; limit = getNextChild(child, "limit", limit))
			{
				const char *nameAttr = getElemAttr(limit, "name");
				if (!strcmp(nameAttr, "slow"))
				{
					setLimitAttr(limit, slow);
					cnt_attr++;
				}
				releaseElemValue(nameAttr);
			}
			if (!cnt_attr)
				limit = addLimit(cfg, child, "slow", slow);
			if (checkCorrectAttrs(child, "slow"))
				limit = removeBadLimit(child, "slow");
		}
	}

	rewrite_cfg(cfg);
	releaseConfigData(cfg);
	reread_cfg_cmd();

	return 1;
}

int deleteUser(char *user)
{
	char xml_parse_error[MAX_XML_PATH] = { 0 };
	xml_data *cfg = parseConfigData((char *) CONFIG_PATH, xml_parse_error,
			MAX_XML_PATH - 1);
	if (cfg == NULL)
	{
		fprintf(stderr, "Error reading config file %s\n", xml_parse_error);
		return 0;
	}

	if (!strncmp(user, "default", sizeof(username_t) - 1))
	{
		releaseConfigData(cfg);
		return 1;
	}

	void *child = SearchTagByName(cfg, "user", user);
	if (child != NULL)
	{
		removeNode(child);

		rewrite_cfg(cfg);
		releaseConfigData(cfg);
		reread_cfg_cmd();
	} else
	{
		releaseConfigData(cfg);
	}

	return 1;
}

int ignoreUser(char *user)
{
	unrestrict(user);

	char xml_parse_error[MAX_XML_PATH] = { 0 };
	xml_data *cfg = parseConfigData((char *) CONFIG_PATH, xml_parse_error,
			MAX_XML_PATH - 1);
	if (cfg == NULL)
	{
		fprintf(stderr, "Error reading config file %s\n", xml_parse_error);
		return 0;
	}

	if (!strncmp(user, "default", sizeof(username_t) - 1))
	{
		releaseConfigData(cfg);
		return 1;
	}

	void * child = SearchTagByName(cfg, "user", user);

	if (child == NULL)
	{
		child = setNodeWithAttr(cfg, NULL, "user", NULL, "name", user);
	}

	setAttr(child, "mode", "ignore");

	rewrite_cfg(cfg);
	releaseConfigData(cfg);
	reread_cfg_cmd();

	return 1;
}

int watchUser(char *user)
{
	char xml_parse_error[MAX_XML_PATH] = { 0 };
	xml_data *cfg = parseConfigData((char *) CONFIG_PATH, xml_parse_error,
			MAX_XML_PATH - 1);
	if (cfg == NULL)
	{
		fprintf(stderr, "Error reading config file %s\n", xml_parse_error);
		return 0;
	}

	if (!strncmp(user, "default", sizeof(username_t) - 1))
	{
		releaseConfigData(cfg);
		return 1;
	}

	void * child = SearchTagByName(cfg, "user", user);

	if (child == NULL)
	{
		child = setNodeWithAttr(cfg, NULL, "user", NULL, "name", user);
	}

	setAttr(child, "mode", "restrict");

	rewrite_cfg(cfg);
	releaseConfigData(cfg);
	reread_cfg_cmd();

	return 1;
}

int setLveMode(char *mode)
{
	char xml_parse_error[MAX_XML_PATH] = { 0 };
	xml_data *cfg = parseConfigData((char *) CONFIG_PATH, xml_parse_error,
			MAX_XML_PATH - 1);
	if (cfg == NULL)
	{
		fprintf(stderr, "Error reading config file %s\n", xml_parse_error);
		return 0;
	}
	if (mode == NULL || (strcmp(mode, "off") && strcmp(mode, "abusers")
		&& strcmp(mode, "all") && strcmp(mode, "single") && strcmp(mode, "on")))
	{
		releaseConfigData(cfg);
		fprintf(stderr, "Incorrect value mode\n");
		return 0;
	}

	void * child = SearchTagByName(cfg, "lve", NULL);

	if (child == NULL)
		child = setNode(cfg, NULL, "lve", NULL);

	setAttr(child, "use", mode);

	rewrite_cfg(cfg);
	releaseConfigData(cfg);

	reinit_users_list_cmd();

	return 1;
}

int setLveAccuracy(char *mode)
{
	char xml_parse_error[MAX_XML_PATH] = { 0 };
	xml_data *cfg = parseConfigData((char *) CONFIG_PATH, xml_parse_error,
			MAX_XML_PATH - 1);
	if (cfg == NULL)
	{
		fprintf(stderr, "Error reading config file %s\n", xml_parse_error);
		return 0;
	}
	if (mode == NULL || (strcmp(mode, "off") && strcmp(mode, "on")))
	{
		releaseConfigData(cfg);
		fprintf(stderr, "Incorrect value mode\n");
		return 0;
	}

	void * child = SearchTagByName(cfg, "lve", NULL);

	if (child == NULL)
		child = setNode(cfg, NULL, "lve", NULL);

	setAttr(child, "improved_accuracy", mode);

	rewrite_cfg(cfg);
	releaseConfigData(cfg);
	reread_cfg_cmd();

	return 1;
}

