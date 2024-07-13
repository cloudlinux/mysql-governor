/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Shkatula Pavel <shpp@cloudlinux.com>
 */

#include <stdio.h>
#include <stdlib.h>

#include "data.h"
#include "xml.h"

#include "dbctl_cfg.h"
#include "dbctl_rest.h"
#include "dbctl_conn.h"
#include "wrappers.h"
#include "dbgovernor_string_functions.h"

int restrict_user(char *user, char *level)
{
	FILE *in = NULL;
	FILE *out = NULL;
	int _socket = -1;

	if (!strncmp(user, "default", sizeof(username_t) - 1))
	{
		return 1;
	}

	if (opensock(&_socket, &in, &out))
	{
		client_type_t ctt = DBCTL;
		int res __attribute__((unused));
		res = fwrite(&ctt, sizeof(client_type_t), 1, out);
		fflush(out);

		DbCtlCommand command;
		command.command = RESTRICT;
		strcpy(command.parameter, "");
		strncpy(command.options.username, user,
				sizeof(command.options.username) - 1);
		command.options.cpu = 0;
		command.options.level = atoi(level ? level : "-1");
		command.options.read = 0;
		command.options.write = 0;
		command.options.timeout = 0;
		command.options.user_max_connections = 0;

		fwrite_wrapper(&command, sizeof(DbCtlCommand), 1, out);
		fflush(out);

		closesock(_socket, in, out);
	} else
	{
		closesock(_socket, in, out);
		return 0;
	}

	return 1;
}

int unrestrict(char *user)
{
	FILE *in = NULL;
	FILE *out = NULL;
	int _socket = -1;

	if (!strncmp(user, "default", sizeof(username_t) - 1))
	{
		return 1;
	}

	if (opensock(&_socket, &in, &out))
	{
		client_type_t ctt = DBCTL;
		int res __attribute__((unused));
		res = fwrite(&ctt, sizeof(client_type_t), 1, out);
		fflush(out);

		DbCtlCommand command;
		command.command = UNRESTRICT;
		strcpy(command.parameter, "");
		strncpy(command.options.username, user,
				sizeof(command.options.username) - 1);
		command.options.cpu = 0;
		command.options.level = 0;
		command.options.read = 0;
		command.options.write = 0;
		command.options.timeout = 0;
		command.options.user_max_connections = 0;

		fwrite_wrapper(&command, sizeof(DbCtlCommand), 1, out);
		fflush(out);

		closesock(_socket, in, out);
	} else
	{
		closesock(_socket, in, out);
		return 0;
	}

	return 1;
}

int dbupdatecmd(void)
{
	FILE *in = NULL;
	FILE *out = NULL;
	int _socket = -1;

	if (opensock(&_socket, &in, &out))
	{
		client_type_t ctt = DBCTL;
		int res __attribute__((unused));
		res = fwrite(&ctt, sizeof(client_type_t), 1, out);
		fflush(out);

		DbCtlCommand command;
		command.command = DBUSER_MAP_CMD;
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

		closesock(_socket, in, out);
	} else
	{
		closesock(_socket, in, out);
		return 0;
	}

	return 1;
}

int unrestrict_all(void)
{
	FILE *in = NULL;
	FILE *out = NULL;
	int _socket = -1;

	if (opensock(&_socket, &in, &out))
	{
		client_type_t ctt = DBCTL;
		int res __attribute__((unused));
		res = fwrite(&ctt, sizeof(client_type_t), 1, out);
		fflush(out);

		DbCtlCommand command;
		command.command = UNRESTRICT_A;
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

		closesock(_socket, in, out);
	} else
	{
		closesock(_socket, in, out);
		return 0;
	}

	return 1;
}
