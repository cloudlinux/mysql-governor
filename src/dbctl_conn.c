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
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <string.h>
#include <math.h>
#include <glib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "data.h"

#include "dbctl_conn.h"

int
connect_to_server_dbctl (void)
{
	int s, len;
	struct sockaddr_un saun;

	if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		return -1;
	}

	saun.sun_family = AF_UNIX;
	strcpy (saun.sun_path, SOCK_ADDRESS);

	len = sizeof (saun.sun_family) + strlen (saun.sun_path);
	if (connect (s, (struct sockaddr *) &saun, len) < 0)
	{
		close (s);
		return -2;
	}

	return s;
}

int
opensock (int *_socket, FILE ** in, FILE ** out)
{
	*_socket = connect_to_server_dbctl ();
	if (*_socket >= 0)
	{
		*in = fdopen (*_socket, "r+");
		*out = fdopen (*_socket, "w");
	}

	if (!*in || !*out)
	{
		printf
			("Configuration saved. Unable to apply to live instance - can't connect to socket. Maybe governor is not started\n");
		return 0;
	}

	return 1;
}

void
closesock (int _socket, FILE * in, FILE * out)
{
	if (in)
	{
		fclose (in);
		//in = NULL;
	}

	if (out)
	{
		fclose (out);
		//out = NULL;
	}

	if (_socket > 0)
	{
		close (_socket);
	}
}
