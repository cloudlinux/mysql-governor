/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>


#include "data.h"

#include "wrappers.h"

int
inputAvailable (FILE * fp, unsigned int timeout)
{
	struct timeval tv;
	fd_set fds;
	tv.tv_sec = timeout ? timeout : GOVERNOR_READ_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO (&fds);
	FD_SET (fileno (fp), &fds);
	errno = 0;
	while (1)
	{
		if (select (fileno (fp) + 1, &fds, NULL, NULL, &tv) < 0)
		{
			if (errno == EINTR)
				continue;
		}
		break;
	}
	return (FD_ISSET (0, &fds));
}


size_t
fread_wrapper (void *__restrict __ptr, size_t __size, size_t __n,
			FILE * __restrict __s)
{
	size_t res = 0;
	while (1)
	{
		//if(inputAvailable(__s)){
		res = fread (__ptr, __size, __n, __s);
		//}
		if (res == __n)
		{
			return res;
		}
		else if (ferror (__s) && errno == EINTR)
		{
			errno = 0;
			clearerr (__s);
		}
		else
		{
			return 0;
		}
	}
}


size_t
fwrite_wrapper (__const void *__restrict __ptr, size_t __size,
		size_t __n, FILE * __restrict __s)
{
	size_t res;
	while (1)
	{
		res = fwrite (__ptr, __size, __n, __s);
		if (res == __n)
		{
			return res;
		}
		else if (ferror (__s) && errno == EINTR)
		{
			errno = 0;
			clearerr (__s);
		}
		else
		{
			return 0;
		}
	}
}

