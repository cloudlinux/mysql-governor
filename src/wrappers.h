/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef WRAPPERS_H_
#define WRAPPERS_H_

#define GOVERNOR_READ_TIMEOUT 30

size_t fread_wrapper (void *__restrict __ptr, size_t __size, size_t __n,
			FILE * __restrict __stream);
size_t fwrite_wrapper (__const void *__restrict __ptr, size_t __size,
			size_t __n, FILE * __restrict __s);

int inputAvailable (FILE * fp, unsigned int timeout);

#endif /* WRAPPERS_H_ */
