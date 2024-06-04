/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 */

// Implementation of Governor LVE thread info
// based on tsearch() function family.
//
// Inside libgovernor.so, it was used one day in governor_put_in_lve() and governor_lve_thr_exit().
// That change caused problems (possibly not related to this functionality) and was retracted.
// Currently governor_put_in_lve() and governor_lve_thr_exit() are not called from the patches.
//
// We separated it out into this header to reuse tsearch()-based thread info hash
// inside new refactored patches (CLOS-2697),
// to get rid of clumsy implementation that uses MySQL-native hash.h/c.
//
// Exposes:
// 'gov_mutex' thread-local variable - "Governor mutex", our LVE-related thread info
// governor_add_mysql_thread_info() - initializes 'gov_mutex' for the calling thread; then stores it in the global, process-scope hash "thread id" -> "its Governor mutex"
// governor_remove_mysql_thread_info() - deletes 'gov_mutex' for the calling thread; also removes it from the global hash
// governor_destroy_mysql_thread_info() - cleans up the global hash; to be called at process de-initialization


static __thread governor_mutex *gov_mutex = NULL;	// main purpose of the header

// global "thread id" -> "Governor mutex" hash:
#include <search.h>				// tsearch() function family
static void *gv_hash = NULL;	// to be accessed using tsearch() and relatives
static pthread_mutex_t gv_hash_mutex = PTHREAD_MUTEX_INITIALIZER;	// protect 'gv_hash' accessed from multiple threads

static int mysql_mutex_cmp(const void *a, const void *b)	// for tsearch() family
{
	const governor_mutex *pa = (const governor_mutex*)a, *pb = (const governor_mutex*)b;
	return
		pa->key < pb->key ? -1 :
		pa->key > pb->key ?  1 :
		0;
}

static int governor_add_mysql_thread_info(void)
{
	governor_mutex key;
	key.key = gettid_p();

	orig_pthread_mutex_lock(&gv_hash_mutex);
	const void *ptr = tfind(&key, &gv_hash, mysql_mutex_cmp);
	if (ptr)
	{
		gov_mutex = *(governor_mutex *const*)ptr;
		orig_pthread_mutex_unlock(&gv_hash_mutex);
		return 0;
	}

	governor_mutex *mm = (governor_mutex*)calloc(1, sizeof(governor_mutex));
	if (!mm)
	{
		orig_pthread_mutex_unlock(&gv_hash_mutex);
		return -1;
	}
	mm->key = key.key;

	if (!tsearch(mm, &gv_hash, mysql_mutex_cmp))
	{
		free(mm);
		orig_pthread_mutex_unlock(&gv_hash_mutex);
		return -1;
	}

	orig_pthread_mutex_unlock(&gv_hash_mutex);
	gov_mutex = mm;
	return 0;
}

static void governor_remove_mysql_thread_info(void)
{
	orig_pthread_mutex_lock(&gv_hash_mutex);
	if (gv_hash)
	{
		governor_mutex key;
		key.key = gettid_p();
		const void *ptr = tfind(&key, &gv_hash, mysql_mutex_cmp);
		if (ptr)
		{
			governor_mutex *mm = *(governor_mutex *const*)ptr;
			tdelete(&key, &gv_hash, mysql_mutex_cmp);
			free(mm);
		}
	}
	orig_pthread_mutex_unlock(&gv_hash_mutex);
	gov_mutex = NULL;
}

static void governor_destroy_mysql_thread_info(void)
{
	if (gv_hash)
	{
		orig_pthread_mutex_lock(&gv_hash_mutex);
		tdestroy(gv_hash, free);
		gv_hash = NULL;
		orig_pthread_mutex_unlock(&gv_hash_mutex);
	}
}

