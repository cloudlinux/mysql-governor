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


static int mysql_mutex_cmp(const void *a, const void *b)
{
	governor_mutex *pa = (governor_mutex *)a;
	governor_mutex *pb = (governor_mutex *)b;

	if (pa->key < pb->key)
		return -1;

	if (pa->key > pb->key)
		return 1;

	return 0;
}

__thread governor_mutex *gov_mutex = 0;

static void * gv_hash = NULL;

static pthread_mutex_t gv_hash_mutex = PTHREAD_MUTEX_INITIALIZER;

static int governor_add_mysql_thread_info(void)
{
	governor_mutex *mm = NULL;
	governor_mutex key;
	void * ptr;

	orig_pthread_mutex_lock(&gv_hash_mutex);
	key.key = gettid_p();
	ptr = tfind(&key, &gv_hash, mysql_mutex_cmp);
	if (ptr != NULL)
	{
		mm = *(governor_mutex **)ptr;
		orig_pthread_mutex_unlock(&gv_hash_mutex);
		gov_mutex = mm;
		return 0;
	}

	mm = (governor_mutex *) calloc(1, sizeof(governor_mutex));
	if (mm == NULL)
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
		governor_mutex *mm = NULL;
		governor_mutex key;
		void * ptr;

		key.key = gettid_p();
		ptr = tfind(&key, &gv_hash, mysql_mutex_cmp);
		if (ptr != NULL) {

			mm = *(governor_mutex **)ptr;
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
