/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include "tick_generator.h"

unsigned long long tick_id = 0;

void
increment_tick (void)
{
	tick_id++;
}

unsigned long long
get_current_tick (void)
{
	return tick_id;
}

int
is_new_tick (long long tick)
{
	if (tick != tick_id)
		return 1;
	else
		return 0;
}
