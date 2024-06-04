/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 */

// Logging definitions, common for Governor and MySQL patches

#pragma once

enum _log_tag_bitnums	// helper to assign bit number to each tag
{
	#define DEFINE_LOG_TAG(tag)	_log_tag_bitnum_##tag,
	#include "log_tags.h"
	#undef DEFINE_LOG_TAG
	LOG_TAG_BITS
};

// Log tags
// are bit flags to be OR-ed and passed to "LOG(tags, ...)".
// They are named "L_<TAG>", and occupy LOG_TAG_BITS lower bits.
enum
{
	#define DEFINE_LOG_TAG(tag)	L_##tag = 1 << _log_tag_bitnum_##tag,
	#include "log_tags.h"
	#undef DEFINE_LOG_TAG
};

#define ALWAYS_ENABLED_LOG_TAGS	(L_ERR | L_IMPORTANT | L_LIFE)	// independent of file flags

#ifdef __cplusplus
extern "C" {
#endif

typedef int t_write_log_ex(unsigned tags, unsigned level, const char *src_file, int src_line, const char *src_func, const char *fmt, ...);

#ifdef __cplusplus
}
#endif
