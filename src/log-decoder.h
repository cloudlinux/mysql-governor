/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef LOG_DECODER_H_
#define LOG_DECODER_H_

long getLimitValuePeriod (Account * ac, T_LONG lm);
long long getRestrictValue (Account * ac);
long getLimitValue (Account * ac, stats_limit_cfg * lm);
long long getLongRestrictValue (Account * ac);
long long getMidRestrictValue (Account * ac);
long long getShortRestrictValue (Account * ac);
long long getCurrentRestrictValue (Account * ac);
void
prepareRestrictDescription (char *buffer, Account * ac,
			stats_limit_cfg * limit);
const char * getPeriodName (Account * ac);
stats_limit *getRestrictDump (Account * ac);
void
prepareRestrictDescriptionLimit (char *buffer, Account * ac,
			stats_limit_cfg * limit);
const char *
getParamName (Account * ac);

#endif /* LOG_DECODER_H_ */
