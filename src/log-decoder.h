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

long getLimitValuePeriod(const Account * ac, T_LONG lm);
long long getRestrictValue(const Account * ac);
long getLimitValue(const Account * ac, const stats_limit_cfg * lm);
long long getLongRestrictValue(const Account * ac);
long long getMidRestrictValue(const Account * ac);
long long getShortRestrictValue(const Account * ac);
long long getCurrentRestrictValue(const Account * ac);
const char *prepareRestrictDescription(char *buffer, const Account * ac, const stats_limit_cfg * limit);
const char * getPeriodName(const Account * ac);
const stats_limit *getRestrictDump(const Account * ac);
const char *prepareRestrictDescriptionLimit(char *buffer, const Account * ac, const stats_limit_cfg * limit);
const char *getParamName(const Account * ac);

#endif /* LOG_DECODER_H_ */
