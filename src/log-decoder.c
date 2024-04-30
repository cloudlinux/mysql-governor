/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#include "data.h"
#include "governor_config.h"
#include "getsysinfo.h"
#include "stats.h"
#include "log-decoder.h"
#include "math.h"
#include "dbgovernor_string_functions.h"

#include <stdlib.h>
#include <string.h>

extern struct governor_config *cfg;

/*Get the value of the limit on which the restriction occurred*/
long
getLimitValuePeriod (Account * ac, T_LONG lm)
{
  switch (ac->info.field_restrict)
    {
    case CURRENT_PERIOD:
      return lm._current;
    case SHORT_PERIOD:
      return lm._short;
    case MID_PERIOD:
      return lm._mid;
    case LONG_PERIOD:
      return lm._long;
    default:
      return -1;
    };
}

/*Get the value of the parameter on which the restriction occurred*/
long long
getRestrictValue (Account * ac)
{
  switch (ac->info.field_restrict)
    {
    case CURRENT_PERIOD:
      return getCurrentRestrictValue (ac);
    case SHORT_PERIOD:
      return getShortRestrictValue (ac);
    case MID_PERIOD:
      return getMidRestrictValue (ac);
    case LONG_PERIOD:
      return getLongRestrictValue (ac);
    };
  return -1;
}

/*Get the value of the current period parameter*/
long long
getCurrentRestrictValue (Account * ac)
{
  switch (ac->info.field_level_restrict)
    {
    case CPU_PARAM:
      return (long long) ceil (ac->current.cpu * 100.0);
    case READ_PARAM:
      return ac->current.read;
    case WRITE_PARAM:
      return ac->current.write;
    default:
      return -1;
    }
}

/*Get the value of the short period parameter*/
long long
getShortRestrictValue (Account * ac)
{
  switch (ac->info.field_level_restrict)
    {
    case CPU_PARAM:
      return (long long) ceil (ac->short_average.cpu * 100.0);
    case READ_PARAM:
      return ac->short_average.read;
    case WRITE_PARAM:
      return ac->short_average.write;
    default:
      return -1;
    }
}

/*Get the value of the average period parameter*/
long long
getMidRestrictValue (Account * ac)
{
  switch (ac->info.field_level_restrict)
    {
    case CPU_PARAM:
      return (long long) ceil (ac->mid_average.cpu * 100.0);
    case READ_PARAM:
      return ac->mid_average.read;
    case WRITE_PARAM:
      return ac->mid_average.write;
    default:
      return -1;
    }
}

/*Get the value of the long period parameter*/
long long
getLongRestrictValue (Account * ac)
{
  switch (ac->info.field_level_restrict)
    {
    case CPU_PARAM:
      return (long long) ceil (ac->long_average.cpu * 100.0);
    case READ_PARAM:
      return ac->long_average.read;
    case WRITE_PARAM:
      return ac->long_average.write;
    default:
      return -1;
    }
}

/*Get the value of the limit on which the restrict passed*/
long
getLimitValue (Account * ac, stats_limit_cfg * lm)
{
  switch (ac->info.field_level_restrict)
    {
    case CPU_PARAM:
      return getLimitValuePeriod (ac, lm->cpu);
    case READ_PARAM:
      return getLimitValuePeriod (ac, lm->read);
    case WRITE_PARAM:
      return getLimitValuePeriod (ac, lm->write);
    default:
      return -1;
    }
}

const char *
getPeriodName (Account * ac)
{
  switch (ac->info.field_restrict)
    {
    case CURRENT_PERIOD:
      return "current value";
    case SHORT_PERIOD:
      return "short av.value";
    case MID_PERIOD:
      return "middle av.value";
    case LONG_PERIOD:
      return "long av.value";
    default:
      return "undef";
    };
}

const char *
getParamName (Account * ac)
{
  switch (ac->info.field_level_restrict)
    {
    case CPU_PARAM:
      return "cpu";
    case READ_PARAM:
      return "read";
    case WRITE_PARAM:
      return "write";
    default:
      return "manual";
    }
}

void
insertSystemInfo (char *buffer)
{
  char loadavg[GETSYSINFO_MAXFILECONTENT];
  char vmstat[GETSYSINFO_MAXFILECONTENT];
  char innerBuffer[_DBGOVERNOR_BUFFER_8192];
  getloadavggov (loadavg);
  getvmstat (vmstat);
  snprintf (innerBuffer, _DBGOVERNOR_BUFFER_8192, "%s loadavg(%s) vmstat(%s)",
	    buffer, loadavg, vmstat);
  strlcpy (buffer, innerBuffer, _DBGOVERNOR_BUFFER_8192);
}

void
prepareRestrictDescription (char *buffer, Account * ac, stats_limit_cfg * limit)
{
	if (ac->info.field_restrict == NO_PERIOD)
	{
		strcpy (buffer, "unrestrict");
	}
	else
	{
		sprintf (buffer, "%s LIMIT_ENFORCED period %s, field %s value %lld/limit %ld restrict level %d",
			ac->id, getPeriodName(ac), getParamName(ac), getRestrictValue (ac), getLimitValue (ac, limit), ac->restricted + 1);
	}

	if (cfg->restrict_format >= 2)
	{
		insertSystemInfo (buffer);
	}
}

void
prepareRestrictDescriptionLimit (char *buffer, Account * ac, stats_limit_cfg * limit)
{
	if (ac->info.field_restrict == NO_PERIOD)
	{
		strcpy (buffer, "unrestrict");
	}
	else
	{
		sprintf (buffer, "%s LIMIT_ENFORCED period %s, field %s value %lld/limit %ld",
			ac->id, getPeriodName(ac), getParamName(ac), getRestrictValue (ac), getLimitValue (ac, limit));
	}

	if (cfg->restrict_format >= 2)
	{
		insertSystemInfo (buffer);
	}
}

/*Get a list of parameters corresponding to the period, the so-called dump*/
stats_limit *
getRestrictDump (Account * ac)
{
  switch (ac->info.field_restrict)
    {
    case CURRENT_PERIOD:
      return (stats_limit *) & ac->current;
    case SHORT_PERIOD:
      return (stats_limit *) & ac->short_average;
    case MID_PERIOD:
      return (stats_limit *) & ac->mid_average;
    case LONG_PERIOD:
      return (stats_limit *) & ac->long_average;
    };
  return (stats_limit *) NULL;
}
