/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#define HELP_LEN 24

char help[HELP_LEN][512] =
{
  "dbtop - utility to monitor MySQL usage.\n",
  "-r - dbtop refresh period in seconds( dbtop -r12 )",
  "Control keys:\n",
  "z - toogle color mode and two-color mode\n",
  "q, F10, Ctrl-c - quit program\n",
  "u - sort table by username\n",
  "c - sort table by first column\n",
  "r - sort table by second column\n",
  "w - sort table by third column\n",
  "l - sort table by restrict level\n",
  "t - sort table by time to end restrict\n",
  "Control keys, that sort table, displays into header of table bold and underlined symbol.\n",
  "Sorted field will be highlighted by *.\n",
  "CAUSE field shows current stage, reason for restriction and number of seconds before restriction will be lifted:\n",
  "Values of column 'CAUSE' - cause of restriction or freezing:\n",
  "Possible stages: - - OK, 1 - Restriction 1, 2 - Restriction 2, 3 - Restriction 3, F -- Account Frozen\n",
  "c - current (current value of parameter)\n",
  "s - short (average value of 5 last values of parameter)\n",
  "m - middle (average value of 15 last values of parameter)\n",
  "l - long (average value of 30 last values of parameter)\n",
  "and parameter which is cause of restriction\n",
  "F/s:busy_time/12 - frozen account with short average restriction by busy_time and 12 seconds left etc.\n",
  "Displays field in table:\n",
  "current value/middle value/long value\n"
};
