/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef DATA_H_
#define DATA_H_

/* true and false values including*/
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>

/* Max user length in MySQL */
#define USERNAMEMAXLEN 16*4
#define PARAMETERMAXLEN 16*4
typedef char username_t[USERNAMEMAXLEN];
typedef char parameter_t[USERNAMEMAXLEN];

#define _DBGOVERNOR_BUFFER_128  128
#define _DBGOVERNOR_BUFFER_256  256
#define _DBGOVERNOR_BUFFER_512  512
#define _DBGOVERNOR_BUFFER_1024 1024
#define _DBGOVERNOR_BUFFER_2048 2048
#define _DBGOVERNOR_BUFFER_4096 4096
#define _DBGOVERNOR_BUFFER_8192 8192
#define _DBGOVERNOR_BUFFER_HUGE 16384

#ifndef TEST_EMUL
#define SOCK_ADDRESS "/var/run/db-governor"
#define MYSQL_SOCK_ADDRESS "/var/run/db-governor-mysql"
#define CONFIG_PATH "/etc/container/mysql-governor.xml"
#define PID_PATH "/var/run/db-governor.pid"
#else
#define SOCK_ADDRESS "db-governor"
#define MYSQL_SOCK_ADDRESS "db-governor-mysql"
#define CONFIG_PATH "db-governor.xml"
#define PID_PATH "db-governor.pid"
#endif

#define PATH_TO_GOVERNOR_STATS "/var/lve/dbgovernor/"
#define PATH_TO_LOG_USER_QUERIES "/var/lve/dbgovernor-store/"

#define DBUSER_MAP_FILE "/etc/container/dbuser-map"
#define DUPLICATE_CONFIG_PATH "/var/run/mysql-governor-config.xml"

#define BAD_LVE 3

/* Network names identificators */
typedef enum client_type_enum
{
  DBDUMPER = 0, DBTOP, DBEXIT, DBCTL, DBTOPCL
} client_type_t;

typedef enum dbctl_command_enum
{
  SET =
    0, IGNORE, DELETE, LIST, LIST_R, RESTRICT, UNRESTRICT, UNRESTRICT_A,
    LOG_PATH, REREAD_CFG, REINIT_USERS_LIST, DBUSER_MAP_CMD
} dbctl_command_l;

typedef enum
{ TEST_MODE,
  PRODUCTION_MODE,
  DEBUG_MODE,
  ERROR_MODE,
  RESTRICT_MODE,
  NORESTRICT_MODE,
  IGNORE_MODE,
  OLD_RESTRICT_MODE,
  NEW_RESTRICT_MODE
} MODE_TYPE;

typedef struct
{
  long _current, _short, _mid, _long;
} T_LONG;

typedef enum
{
  NORESTRICT_PARAM2 = 0,
  CPU_PARAM = 4,
  READ_PARAM,
  WRITE_PARAM,
  NORESTRICT_PARAM = 100,
} GOVERNORS_FIELD_NAME;

/*Period types*/
typedef enum
{
  NO_PERIOD = 0,
  CURRENT_PERIOD,
  SHORT_PERIOD,
  MID_PERIOD,
  LONG_PERIOD
} GOVERNORS_PERIOD_NAME;

typedef struct dbctl_options_struct
{
  username_t username;
  int cpu;
  int read;
  int write;
  int level;
  int timeout;
  int user_max_connections;

} DbCtlOptions;

typedef struct user_statistics_struct_cfg
{
  T_LONG cpu;
  T_LONG write;
  T_LONG read;
  T_LONG slow;
  bool account_flag;		// true == account ("name" attribute), false == "mysql_name" attribute
  MODE_TYPE mode;		// RESTRICT_MODE|NORESTRICT_MODE|IGNORE_MODE (default = RESTRICT_MODE)
} Stats_cfg;

typedef struct user_statistics_struct
{
  double cpu;
  long long write;
  long long read;
} Stats;

typedef Stats stats_limit;
typedef Stats_cfg stats_limit_cfg;

#define CD_MAGIC 0xDEADBEEF
typedef struct _client_data
{
  int magic;
  int type;
  pid_t tid;
  pid_t pid;
  char username[USERNAMEMAXLEN];
  long long cpu;
  long long write;
  long long read;
  time_t update_time;
  long naoseconds;
  struct timeval utime;
  struct timeval stime;
} client_data;

typedef struct restrict_info_struct
{
  GOVERNORS_PERIOD_NAME field_restrict;
  GOVERNORS_FIELD_NAME field_level_restrict;
} restrict_info;

/* Restrict command enumerator */
typedef enum command_enum
{
  EXIT = 0, FREEZE, UNFREEZE, SLOWQUERY
} command_t;

typedef struct mysql_command_struct
{
  username_t username;
  command_t command;
  int restrict_level;
  long id;
} Command;

typedef struct mysql_dbctl_command_struct
{
  dbctl_command_l command;
  parameter_t parameter;
  DbCtlOptions options;

} DbCtlCommand;

//Network exchange data
typedef struct _dbtop_exch
{
  username_t id;
  Stats current;
  Stats short_average;
  Stats mid_average;
  Stats long_average;
  int restricted;
  int timeout;
  restrict_info info;
  time_t start_count;
} dbtop_exch;

typedef struct __dbgov_statitrics
{
  char username[USERNAMEMAXLEN];
  int max_simultaneous_requests;

  double sum_cpu;		// in %
  double sum_write;		// in MB/s
  double sum_read;		// in MB/s

  int number_of_iterations;	// number of measurements per period

  double max_cpu;		// in %
  double max_write;		// in MB/s
  double max_read;		// in MB/s

  int number_of_restricts;

  long limit_cpu_on_period_end;	//in %
  long limit_read_on_period_end;	//in MB/s
  long limit_write_on_period_end;	//in MB/s

  int cause;
  MODE_TYPE ignored;

} dbgov_statitrics;

typedef struct _user_map
{
  username_t username;
  int uid;
  username_t account_name;
} UserMap;

#endif /* DATA_H_ */
