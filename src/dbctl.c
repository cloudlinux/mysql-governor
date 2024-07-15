/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Shkatula Pavel <shpp@cloudlinux.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <ncurses.h>
#include <pthread.h>

#include <glib.h>

#include "dbgovernor_string_functions.h"

#include "dbctl_set.h"
#include "dbctl_list.h"
#include "dbctl_rest.h"
#include "version.h"

int kb_flag = 0;

typedef struct dbclt_options
{
	int option;
	char *val;
} Options;

typedef enum dbctl_keyword_enum
{
	HELP_KWE,
	VERSION_KWE,
	LVE_MODE_KWE,
	LVE_ACCURACY_KWE,
	SET_KWE,
	RESTRICT_KWE,
	IGNORE_KWE,
	MONITOR_KWE,
	DELETE_KWE,
	UNRESTRICT_KWE,
	LIST_KWE,
	LIST_RESTRICTED_KWE,
	UNRESTRICT_ALL_KWE,
	LIST_RESTRICTED_SHM_KWE,
	DBUPDATE_KWE,
	LIST_RAW_KWE,
	LIST_JSON_KWE,
	ERROR_KWE = -1
} dbctl_keyword_t;

static const char HELP_KW[] = "--help";
static const char VERSION_KW[] = "--version";
static const char LVE_MODE_KW[] = "--lve-mode";
static const char LVE_ACCURACY_KW[] = "--lve-improved-accuracy";
static const char SET_KW[] = "set";
static const char RESTRICT_KW[] = "restrict";
static const char IGNORE_KW[] = "ignore";
static const char MONITOR_KW[] = "monitor";
static const char DELETE_KW[] = "delete";
static const char UNRESTRICT_KW[] = "unrestrict";
static const char LIST_KW[] = "list";
static const char LIST_RESTRICTED_KW[] = "list-restricted";
static const char UNRESTRICT_ALL_KW[] = "unrestrict-all";
static const char LIST_RESTRICTED_SHM_KW[] = "list-restricted-shm";
static const char DBUPDATE_KW[] = "dbupdate";
static const char LIST_RAW_KW[] = "list-raw";
static const char LIST_JSON_KW[] = "list-json";

static dbctl_keyword_t
parse_comm (int argc, char **argv);

void
version (void)
{
	printf ("version %s\n", GOVERNOR_CUR_VER);
}

void
usage (void)
{
	puts ("usage: dbctl command [parameter] [options]");
}

void
help (void)
{
	printf ("dbctl ");
	version ();
	usage ();
	printf ("commands:\n");
	printf ("%-24s set parameters for a db_governor\n", SET_KW);

	printf ("%-24s list users & their limits (list all known users in dbgovernor, not just those that have limits set )\n", LIST_KW);
	printf ("%-24s list restricted customers, with their limits, restriction reason, and time period they will still be restricted\n", LIST_RESTRICTED_KW);

	printf ("%-24s ignore particular user\n", IGNORE_KW);
	printf ("%-24s cancel ignore particular user\n", MONITOR_KW);
	printf ("%-24s remove limits for user/use defaults\n", DELETE_KW);

	printf ("%-24s restrict user using lowest level (or if --level specified, using the specified level)\n", RESTRICT_KW);
	printf ("%-24s unrestrict username (configuration file remains unchanged)\n", UNRESTRICT_KW);
	printf ("%-24s unrestrict all restricted users (configuration file remains unchanged)\n", UNRESTRICT_ALL_KW);

	printf ("%-24s show this message\n", HELP_KW);
	printf ("%-24s version number\n", VERSION_KW);
	printf ("%-24s set lve mode 'off|abusers|all|single|on'\n", LVE_MODE_KW);
	printf ("%-27s 'off' - not put user's queries into LVE\n", "");
	printf ("%-27s 'abusers' - when user reaches the limit,\n", "");
	printf ("%-27s             put user's queries into LVE for that user\n", "");
	printf ("%-27s 'all' - user's queries always run inside LVE for that user - deprecated\n", "");
	printf ("%-27s 'single|on' - single LVE for all abusers. 'on' - deprecated\n", "");
	printf ("%-24s set lve improved accuracy algorithm 'off|on'\n", LVE_ACCURACY_KW);

	printf ("\nparameter:\n");
	printf ("%-24s set default parameter\n", "default");
	printf ("%-24s set parameter for user\n", "username");

	printf ("\noptions:\n");
	printf ("%-24s limit CPU   (pct)  usage\n", "--cpu=N");
	printf ("%-24s limit READ  (MB/s) usage (can by k(KB/s), b(BB/s))\n", "--read=N");
	printf ("%-24s limit WRITE (MB/s) usage (can by k(KB/s), b(BB/s))\n", "--write=N");

	printf ("\noptions for parameter list:\n");
	printf ("%-24s show limits in Kbytes no pretty print\n", "--kb");
	printf ("%-24s show limits in bytes no pretty print\n", "--bb");
	printf ("%-24s show limits in Mbytes no pretty print\n", "--mb");
	printf ("%-24s limit time for long running select queries\n", "--slow=N");
	printf ("%-24s level (1,2,3 or 4) specified\n", "--level=N");
}

GList *
GetOptList (int argc, char **argv, int *ret)
{
	int helpflag = 0;
	int verflag = 0;

	struct option loptions[] =
	{
		{"cpu", required_argument, NULL, 'c'},
		{"read", required_argument, NULL, 'r'},
		{"write", required_argument, NULL, 'w'},
		{"slow", required_argument, NULL, 's'},
		{"level", required_argument, NULL, 'l'},
		{"lve-mode", required_argument, NULL, 100},
		{"lve-improved-accuracy", required_argument, NULL, 101},
		{"help", no_argument, &helpflag, 1},
		{"version", no_argument, &verflag, 1},
		{"kb", no_argument, &kb_flag, 1},
		{"bb", no_argument, &kb_flag, 2},
		{"mb", no_argument, &kb_flag, 3},
		{0, 0, 0, 0}
	};

	GList *opts = NULL;
	int opt;
	while ((opt = getopt_long (argc, argv, "c:r:w:s:", loptions, NULL)) != -1)
	{
		switch (opt)
		{
			case 'c':
			case 'r':
			case 'w':
				{
					Options *_opts;
					_opts = malloc (sizeof (Options));
					_opts->option = opt;
					_opts->val = optarg;

					SplitStr *data = NULL;
					int res = split (&data, optarg, ',');
					if (!res)
					{
					puts ("Error format parameter!");
					exit (0);
					}
					release_split (data, res);

					opts = g_list_append (opts, _opts);
				}
				break;
			case 's':
				{
					Options *_opts;
					_opts = malloc (sizeof (Options));
					_opts->option = opt;
					_opts->val = optarg;

					opts = g_list_append (opts, _opts);
				}
				break;
			case 'l':
				{
					Options *_opts;
					_opts = malloc (sizeof (Options));
					_opts->option = opt;
					_opts->val = optarg;

					opts = g_list_append (opts, _opts);
				}
				break;
			case 100:
			case 101:
				{
					Options *_opts;
					_opts = malloc (sizeof (Options));
					_opts->option = opt;
					_opts->val = optarg;

					opts = g_list_append (opts, _opts);
				}
				break;
			case 0:
				break;
			case ':':
				*ret = 1;
				return opts;
			case '?':
				*ret = 1;
				return opts;
		}
	}

	if (opts == NULL)
	{
		if (helpflag == 1)
		{
			help ();
			*ret = 0;
			return NULL;
		}
		if (verflag == 1)
		{
			version ();
			*ret = 0;
			return NULL;
		}
	}

	*ret = 0;
	return opts;
}

char *
GetVal (char opt, GList * list)
{
	GList *opts = NULL;
	for (opts = g_list_first (list); opts != NULL; opts = g_list_next (opts))
	{
		Options *_opts = (Options *) opts->data;
		if (_opts->option == opt)
			return _opts->val;
	}

	return NULL;
}

int
GetCmd (int argc, char **argv)
{
	int ret = 0;

	dbctl_keyword_t kw = parse_comm(argc, argv);
	if (kw == ERROR_KWE)
		return 1;

	switch (kw)
	{
		case ERROR_KWE:
			return 1;

		case HELP_KWE:
		case VERSION_KWE:
		default:
			GetOptList (argc, argv, &ret);
			return ret;

		case LVE_MODE_KWE:
			{
				GList *list = (GList *) GetOptList (argc, argv, &ret);
				if (!setLveMode ((char *) GetVal (100, list)))
					return 2;
			}
			break;

		case LVE_ACCURACY_KWE:
			{
				GList *list = (GList *) GetOptList (argc, argv, &ret);
				if (!setLveAccuracy ((char *) GetVal (101, list)))
					return 2;
			}
			break;

		case SET_KWE:
			if (argc > 2)
			{
				char *_argv = argv[2];
				GList *list = (GList *) GetOptList (argc, argv, &ret);

				if (strcmp ("default", _argv) == 0)
				{
					if (!setDefault ((char *) GetVal ('c', list),
						(char *) GetVal ('r', list), (char *) GetVal ('w', list),
						(char *) GetVal ('s', list)))
						return 2;
				}
				else
				{
					if (!setUser (_argv, (char *) GetVal ('c', list),
						(char *) GetVal ('r', list), (char *) GetVal ('w', list),
						(char *) GetVal ('s', list)))
						return 2;
				}
			}
			else
				return 1;
			break;

		case RESTRICT_KWE:
			if (argc > 2)
			{
				char *_argv = argv[2];
				GList *list = (GList *) GetOptList (argc, argv, &ret);

				if (!restrict_user (_argv, (char *) GetVal ('l', list)))
					return 2;
			}
			else
				return 1;
			break;

		case IGNORE_KWE:
			if (argc > 2)
			{
				if (!ignoreUser (argv[2]))
					return 2;
			}
			else
				return 1;
			break;

		case MONITOR_KWE:
			if (argc > 2)
			{
				if (!watchUser (argv[2]))
					return 2;
			}
			else
				return 1;
			break;

		case DELETE_KWE:
			if (argc > 2)
			{
				if (!deleteUser (argv[2]))
					return 2;
			}
			else
				return 1;
			break;

		case UNRESTRICT_KWE:
			if (argc > 2)
			{
				if (!unrestrict (argv[2]))
					return 2;;
			}
			else
				return 1;
			break;

		case LIST_KWE:
		case LIST_RAW_KWE:
			if (argc == 3)
			{
				if (!strcmp(argv[2], "--bb")) kb_flag = 2;
				if (!strcmp(argv[2], "--kb")) kb_flag = 1;
				if (!strcmp(argv[2], "--mb")) kb_flag = 3;
			}
			if (!list_all(kb_flag, 0, (kw==LIST_RAW_KWE)) != 0)
				return 2;
			break;

		case LIST_JSON_KWE:
			if (argc == 3)
			{
				if (!strcmp(argv[2], "--bb")) kb_flag = 2;
				if (!strcmp(argv[2], "--kb")) kb_flag = 1;
				if (!strcmp(argv[2], "--mb")) kb_flag = 3;
			}
			if (!list_all_json(kb_flag))
				return 2;
			break;

		case LIST_RESTRICTED_KWE:
			if (!list_restricted ())
				return 2;
			break;

		case UNRESTRICT_ALL_KWE:
			if (!unrestrict_all ())
				return 2;
			break;

		case LIST_RESTRICTED_SHM_KWE:
			list_restricted_shm ();
			break;

		case DBUPDATE_KWE:
			if (!dbupdatecmd())
				return 2;
			break;
	}
	return 0;
}

int
main (int argc, char **argv)
{
	int ret = 1;

	if (argc < 2 || (ret = GetCmd(argc, argv)) == 1)
		usage ();

	return ret;
}


typedef struct parse_info_t
{
	dbctl_keyword_t kwe;
	const char *kw;
	size_t kwlen;          /* ==0 for full compare, >0 for prefix compare */
	int min_argc;          /* ==-1 if not used */
	int min_argc_default;  /* alternative min_argc: ==-1 if not used */
	int max_argc;          /* ==-1 if not used */
} parse_info_t;


#define PARSE_INFO_ENTRY(nm, min1, min2, max1) { nm##_KWE, nm##_KW, 0, min1, min2, max1 }

static const parse_info_t parse_info[] =
{
	// args are ignored
	PARSE_INFO_ENTRY(HELP, -1, -1, -1),
	PARSE_INFO_ENTRY(VERSION, -1, -1, -1),
	{ LVE_MODE_KWE, LVE_MODE_KW, sizeof LVE_MODE_KW - 1, -1, -1, -1 },
	{ LVE_ACCURACY_KWE, LVE_ACCURACY_KW, sizeof LVE_ACCURACY_KW - 1, -1, -1, -1 },

	// min 3 args for user, min 4 args for default
	PARSE_INFO_ENTRY(SET, 3, 4, -1),

	// min 3 args
	PARSE_INFO_ENTRY(RESTRICT, 3, -1, -1),

	// 3 args exact
	PARSE_INFO_ENTRY(IGNORE, 3, -1, 3),
	PARSE_INFO_ENTRY(MONITOR, 3, -1, 3),
	PARSE_INFO_ENTRY(DELETE, 3, -1, 3),
	PARSE_INFO_ENTRY(UNRESTRICT, 3, -1, 3),

	// 2 or 3 args
	PARSE_INFO_ENTRY(LIST, -1, -1, 3),
	PARSE_INFO_ENTRY(LIST_RAW, -1, -1, 3),
	PARSE_INFO_ENTRY(LIST_JSON, -1, -1, 3),

	// 2 args exact
	PARSE_INFO_ENTRY(LIST_RESTRICTED, -1, -1, 2),
	PARSE_INFO_ENTRY(UNRESTRICT_ALL, -1, -1, 2),
	PARSE_INFO_ENTRY(LIST_RESTRICTED_SHM, -1, -1, 2),
	PARSE_INFO_ENTRY(DBUPDATE, -1, -1, 2)
};

static int
check_argc(const parse_info_t *cur, int argc, char **argv)
{
	int n;

	if (cur->min_argc > 0 && argc < cur->min_argc)
	{
		n = cur->min_argc-2;
		printf("Incorrect syntax: \"%s\" command requires at least %d parameter%s\n", cur->kw, n, n>1?"s":"");
		return -1;
	}

	if (cur->min_argc_default > 0 && !strcmp(argv[2], "default") && argc < cur->min_argc_default)
	{
		n = cur->min_argc_default-2;
		printf("Incorrect syntax: \"%s\" command in \"default\" mode requires at least %d parameter%s\n", cur->kw, n, n>1?"s":"");
		return -1;
	}

	if (cur->max_argc > 0 && argc > cur->max_argc)
	{
		n = cur->max_argc-2;
		if (n > 0)
			printf("Incorrect syntax: \"%s\" command requires no more than %d parameter%s\n", cur->kw, n, n>1?"s":"" );
		else
			printf("Incorrect syntax: \"%s\" command shouldn't have any parameter\n", cur->kw);
		return -1;
	}
	return 0;
}

static dbctl_keyword_t
parse_comm (int argc, char **argv)
{
	int i;
	const char *cmd = argv[1];
	static const int parse_info_num = sizeof parse_info / sizeof parse_info[0];

	for (i=0; i < parse_info_num; ++i)
	{
		const parse_info_t *cur = parse_info + i;
		if (cur->kwlen ? strncmp(cmd, cur->kw, cur->kwlen) : strcmp(cmd, cur->kw) )
			continue;

		return check_argc(cur, argc, argv) ? ERROR_KWE : cur->kwe;
	} //for (i=0; i < parse_info_num; ++i)
	printf("Incorrect syntax: unknown command \"%s\"\n", cmd );
	return ERROR_KWE;
}
