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

typedef char name_comm[256];

int
valid_comm (int argc, char **argv)
{
  name_comm level_111[] = { "set", "restrict" };
  name_comm level_110[] = { "ignore", "monitor", "delete", "unrestrict" };
  name_comm level_100[] =
    { "list", "list-restricted", "unrestrict-all", "list-restricted-shm", "dbupdate" };

  char _tmp_arg[11];
  _tmp_arg[0] = '\0';
  strlcpy (_tmp_arg, argv[1], sizeof (_tmp_arg));

  if (strcmp ("--help", argv[1]) == 0 ||
      strcmp ("--version", argv[1]) == 0 ||
      strcmp ("--lve-mode", _tmp_arg) == 0)
    {
      return 1;
    }

  int val_comm = 0;
  int i = 0;
  for (i = 0; i < 5; i++)
    if (strcmp (level_100[i], argv[1]) == 0)
      val_comm++;
  for (i = 0; i < 4; i++)
    if (strcmp (level_110[i], argv[1]) == 0)
      val_comm++;
  for (i = 0; i < 2; i++)
    if (strcmp (level_111[i], argv[1]) == 0)
      val_comm++;

  if (!val_comm)
    return 0;

  for (i = 0; i < 5; i++)
    {
      if (strcmp (level_100[i], argv[1]) == 0)
    if (!(!strcmp(argv[1], "list") && (argc == 3)) && (argc > 2))
	  {
	    printf ("Incorrect syntax. Command %s shouldn't has any parameter\n", argv[1]);
	    return 0;
	  }
    }

  for (i = 0; i < 4; i++)
    {
      if (strcmp (level_110[i], argv[1]) == 0)
	{
	  if (argc != 3)
	    {
	      printf ("Incorrect syntax. Command %s should has 3 parameters\n", argv[1]);
	      return 0;
	    }
	  else
	    {
	      int j = 0;
	      for (j = 0; j < 5; j++)
		if (strcmp (level_100[j], argv[2]) == 0)
		  {
		    printf ("Incorrect syntax. Both parameters %s and %s can't be used together\n", argv[1], argv[2]);
		    return 0;
		  }

	      for (j = 0; j < 4; j++)
		if (strcmp (level_110[j], argv[2]) == 0)
		  {
		    printf ("Incorrect syntax. Both parameters %s and %s can't be used together\n", argv[1], argv[2]);
		    return 0;
		  }

	      for (j = 0; j < 2; j++)
		if (strcmp (level_111[j], argv[2]) == 0)
		  {
		    printf ("Incorrect syntax. Both parameters %s and %s can't be used together\n", argv[1], argv[2]);
		    return 0;
		  }

	      if (strcmp ("default", argv[2]) == 0)
		{
		  printf ("Incorrect syntax. default in parameter can't use with this command\n");
		  return 0;
		}
	    }
	}
    }

  for (i = 0; i < 2; i++)
    {
      if (strcmp (level_111[i], argv[1]) == 0)
	{
	  if (argc > 2)
	    {
	      if (strcmp (level_111[i], "set") == 0)
		{
		  if (strcmp ("default", argv[2]) != 0)
		    {
		      int j = 0;
		      for (j = 0; j < 5; j++)
			if (strcmp (level_100[j], argv[2]) == 0)
			  {
			    printf ("Incorrect syntax. Both parameters %s and %s can't be used together\n", argv[1], argv[2]);
			    return 0;
			  }
		      for (j = 0; j < 4; j++)
			if (strcmp (level_110[j], argv[2]) == 0)
			  {
			    printf ("Incorrect syntax. Both parameters %s and %s can't be used together\n", argv[1], argv[2]);
			    return 0;
			  }
		      for (j = 0; j < 2; j++)
			if (strcmp (level_111[j], argv[2]) == 0)
			  {
			    printf ("Incorrect syntax. Both parameters %s and %s can't be used together\n", argv[1], argv[2]);
			    return 0;
			  }
		    }
		  else
		    {
		      if (argc == 3)
			{
			  printf ("Incorrect syntax\n");
			  return 0;
			}
		    }
		}
	      if (strcmp (level_111[i], "restrict") == 0)
		{
		  int j = 0;
		  for (j = 0; j < 5; j++)
		    if (strcmp (level_100[j], argv[2]) == 0)
		      {
			printf ("Incorrect syntax. Both parameters %s and %s can't be used together\n", argv[1], argv[2]);
			return 0;
		      }
		  for (j = 0; j < 4; j++)
		    if (strcmp (level_110[j], argv[2]) == 0)
		      {
			printf ("Incorrect syntax. Both parameters %s and %s can't be used together\n", argv[1], argv[2]);
			return 0;
		      }
		  for (j = 0; j < 2; j++)
		    if (strcmp (level_111[j], argv[2]) == 0)
		      {
			printf ("Incorrect syntax. Both parameters %s and %s can't be used together\n", argv[1], argv[2]);
			return 0;
		      }
		}
	    }
	  else
	    {
	      printf ("Incorrect syntax\n");
	      return 0;
	    }
	}
    }

  return 1;
}

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
  printf ("set                      set parameters for a db_governor\n");

  printf
    ("list         list users & their limits (list all known users in dbgovernor, not just those that have limits set )\n");
  printf
    ("list-restricted          list restricted customers, with their limits, restriction reason, and time period they will still be restricted\n");

  printf ("ignore                   ignore particular user\n");
  printf ("monitor                  cancel ignore particular user\n");
  printf ("delete                   remove limits for user/use defaults\n");

  printf
    ("restrict                 restrict user using lowest level (or if --level specified, using the specified level)\n");
  printf
    ("unrestrict               unrestrict username (configuration file remains unchanged)\n");
  printf
    ("unrestrict-all           unrestrict all restricted users (configuration file remains unchanged)\n");

  printf ("--help                   show this message\n");
  printf ("--version                version number\n");
  printf
    ("--lve-mode               set lve mode 'off|abusers|all|single|on'\n");
  printf
    ("                            'off' - not put user's queries into LVE\n");
  printf
    ("                            'abusers' - when user reaches the limit,\n");
  printf
    ("                                        put user's queries into LVE for that user\n");
  printf
    ("                            'all' - user's queries always run inside LVE for that user - deprecated\n");
  printf
    ("                            'single|on' - single LVE for all abusers. 'on' - deprecated\n");

  printf ("\nparameter:\n");
  printf ("default                  set default parameter\n");
  printf ("username                 set parameter for user\n");

  printf ("\noptions:\n");
  printf ("--cpu=N                  limit CPU   (pct)  usage\n");
  printf ("--read=N                 limit READ  (MB/s) usage (can by k(KB/s), b(BB/s))\n");
  printf ("--write=N                limit WRITE (MB/s) usage (can by k(KB/s), b(BB/s))\n");
  printf ("\noptions for parameter list:\n");
  printf ("--kb                     show limits in Kbytes no pretty print\n");
  printf ("--bb                     show limits in bytes no pretty print\n");
  printf ("--mb                     show limits in Mbytes no pretty print\n");
  printf
    ("--slow=N                 limit time for long running select queries\n");
  printf ("--level=N                level (1,2,3 or 4) specified\n");
}

GList *
GetOptList (int argc, char **argv, int *ret)
{
  int helpflag = 0;
  int verflag = 0;

  struct option loptions[] = {
    {"cpu", required_argument, NULL, 'c'},
    {"read", required_argument, NULL, 'r'},
    {"write", required_argument, NULL, 'w'},
    {"slow", required_argument, NULL, 's'},
    {"level", required_argument, NULL, 'l'},
    {"lve-mode", required_argument, NULL, 100},
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

	    SplitStr *data = NULL;

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
	  break;
	case '?':
	  *ret = 1;
	  return opts;
	  break;
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
  int ret;
  ret = 0;

  char _tmp_arg[11];
  _tmp_arg[0] = '\0';
  strlcpy (_tmp_arg, argv[1], sizeof (_tmp_arg));

  if (!valid_comm (argc, argv))
    return 1;

  if (strcmp ("set", argv[1]) == 0)
    {
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
    }
  else if (strcmp ("ignore", argv[1]) == 0)
    {
      if (argc > 2)
	{
	  if (!ignoreUser (argv[2]))
	    return 2;
	}
      else
	return 1;
    }
  else if (strcmp ("monitor", argv[1]) == 0)
    {
      if (argc > 2)
	{
	  if (!watchUser (argv[2]))
	    return 2;
	}
      else
	return 1;
    }
  else if (strcmp ("delete", argv[1]) == 0)
    {
      if (argc > 2)
	{
	  if (!deleteUser (argv[2]))
	    return 2;
	}
      else
	return 1;
    }
  else if (strcmp ("list", argv[1]) == 0)
    {
      if (argc == 3)
	{
	  if (!strcmp(argv[2], "--bb")) kb_flag = 2;
	  if (!strcmp(argv[2], "--kb")) kb_flag = 1;
	  if (!strcmp(argv[2], "--mb")) kb_flag = 3;
	}
      if (!list(kb_flag, 0) != 0)
	return 2;
    }
  else if (strcmp ("list-restricted", argv[1]) == 0)
    {
      if (!list_restricted ())
	return 2;
    }
  else if (strcmp ("list-restricted-shm", argv[1]) == 0)
    {
      list_restricted_shm ();
    }
  else if (strcmp ("restrict", argv[1]) == 0)
    {
      if (argc > 2)
	{
	  char *_argv = argv[2];
	  GList *list = (GList *) GetOptList (argc, argv, &ret);

	  if (!restrict_user (_argv, (char *) GetVal ('l', list)))
	    return 2;
	}
      else
	return 1;
    }
  else if (strcmp ("unrestrict", argv[1]) == 0)
    {
      if (argc > 2)
	{
	  if (!unrestrict (argv[2]))
	    return 2;;
	}
      else
	return 1;
    }
  else if (strcmp ("unrestrict-all", argv[1]) == 0)
    {
      if (!unrestrict_all ())
	return 2;
    }
  else if (strcmp ("--lve-mode", _tmp_arg) == 0)
    {
      char *_argv = argv[2];
      GList *list = (GList *) GetOptList (argc, argv, &ret);
      if (!setLveMode ((char *) GetVal (100, list)))
	return 2;
    }
  else if (strcmp ("dbupdate", argv[1]) == 0)
    {
      if (!dbupdatecmd())
	return 2;
    }
  else
    {
      GetOptList (argc, argv, &ret);

      int _ret = ret;
      return _ret;
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
