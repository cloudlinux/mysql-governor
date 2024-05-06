/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */
#include <signal.h>

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <ncurses.h>
#include "data.h"
#include "stats.h"
#include "errno.h"
#include <math.h>
#include <getopt.h>
#include <time.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <execinfo.h>

#include "wrappers.h"
#include "dbgovernor_string_functions.h"

#include "help.h"

void printHeader (void);
void *screen_regenerate (void);
char *print_formatted_user_name (char *name, char *buf);

static void
dumpstack (FILE * f)
{
	static void *backbuf[50];
	int levels;

	levels = backtrace (backbuf, 50);
	backtrace_symbols_fd (backbuf, levels, fileno (f));

	return;
}

void
get_signal (int signo)
{
	FILE *dbtop_log_err;

	dbtop_log_err = fopen ("/tmp/dbtop_log_err.log", "a+");
	if (dbtop_log_err != NULL)
	{
		fprintf (dbtop_log_err,
			"------------------------Signal no=%d-----------------------\n",
			signo);
		dumpstack (dbtop_log_err);
		fclose (dbtop_log_err);
	}
	exit (0);
}

int
connect_to_server_dbtop (void)
{
	int s, len;
	struct sockaddr_un saun;

	/*
	* Get a socket to work with.  This socket will
	* be in the UNIX domain, and will be a
	* stream socket.
	*/
	if ((s = socket (AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		return -1;
	}

	/*
	* Create the address we will be connecting to.
	*/
	saun.sun_family = AF_UNIX;
	strcpy (saun.sun_path, SOCK_ADDRESS);

	/*
	* Try to connect to the address.  For this to
	* succeed, the server must already have bound
	* this address, and must have issued a listen()
	* request.
	*
	* The third argument indicates the "length" of
	* the structure, not just the length of the
	* socket name.
	*/
	len = sizeof (saun.sun_family) + strlen (saun.sun_path);

	if (connect (s, (struct sockaddr *) &saun, len) < 0)
	{
		close (s);
		return -2;
	}

	return s;
}

#define init_screen() int screen_height, screen_weight; \
	initscr(); \
	getmaxyx(stdscr, screen_height, screen_weight)
#define end_screen()  endwin()
#define getW() screen_weight
#define getH() screen_height
#define NEWLINE 1
#define NONEWLINE 0

#define GINT_COMPARE_FUNCTION_NAME(x) gint_compare_by_## x
#define GINT_COMPARE_FUNCTION(x) gint \
gint_compare_by_## x(gconstpointer ptr_a, gconstpointer ptr_b) \
{ \
	Account *a, *b; \
	a = (Account *) ptr_a; \
	b = (Account *) ptr_b; \
	if (a->current.x > b->current.x) \
	{ \
		return (-1); \
	} \
	if (a->current.x == b->current.x) \
	{ \
		return strncmp(a->id, b->id, USERNAMEMAXLEN); \
	} \
	return (1); \
}

#define CTRLC 3

FILE *in;
FILE *out;
int _socket;

int sort_type = 0, screen_view = 1, is_colorize = 1;
volatile int refresh_time = 1;

GList *accounts = NULL;
GList *recv_accounts = NULL;

void
closesock (void)
{
	if (in)
	{
		fclose (in);
		in = NULL;
	}
	if (out)
	{
		fclose (out);
		out = NULL;
	}
	if (_socket > 0)
	{
		close (_socket);
		_socket = 0;
	}
}

GINT_COMPARE_FUNCTION (cpu);
GINT_COMPARE_FUNCTION (read);
GINT_COMPARE_FUNCTION (write)

gint gint_compare_by_restrict (gconstpointer ptr_a, gconstpointer ptr_b)
{
	Account *a, *b;
	a = (Account *) ptr_a;
	b = (Account *) ptr_b;
	if (a->timeout > b->timeout)
	{
		return (-1);
	}
	if (a->timeout == b->timeout)
	{
		return 0;
	}
	return (1);
}

;

static int
getTimeToEnd (Account * ac)
{
	return (((ac->start_count + ac->timeout) - time (NULL)) < 0) ? 0
		: ((ac->start_count + ac->timeout) - time (NULL));
}

gint
gint_compare_by_tte (gconstpointer ptr_a, gconstpointer ptr_b)
{
	Account *a, *b;
	a = (Account *) ptr_a;
	b = (Account *) ptr_b;
	int tte_a = getTimeToEnd (a);
	int tte_b = getTimeToEnd (b);
	if (tte_a > tte_b)
	{
		return (-1);
	}
	if (tte_a == tte_b)
	{
		return 0;
	}
	return (1);
}

gint
gint_compare_by_username (gconstpointer ptr_a, gconstpointer ptr_b)
{
	Account *a, *b;
	a = (Account *) ptr_a;
	b = (Account *) ptr_b;
	return strncmp (a->id, b->id, USERNAMEMAXLEN);
}

char *
getRestrictInfo (Account * ac, char *buffer)
{
	char ch;
	if (ac->info.field_restrict == NO_PERIOD)
	{
		strcpy (buffer, "");
		return buffer;
	}
	else
	{
		switch (ac->info.field_restrict)
		{
			case CURRENT_PERIOD:
				ch = 'c';
				break;
			case SHORT_PERIOD:
				ch = 's';
				break;
			case MID_PERIOD:
				ch = 'm';
				break;
			case LONG_PERIOD:
				ch = 'l';
				break;
			default:
				ch = 'u';
		};

		switch (ac->info.field_level_restrict)
		{
			case CPU_PARAM:
				sprintf (buffer, "%c:%s/", ch, "cpu");
				break;
			case READ_PARAM:
				sprintf (buffer, "%c:%s/", ch, "read");
				break;
			case WRITE_PARAM:
				sprintf (buffer, "%c:%s/", ch, "write");
				break;
			default:
				sprintf (buffer, "%c:%s/", ch, "unk");
		}
		return buffer;
	}
}

int
str_real_len (char *str)
{
	int ln = 0;
	while (*str)
	{
		str++;
		if (*str != '+')
			ln++;
	}
	return ln;
}

void
printString2 (char *str, int attr, int len, int endline)
{
	static int idx = 0;
	int screen_height, screen_weight;

	getmaxyx (stdscr, screen_height, screen_weight);
	if ((screen_weight - 1) == 0)
		return;

	int ln = (str_real_len (str) > len) ? len : str_real_len (str);
	chtype ch;
	for (idx = 0; idx < len; idx++)
	{
		if (idx > screen_weight)
		{
			endline = 1;
			break;
		}
		else
		{
			if (idx < ln)
			{
				if (str[idx] == '+')
					ch = str[++idx] | attr | A_BOLD | A_UNDERLINE;
				else
					ch = str[idx] | attr;
			}
			else
				ch = ' ' | attr;
			addch (ch);
		}
	}

	if (endline)
	{
		printw ("\n");
	}
}

void
printString (char *str, int attr, int len, int endline)
{
	static int x_counter = 0;
	int screen_height, screen_weight, counter;

	getmaxyx (stdscr, screen_height, screen_weight);
	if (x_counter >= (screen_weight - 1))
	{
		if (endline)
		{
			x_counter = 0;
		}
		return;
	}
	int isend = 0;
	int ln = (str_real_len (str) > len) ? len : str_real_len (str);
	int spaces = len - ln;
	int index = 0;
	int string_counter = 0;
	chtype ch;
	for (index = 0; index < len; index++)
	{
		if (x_counter >= (screen_weight - 1))
		{
			printw ("\n");
			isend = 1;
			break;
		}
		else
		{
			if (index < ln)
			{
				if (str[string_counter] == '+')
				{
					string_counter++;
					ch = str[string_counter] | attr | A_BOLD | A_UNDERLINE;
					addch (ch);
					string_counter++;
				}
				else
				{
					ch = str[string_counter] | attr;
					addch (ch);
					string_counter++;
				}
			}
			else
			{
				ch = ' ' | attr;
				addch (ch);
			}
			x_counter++;
		}
		}
	if (endline && !isend)
	{
		printw ("\n");
		x_counter = 0;
	}
	if (endline)
	{
		x_counter = 0;
	}
}

void
formatIntNumber (long long int number, char *formatString, int len)
{
	int needChars = 0;
	long long int tmpNumber = abs (number);
	while (tmpNumber > 0)
	{
		needChars++;
		tmpNumber /= 10;
	}
	if (needChars < len)
	{
		sprintf (formatString, "%lld", number);
	}
	else if ((needChars - 3) < (len - 1))
	{
		sprintf (formatString, "%lldK", (number + 500) / 1000);
	}
	else if ((needChars - 6) < (len - 1))
	{
		sprintf (formatString, "%lldM", (number + 500000) / 1000000);
	}
	else if ((needChars - 9) < (len - 1))
	{
		sprintf (formatString, "%lldG", (number + 500000000) / 1000000000);
	}
	else
	{
		sprintf (formatString, "Ovf");
	}
	return;
}

void
formatIntString (char *buffer, int amount, char *delim, ...)
{
	int i;
	long val;
	char data[1024] = "";
	va_list vl;
	va_start (vl, delim);
	strcpy (buffer, "");
	for (i = 0; i < amount; i++)
	{
		val = va_arg (vl, long);
		formatIntNumber (val, data, 6);
		if (!strcmp (buffer, ""))
			strcat (buffer, data);
		else
		{
			strcat (buffer, delim);
			strcat (buffer, data);
		}
	}
	va_end (vl);
	return;
}

void
_free_account (Account * ac)
{
	free ((void *) ac->id);
	free (ac);
}

void
_copy_to_showed_accounts (Account * ac)
{
	Account *tmp_ac;
	tmp_ac = malloc (sizeof (Account));
	tmp_ac->id = malloc (sizeof (username_t));
	tmp_ac->users = NULL;
	strlcpy (tmp_ac->id, ac->id, sizeof (username_t));
	memcpy (&tmp_ac->current, &ac->current, sizeof (Stats));
	memcpy (&tmp_ac->short_average, &ac->short_average, sizeof (Stats));
	memcpy (&tmp_ac->mid_average, &ac->mid_average, sizeof (Stats));
	memcpy (&tmp_ac->long_average, &ac->long_average, sizeof (Stats));
	tmp_ac->restricted = ac->restricted;
	tmp_ac->timeout = ac->timeout;
	tmp_ac->start_count = ac->start_count;
	memcpy (&tmp_ac->info, &ac->info, sizeof (restrict_info));

	accounts = g_list_append (accounts, tmp_ac);
}

char
getRestrictChar (GOVERNORS_PERIOD_NAME restrict_level)
{
	char ch;
	switch (restrict_level)
	{
		case 0:
			ch = '1';
			break;
		case 1:
			ch = '2';
			break;
		case 2:
			ch = '3';
			break;
		case 1000:
			ch = 'R';
			break;
		default:
			ch = '4';
	}
	return ch;
}

void
print_account_screen1 (Account * ac)
{
	int x, y;
	char buf[1024];
	char stringBuf[1024];

	memset (buf, 0, sizeof (buf));
	memset (stringBuf, 0, sizeof (stringBuf));
	snprintf (stringBuf, 1024, "%s", print_formatted_user_name (ac->id, buf));
	printf ("%-18s ", stringBuf);
	printString (buf, A_BOLD, 17, NONEWLINE);

	memset (buf, 0, sizeof (buf));
	memset (stringBuf, 0, sizeof (stringBuf));
	sprintf (buf, "%d/%d/%d ", (int) ceil (fabs (ac->current.cpu * 100.0)),
		(int) ceil (fabs (ac->mid_average.cpu * 100.0)),
		(int) ceil (fabs (ac->long_average.cpu * 100.0)));
	printString (buf, A_NORMAL, 20, NONEWLINE);

	memset (buf, 0, sizeof (buf));
	memset (stringBuf, 0, sizeof (stringBuf));
	formatIntString (stringBuf, 3, "/", ac->current.read, ac->mid_average.read,
			ac->long_average.read);
	sprintf (buf, "%-19s ", stringBuf);
	printString (buf, A_NORMAL, 19, NONEWLINE);

	memset (buf, 0, sizeof (buf));
	memset (stringBuf, 0, sizeof (stringBuf));
	formatIntString (stringBuf, 3, "/", ac->current.write,
			ac->mid_average.write, ac->long_average.write);
	sprintf (buf, "%-17s ", stringBuf);
	printString (buf, A_NORMAL, 17, NONEWLINE);

	memset (buf, 0, sizeof (buf));
	memset (stringBuf, 0, sizeof (stringBuf));
	getRestrictInfo (ac, stringBuf);
	if (ac->info.field_restrict != NO_PERIOD)
	{
		sprintf (buf, "%c/%s%d", getRestrictChar (ac->restricted), stringBuf,
			getTimeToEnd (ac));
	}
	else
	{
		strcpy (buf, "-");
	}
	printString (buf, A_NORMAL, 24, NEWLINE);
}

void
reset_accounts (void)
{
	if (accounts != NULL)
	{
		g_list_foreach (accounts, (GFunc) _free_account, NULL);
		g_list_free (accounts);
		accounts = NULL;
	}
}

void
reset_recv_accounts (void)
{
	if (recv_accounts != NULL)
	{
		g_list_foreach (recv_accounts, (GFunc) _free_account, NULL);
		g_list_free (recv_accounts);
		recv_accounts = NULL;
	}
}

void
sort_accounts (void)
{
	switch (sort_type)
	{
		// 1 screen
		case 0:
			accounts = g_list_sort (accounts, GINT_COMPARE_FUNCTION_NAME (cpu));
			break;
		case 1:
			accounts = g_list_sort (accounts, GINT_COMPARE_FUNCTION_NAME (read));
			break;
		case 2:
			accounts = g_list_sort (accounts, GINT_COMPARE_FUNCTION_NAME (write));
			break;
		case 3:
			accounts = g_list_sort (accounts, gint_compare_by_username);
			break;
		case 4:
			accounts = g_list_sort (accounts, gint_compare_by_restrict);
			break;
		case 5:
			accounts = g_list_sort (accounts, gint_compare_by_tte);
			break;
		default:
			accounts = g_list_sort (accounts, gint_compare_by_username);
	}
}

void *
read_info (void)
{
	Account *ac;
	int new_record;
	int tester = 1;
	while (fread_wrapper (&new_record, sizeof (int), 1, in))
	{
		if (new_record == 1)
		{
			reset_recv_accounts ();
			fwrite_wrapper (&tester, sizeof (int), 1, in);
		}
		else if (new_record == 0)
		{
			ac = malloc (sizeof (Account));
			ac->id = malloc (sizeof (username_t));
			ac->users = NULL;
			dbtop_exch dt;
			if (fread_wrapper (&dt, sizeof (dbtop_exch), 1, in))
			{
				strncpy (ac->id, dt.id, sizeof (username_t));
				memcpy (&ac->current, &dt.current, sizeof (Stats));
				memcpy (&ac->short_average, &dt.short_average, sizeof (Stats));
				memcpy (&ac->mid_average, &dt.mid_average, sizeof (Stats));
				memcpy (&ac->long_average, &dt.long_average, sizeof (Stats));
				memcpy (&ac->restricted, &dt.restricted, sizeof (int));
				memcpy (&ac->timeout, &dt.timeout, sizeof (int));
				memcpy (&ac->info, &dt.info, sizeof (restrict_info));
				memcpy (&ac->start_count, &dt.start_count, sizeof (time_t));
				recv_accounts = g_list_append (recv_accounts, ac);
			}
			else
			{
				perror ("Done");
				exit (0);
			}
		}
		else
		{
			reset_accounts ();
			if (recv_accounts != NULL)
				g_list_foreach (recv_accounts, (GFunc) _copy_to_showed_accounts,
						NULL);
			sort_accounts ();
		}
	}
	return NULL;
}

void
colorize (void)
{
	if (has_colors ())
		is_colorize = 1 - is_colorize;
	else
		is_colorize = 0;
}

void
printOneScreen (void)
{
	GList *l;
	Account *tmp;
	int i, j;
	int screen_height, screen_weight, counter;
	//char header_buf[512];
	//char header_buf[ COLS ];

	clear ();
	getmaxyx (stdscr, screen_height, screen_weight);
	//char header_buf[ getW() ];
	char header_buf[1024];
	if (screen_view == 5)
	{
		for (j = 0; j < HELP_LEN; j++)
		{
			printw ("%s", help[j]);
		}
	}
	else
	{
		counter = 0;
		printHeader ();

		for (l = accounts; l; l = l->next)
		{
			tmp = (Account *) l->data;
			if ((tmp->info.field_level_restrict == NORESTRICT_PARAM)
				&& (tmp->info.field_restrict == NO_PERIOD))
			{
				if (is_colorize)
				attron (COLOR_PAIR (2));
			}
			else if (tmp->info.field_restrict != NO_PERIOD)
			{
				if (is_colorize)
				attron (COLOR_PAIR (3));
			}

			print_account_screen1 (tmp);

			if ((tmp->info.field_level_restrict == NORESTRICT_PARAM)
				&& (tmp->info.field_restrict == NO_PERIOD))
			{
				if (is_colorize)
				attroff (COLOR_PAIR (2));
			}
			else if (tmp->info.field_restrict != NO_PERIOD)
			{
				if (is_colorize)
				attroff (COLOR_PAIR (3));
			}
			if (counter >= (screen_height - 3))
				break;
			counter++;
		}
	}
	refresh ();
}

void
printHeader (void)
{
	int screen_height, screen_weight;
	char header_buf[1024];

	clear ();
	getmaxyx (stdscr, screen_height, screen_weight);
	printString ("h,? - help; z - toggle color-mode; q,F10,Ctrl-c - quit",
			A_NORMAL, getW (), NEWLINE);
	if (is_colorize)
		attron (COLOR_PAIR (1));

	sprintf (header_buf,
		" +User%c          .+cpu(%%)  %c         . +read(B/s)%c        . +write(B/s)   %c . CAUSE    ",
		sort_type == 3 ? '*' : ' ', !sort_type ? '*' : ' ', sort_type
		== 1 ? '*' : ' ', sort_type == 2 ? '*' : ' ');
	printString (header_buf, (is_colorize) ? A_NORMAL : A_REVERSE, getW (),
			NEWLINE);
	if (is_colorize)
		attroff (COLOR_PAIR (1));
}

char *
print_formatted_user_name (char *name, char *buf)
{
	strlcpy (buf, name, USERNAMEMAXLEN);
	int i = 0;
	for (i = 0; i < USERNAMEMAXLEN; i++)
	{
		if ((buf[i] < 32) && (buf[i] > 0))
			buf[i] = '*';
	}
	return buf;
}

void
print_account_screen1_no_curses (Account * ac)
{
	char buf[1024];
	char stringBuf[1024];
	snprintf (stringBuf, 1024, "%s", print_formatted_user_name (ac->id, buf));
	printf ("%-18s ", stringBuf);
	sprintf (stringBuf, "%d/%d/%d ",
		(int) ceil (fabs (ac->current.cpu * 100.0)),
		(int) ceil (fabs (ac->mid_average.cpu * 100.0)),
		(int) ceil (fabs (ac->long_average.cpu * 100.0)));
	printf ("%-20s ", stringBuf);
	formatIntString (stringBuf, 3, "/", ac->current.read, ac->mid_average.read,
			ac->long_average.read);
	printf ("%-21s ", stringBuf);
	formatIntString (stringBuf, 3, "/", ac->current.write,
			ac->mid_average.write, ac->long_average.write);
	printf ("%-18s ", stringBuf);
	getRestrictInfo (ac, stringBuf);
	if (ac->info.field_restrict != NO_PERIOD)
	{
		sprintf (buf, "%c/%s%d", getRestrictChar (ac->restricted), stringBuf,
			getTimeToEnd (ac));
	}
	else
	{
		strcpy (buf, "-");
	}
	printf ("%s\n", buf);
}

void
printOneScreenNoCurses (void)
{
	GList *l;
	Account *tmp;
	char header_buf[512];

	printf
		("  User            . cpu(%%)             .  read(B/s)          .  write(B/s)      . CAUSE  \n");

	sort_type = 3;
	sort_accounts ();
	for (l = accounts; l; l = l->next)
	{
		tmp = (Account *) l->data;

		print_account_screen1_no_curses (tmp);
	}
}

void *
read_keys (void)
{
	time_t start_time = time(NULL);
	time_t current_time = 0;
	int ch = '\0';
	printHeader ();
	screen_regenerate ();
	while (1)
	{
		switch (ch)
		{
			case 'c':
				sort_type = 0;
				sort_accounts ();
				break;
			case 'r':
				sort_type = 1;
				sort_accounts ();
				break;
			case 'w':
				sort_type = 2;
				sort_accounts ();
				break;
			case 'u':
				sort_type = 3;
				sort_accounts ();
				break;
			case 'l':
				sort_type = 4;
				sort_accounts ();
				break;
			case 't':
				sort_type = 5;
				sort_accounts ();
				break;
			case '1':
				screen_view = 1;
				sort_accounts ();
				break;
			case KEY_F (10):
				fflush (stdout);
				end_screen ();
				//closesock();
				exit (0);
				break;
			case CTRLC:
				fflush (stdout);
				end_screen ();
				//closesock();
				exit (0);
				break;
			case 'q':
				fflush (stdout);
				end_screen ();
				//closesock();
				exit (0);
				break;
			case 'h':
			case '?':
				screen_view = 5;
				break;
			case 'z':
				colorize ();
				break;
		}
		current_time = time(NULL);
		if ((current_time - start_time) >= refresh_time)
		{
			screen_regenerate ();
			start_time = current_time;
		}
		ch = getch ();
		if (ch == ERR)
		{
			if ((current_time - start_time) >= refresh_time)
			{
				screen_regenerate ();
				start_time = current_time;
			}
			continue;
		}
	}
	return NULL;
}

void *
screen_regenerate (void)
{
	client_type_t ctt = DBTOPCL;
	fwrite (&ctt, sizeof (client_type_t), 1, out);
	fflush (out);
	read_info ();
	printOneScreen ();

	fclose (in);
	fclose (out);
	_socket = connect_to_server_dbtop ();
	if (_socket >= 0)
	{
		in = fdopen (_socket, "r+");
		out = fdopen (_socket, "w");
	}
	return NULL;
}

static void
end_pgm (int sig)
{
	fflush (stdout);
	end_screen ();
	exit (0);
}

#ifndef NOGOVERNOR
int
main (int argc, char *argv[])
{
	static struct sigaction act;

	act.sa_handler = get_signal;
	sigfillset (&(act.sa_mask));
	sigaction (SIGSEGV, &act, NULL);

	int no_curses = 0;

	extern char *optarg;
	extern int optind, optopt;
	int c, refresh_tmp_time = 0;
	char *endptr;
	while ((c = getopt (argc, argv, ":r:ch")) != -1)
	{
		switch (c)
		{
			case 'r':
				refresh_tmp_time = (int) strtol (optarg, &endptr, 10);
				if ((refresh_tmp_time) && (refresh_tmp_time <= 60))
				{
					refresh_time = refresh_tmp_time;
				}
				break;
			case 'c':
				no_curses = 1;
				break;
			case 'h':
				printf ("Usage: dbtop [parameters]\n");
				printf ("no parameters - standart ncurses mode\n\n");
				printf ("parameters:\n");
				printf
					("-r interval - refresh interval for ncurses mode(in seconds)\n");
				printf ("-c - show one time users list (no ncurses)\n");
				exit (0);
				break;
		}
	}
	_socket = connect_to_server_dbtop ();
	if (_socket >= 0)
	{
		in = fdopen (_socket, "r+");
		out = fdopen (_socket, "w");
	}
	if (!in || !out)
	{
		printf ("Can't connect to socket. Maybe governor is not started\n");
		exit (-1);
	}
	if (no_curses)
	{
		client_type_t ctt = DBTOPCL;
		fwrite (&ctt, sizeof (client_type_t), 1, out);
		fflush (out);
		accounts = NULL;
		recv_accounts = NULL;
		read_info ();
		printOneScreenNoCurses ();
		exit (0);
	}

	///    
	/*client_type_t ctt = DBTOP;
		fwrite(&ctt, sizeof(client_type_t), 1, out);
		fflush(out); */
	accounts = NULL;
	recv_accounts = NULL;
	initscr ();

	signal (SIGALRM, end_pgm);
	signal (SIGHUP, end_pgm);
	signal (SIGPIPE, end_pgm);
	signal (SIGQUIT, end_pgm);
	signal (SIGTERM, end_pgm);
	signal (SIGINT, end_pgm);

	noecho ();
	nonl ();
	intrflush (stdscr, false);
	keypad (stdscr, true);
	curs_set (0);
	if (has_colors ())
	{
		start_color ();
		use_default_colors ();
		init_pair (1, COLOR_GREEN, COLOR_BLUE);
		init_pair (2, COLOR_BLUE, -1);
		init_pair (3, COLOR_RED, -1);
	}
	raw ();
	halfdelay (5);

	read_keys ();
	closesock ();
}
#endif
