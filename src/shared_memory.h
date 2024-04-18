/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef SHARED_MEMORY_H_
#define SHARED_MEMORY_H_

#ifdef HAVE_MMAP64
#define cl_mmap(a,b,c,d,e,f)    mmap64(a,b,c,d,e,f)
#else
#define cl_mmap(a,b,c,d,e,f)    mmap(a,b,c,d,e,f)
#endif
#define cl_munmap(a,b)          munmap((a),(b))

int init_bad_users_list (void);
void clear_bad_users_list (void);
int remove_bad_users_list (void);
int is_user_in_list (const char *username);
int add_user_to_list (const char *username, int is_all);
int delete_user_from_list (char *username);
long get_users_list_size (void);
void printf_bad_users_list (void);
int delete_allusers_from_list (void);

int32_t is_user_in_bad_list_cleint (char *username);
int init_bad_users_list_client (void);
int init_bad_users_list_client_without_init (void);
int remove_bad_users_list_client (void);
int32_t is_user_in_bad_list_cleint_persistent (char *username);
int user_in_bad_list_cleint_show (void);
int init_bad_users_list_utility (void);
int remove_bad_users_list_utility (void);
int init_bad_users_list_if_not_exitst (void);
void printf_bad_list_cleint_persistent (void);
#ifdef TEST
void _print_message_log(char *format, ...);
#define print_message_log(format, mode, ...) do { _print_message_log(format, ##__VA_ARGS__); } while(0)
#else
#define print_message_log(format, mode, ...) do { } while(0)
#endif

#endif /* SHARED_MEMORY_H_ */
