#!/opt/cloudlinux/venv/bin/python3
# coding:utf-8

# Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2024 All Rights Reserved
#
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENSE.TXT
#

import sentry_sdk
import subprocess
import argparse
import datetime
import struct
import mmap
import sys
import os
from ctypes import sizeof, c_byte, c_char, c_int32, c_long, Structure, Union

USERNAMEMAXLEN = 64
MAX_ITEMS_IN_TABLE = 100000

BAD_USER_LIST_FILE = "/var/lve/dbgovernor-shm/governor_bad_users_list"
WATCHDOG_LOG_FILE = "/var/log/governor-watchdog.log"
SENTRY_DSN_FILE = "/usr/share/lve/dbgovernor/sentry_dsn"
DBCTL_BIN = '/usr/share/lve/dbgovernor/utils/dbctl_orig'
LVEPS_BIN = '/usr/sbin/lveps'

def sizeof_sem_t():
    """
    This function calculates and returns the size of sem_t depending on the system architecture.
    It checks if the system is 64-bit or 32-bit and accordingly sets the size of C structure sem_t.
    It is required to keep memory order while reading restricted users from the shared memory file.

    Returns:
        int: size of sem_t
    """

    # Check if the system is 64-bit or 32-bit
    if struct.calcsize("P") * 8 == 64:
        sizeof_sem_t = 32
    else:
        sizeof_sem_t = 16

    # Define sem_t using ctypes
    class SemT(Union):
        _fields_ = [
            ("__size", c_char * sizeof_sem_t),
            ("__align", c_long)
        ]

    return sizeof(SemT)


def read_sentry_dsn_from_file(path=SENTRY_DSN_FILE):
    """
    Reads the Sentry DSN from the file.
    Args:
        path (str): Path to the file containing the Sentry DSN.
    Returns: Sentry DSN or None if the file is not found.
    """
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception as e:
        return


class ItemStructure(Structure):
    _fields_ = [
        ('username', c_char * USERNAMEMAXLEN),
        ('uid', c_int32)
    ]

class ShmStructure(Structure):
    _fields_ = [
        ('sem', c_byte * sizeof_sem_t()),  # Placeholder for the semaphore
        ('numbers', c_int32),
        ('items', ItemStructure * MAX_ITEMS_IN_TABLE)
    ]


sentry_sdk.init(
    dsn = read_sentry_dsn_from_file(),
    traces_sample_rate = 1.0
)


def sentry_log(message, level="info"):
    """
    Logs message to Sentry if DSN is available.
    Args:
        message (str): The message to be logged.
        level (str, optional): The level of the log. Defaults to "info".
    """
    sentry_sdk.capture_message(message, level)


def log_message(message, level="info", log_to_file=False):
    """
    Logs a message to stdout and Sentry (if it's an error). Optionally, logs to a file.
    Args:
        message (str): The message to log.
        level (str, optional): The log level. Defaults to "info".
        log_to_file (bool, optional): Whether to log to a file. Defaults to False.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} [{level}] {message}\n"

    # Print to stdout
    print(log_entry.strip())

    # Log to Sentry if it's an error
    if level == "error":
        sentry_log(message, level)

    # Write to log file
    if log_to_file:
        try:
            with open(WATCHDOG_LOG_FILE, "a+") as log_file:
                log_file.write(log_entry)
        except PermissionError:
            print(f"Permission denied: Unable to write to {WATCHDOG_LOG_FILE}.")
        except OSError as e:
            print(f"Error opening or writing to {WATCHDOG_LOG_FILE}: {e}")
        except Exception as e:
            print(f"Unexpected error while opening file {WATCHDOG_LOG_FILE}: {e}")


def get_lve_user_list(log_to_file=False):
    """
    Retrieves LVE users by running lveps command.
    Args:
        log_to_file (bool): If True, logs messages to a file.
    Returns:
        List of users in LVE.
    """
    if not os.path.exists(LVEPS_BIN):
        return []

    # Run the lveps command and capture its output
    try:
        result = subprocess.run([LVEPS_BIN, '-n'], text=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        log_message(f"Error running lveps: {e}", "error", log_to_file)
        return []

    # Parse the output
    output = result.stdout
    lines = output.splitlines()
    user_list = []

    # Skip the header line and any potentially empty lines
    for line in lines[1:]:
        if line.strip():  # Check if the line is not empty
            parts = line.split()
            user = parts[0]
            user_list.append(user)

    return user_list


def get_bad_user_list(log_to_file=False):
    """
    Retrieves user list from shared memory.
    Args:
        log_to_file (bool): If True, logs messages to a file.
    Returns:
        List of bad users.
    """
    if not os.path.exists(BAD_USER_LIST_FILE):
        return []

    try:
        fd = os.open(BAD_USER_LIST_FILE, os.O_RDWR)
        buf = mmap.mmap(fd, sizeof(ShmStructure), mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        try:
            shm_structure = ShmStructure.from_buffer_copy(buf)
            user_list = []
            for i in range(shm_structure.numbers):
                user = shm_structure.items[i]
                username = bytes(user.username).decode('utf-8').rstrip('\x00')
                user_list.append((username, user.uid))
        except Exception as e:
            print(f"An error occurred while processing the shared memory: {str(e)}",
                  "error", log_to_file)
            user_list = []
        finally:
            buf.close()
            os.close(fd)
        return user_list
    except OSError as e:
        print(f"Error opening or mapping the shared memory file: {str(e)}", "error", log_to_file)
        return []
    except Exception as e:
        log_message(f"Unexpected error while reading shared memory: {str(e)}", "error", log_to_file)
        return []


def check_bad_user_list(log_to_file=False):
    """
    Checks for restricted users not in LVE and logs them.
    Args:
        log_to_file (bool): If True, logs messages to a file.
    """
    bad_user_list = get_bad_user_list(log_to_file)
    lve_user_list = get_lve_user_list(log_to_file)

    for uid in bad_user_list:
        log_message(f"BAD user: {uid}", "debug", log_to_file)

    for uid in lve_user_list:
        log_message(f"LVE user: {uid}", "debug", log_to_file)

    for username, uid in bad_user_list:
        if uid not in lve_user_list:
            log_message(f"Unrestricted user: {username}, UID={uid}", "error", log_to_file)


def dbctl_check_governor(log_to_file=False):
    """
    Checks if the Governor is responsive by running 'dbctl list'.
    Args:
        log_to_file (bool): If True, logs messages to a file.
    """
    if not os.path.exists(DBCTL_BIN):
        log_message(f"dbctl binary not found at {DBCTL_BIN}", "warn", log_to_file)
        return

    try:
        result = subprocess.run([DBCTL_BIN, 'list'], text=True, check=True, capture_output=True)
        if result.returncode != 0:
            log_message(f"dbctl exit with non-zero value: {result.returncode}, "
                        f"stderr: {result.stderr}, stdout: {result.stdout}",
                        "error", log_to_file)
    except subprocess.CalledProcessError as e:
        log_message(f"Governor is not responsive: exit code={e.returncode}, "
                    f"stderr={e.stderr if e.stderr else 'none'}, "
                    f"stdout={e.stdout if e.stdout else 'none'}",
                    "error", log_to_file)
    except Exception as e:
        log_message(f"Failed to call dbctl command: {str(e)}",
                    "error", log_to_file)


def main(argv):
    """
    Main function that checks if the Governor is responsive and checks for restricted users are in LVE.
    Args:
        argv (list): List of command line arguments.
    """
    parser = argparse.ArgumentParser(description="Governor watchdog")
    parser.add_argument('--file-log', action='store_true',
                        help='Enable logging to a file')

    args = parser.parse_args(argv)
    log_to_file = args.file_log

    dbctl_check_governor(log_to_file)
    check_bad_user_list(log_to_file)

if __name__ == "__main__":
    main(sys.argv[1:])
