#!/opt/cloudlinux/venv/bin/python3
# coding:utf-8

# Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2024 All Rights Reserved
#
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENSE.TXT
#

import os
import sys
import time
import signal
import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration
import logging
import glob
import re

SENTRY_DSN_FILE = "/usr/share/lve/dbgovernor/sentry_dsn"
DAEMON_INTERVAL = 10

GOVERNOR_LOGS_PATH = "/var/log/dbgovernor-sentry-depot/*.txt"
MYSQLD_LOGS_PATH = "/var/log/dbgovernor-mysqld-sentry-depot/*.txt"

MESSAGE_SIZE = 1024
CONNECTS_MAX = 5

class SentryDaemon:
    """
    A daemon process to handle and forward governor logs to Sentry.

    Attributes:
        governor_logs_path (str): The path where the governor Sentry logs are located.
        mysqld_logs_path (str): The path where the mysqld Sentry logs are located.
        sentry_dsn (str): Data Source Name for the Sentry integration.
    """

    def __init__(self, governor_logs_path, mysqld_logs_path, sentry_dsn_file):
        """
        Initializes the SentryDaemon with given socket path and Sentry DSN file.

        Args:
            governor_logs_path (str): The path where the governor Sentry logs are located.
            mysqld_logs_path (str): The path where the mysqld Sentry logs are located.
            sentry_dsn_file (str): The file path containing the Sentry DSN.
        """
        self.governor_logs_path = governor_logs_path
        self.mysqld_logs_path = mysqld_logs_path
        self.sentry_dsn = self.read_sentry_dsn_from_file(sentry_dsn_file)

        # Initialize Sentry SDK
        sentry_sdk.init(
            dsn=self.sentry_dsn,
            traces_sample_rate = 1.0,
            integrations=[LoggingIntegration(level=logging.INFO, event_level=logging.ERROR)]
        )

        self.logger_db_governor = logging.getLogger("db_governor")
        self.logger_mysqld = logging.getLogger("mysqld")

    def read_sentry_dsn_from_file(self, path):
        """
        Reads the Sentry DSN from the specified file.

        Args:
            path (str): Path to the file containing the Sentry DSN.

        Returns:
            str: The Sentry DSN string or None if the file is not found or an error occurs.
        """
        try:
            with open(path) as f:
                return f.read().strip()
        except Exception as e:
            logging.error(f"Error reading Sentry DSN: {e}")
            return

    def handle_sigterm(self, signum, frame):
        """
        Handles SIGTERM signal to perform clean shutdown of the daemon.

        Args:
            signum (int): The signal number.
            frame (frame): The current stack frame.
        """
        print("SIGTERM received, shutting down gracefully...")
        self.cleanup()
        sys.exit(0)

    def start(self):
        """
        Starts the daemon to read log files and send logs to Sentry.
        """
        print(f"Started reading log files in {self.governor_logs_path} and {self.mysqld_logs_path}")

        try:
            while True:
                try:
                    self.process_files(self.governor_logs_path, self.logger_db_governor)
                    self.process_files(self.mysqld_logs_path, self.logger_mysqld)
                except Exception as e:
                    logging.error(f"Failed to process log file: {e}")

                # Sleep for a bit before checking the log files again
                time.sleep(DAEMON_INTERVAL)

        except KeyboardInterrupt:
            self.cleanup()

        finally:
            self.cleanup()

    def process_files(self, log_files_path, logger):
            """
            Processes all log files in the specified path and sends their contents to Sentry.

            Args:
                log_files_path (str): The path pattern to the log files.
                logger (logging.Logger): The logger to use for sending messages to Sentry.
            """
            log_files = glob.glob(log_files_path)
            for log_file_path in log_files:
                if os.path.exists(log_file_path):
                    with open(log_file_path, 'r') as log_file:
                        for line in log_file:
                            self.process_message(line.strip(), logger)

                    os.remove(log_file_path)
                    print(f"Removed log file {log_file_path}")

    def process_message(self, message, logger):
        """
        Processes a single message received from the client.

        Args:
            message (str): The log message received.
            logger (logging.Logger): The logger to use for sending the message to Sentry.
        """
        line_format = r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{9})\] \[(\d+)\.(\d+)\] \[([^]]+)\] \[([^]]+)\] (.*)$"
        match = re.match(line_format, message)

        if match:
            timestamp, process, thread, src_location, tags, msg = match.groups()
            tags = [t for t in tags.split(":") if t != "ERRSENTRY"]

            with sentry_sdk.push_scope() as scope:
                scope.set_tag("timestamp", timestamp)
                scope.set_tag("process", process)
                scope.set_tag("thread", thread)
                for tag in tags:
                    scope.set_tag(tag, True)
                scope.set_tag("src_location", src_location)
                logger.error(msg.strip())
        else:
            logger.error("Invalid log message format")

    def cleanup(self):
        """
        Cleans up the resources used by the daemon, particularly the log files.
        """
        self.cleanup_files(self.governor_logs_path)
        self.cleanup_files(self.mysqld_logs_path)

    def cleanup_files(self, log_files_path):
        """
        Removes all log files in the specified path.

        Args:
            log_files_path (str): The path pattern to the log files.
        """
        log_files = glob.glob(log_files_path)
        for log_file_path in log_files:
            if os.path.exists(log_file_path):
                os.remove(log_file_path)
                print(f"Removed log file {log_file_path}")

if __name__ == "__main__":
    daemon = SentryDaemon(GOVERNOR_LOGS_PATH, MYSQLD_LOGS_PATH, SENTRY_DSN_FILE)
    signal.signal(signal.SIGTERM, daemon.handle_sigterm)
    daemon.start()
