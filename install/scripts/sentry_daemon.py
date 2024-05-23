#!/opt/cloudlinux/venv/bin/python3
# coding:utf-8

# Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2024 All Rights Reserved
#
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENSE.TXT
#

import os
import sys
import signal
import socket
import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration
import logging

SENTRY_DSN_FILE = "/usr/share/lve/dbgovernor/sentry_dsn"
LISTENER_SOCK_FILE = "/var/run/db-governor-sentry.sock"

MESSAGE_SIZE = 1024
CONNECTS_MAX = 5

class SentryDaemon:
    """
    A daemon process to handle and forward logs to Sentry based on UNIX socket communication.

    Attributes:
        socket_path (str): The path to the UNIX socket file.
        server_socket (socket.socket): The socket object for server.
        sentry_dsn (str): Data Source Name for the Sentry integration.
    """

    def __init__(self, socket_path, sentry_dsn_file):
        """
        Initializes the SentryDaemon with given socket path and Sentry DSN file.

        Args:
            socket_path (str): The file path where the UNIX socket should be created.
            sentry_dsn_file (str): The file path containing the Sentry DSN.
        """
        self.socket_path = socket_path
        self.server_socket = None
        self.sentry_dsn = self.read_sentry_dsn_from_file(sentry_dsn_file)

        # Initialize Sentry SDK
        sentry_sdk.init(
            dsn=self.sentry_dsn,
            integrations=[LoggingIntegration(level=logging.INFO, event_level=logging.ERROR)]
        )

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

    def start_server(self):
        """
        Starts the UNIX socket server to listen for incoming log messages.
        """
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.socket_path)
        self.server_socket.listen(CONNECTS_MAX)

        print(f"Started listening on the socket {self.socket_path}")

        try:
            while True:
                try:
                    client_socket, _ = self.server_socket.accept()
                    with client_socket:
                        while True:
                            try:
                                # Receive log from client
                                data = client_socket.recv(MESSAGE_SIZE)
                                if not data:
                                    break

                                self.process_message(data.decode())

                            except Exception as e:
                                logging.error(f"Failed to receive log: {e}")
                                break

                except socket.error as se:
                    logging.error(f"Failed to accept socket: {se}")
                except Exception as e:
                    logging.error(f"General error: {e}")

        finally:
            self.cleanup()

    def process_message(self, message):
        """
        Processes a single message received from the client.

        Args:
            message (str): The log message received.
        """
        if message.startswith("ERROR:"):
            logging.error(message[6:].strip())
        elif message.startswith("INFO:"):
            logging.info(message[5:].strip())
        elif message.startswith("DEBUG:"):
            logging.debug(message[6:].strip())
        else: # Default log level (ERROR)
            logging.error(message)

    def cleanup(self):
        """
        Cleans up the resources used by the daemon, particularly the server socket.
        """
        if self.server_socket:
            self.server_socket.close()
            print("Closed server socket")
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
            print(f"Removed socket file {self.socket_path}")

if __name__ == "__main__":
    daemon = SentryDaemon(LISTENER_SOCK_FILE, SENTRY_DSN_FILE)
    signal.signal(signal.SIGTERM, daemon.handle_sigterm)
    daemon.start_server()
