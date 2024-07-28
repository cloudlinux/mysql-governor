#!/opt/cloudlinux/venv/bin/python3
# coding:utf-8

# Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2024 All Rights Reserved
#
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENSE.TXT
#

import os
import sys
import platform
import time
import signal
import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration
import logging
import glob
import re
from clcommon.utils import get_rhn_systemid_value
from clcommon import get_lve_version
from clcommon.lib.cledition import get_cl_edition_readable
from clsentry.utils import get_pkg_version
from dbgovernor_version import GOVERNOR_CUR_VER

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../")  # utilities.py lives one level higher
from utilities import exec_command

SENTRY_DSN_FILE = "/usr/share/lve/dbgovernor/sentry-dsn"
DAEMON_INTERVAL = 10

SENTRY_DEPOT_ROOT = "/var/lve/dbgovernor/logging/sentry-depot"
SENTRY_DEPOT_DB_GOVERNOR = SENTRY_DEPOT_ROOT + "/db_governor"
SENTRY_DEPOT_MYSQLD      = SENTRY_DEPOT_ROOT + "/mysqld"
SENTRY_DEPOT_EXT = ".txt"

DB_GOVERNOR_LOGS_WILDCARD = SENTRY_DEPOT_DB_GOVERNOR + "/*" + SENTRY_DEPOT_EXT
MYSQLD_LOGS_WILDCARD      = SENTRY_DEPOT_MYSQLD      + "/*" + SENTRY_DEPOT_EXT

class SentryDaemon:
    """
    A daemon process to forward 'db_governor' and extended 'mysqld' logs to Sentry.
    """

    def __init__(self, db_governor_logs_wildcard, mysqld_logs_wildcard, sentry_dsn_file):
        """
        Initializes SentryDaemon with given log path wildcards and Sentry DSN file.

        Args:
            db_governor_logs_wildcard (str): wildcard path for Sentry log files from db_governor.
            mysqld_logs_wildcard (str): wildcard path for Sentry log files from mysqld.
            sentry_dsn_file (str): path to file containing Sentry DSN.
        """

        self.db_governor_logs_wildcard = db_governor_logs_wildcard
        self.mysqld_logs_wildcard = mysqld_logs_wildcard
        with open(sentry_dsn_file) as f:
            dsn = f.read().strip()

        os_name = get_rhn_systemid_value('operating_system')
        os_version = get_rhn_systemid_value('os_release')
        os2 = [s for s in exec_command("cldetect --detect-os", as_string=True, no_debug_log=True).split(" ") if s]  # do this before sentry_sdk.init(): not only because these are constants, but also to avoid 'subprocess' calls being put into breadcrumbs:
        if len(os2) == 2:
            os_name, os_version = os2

        sentry_sdk.init(
            dsn = dsn,
            #debug = True,                   # uncomment to look deeper under the hood of 'sentry_sdk'
            before_send = self.before_send,  # to strip away undesirable event attributes
            release = GOVERNOR_CUR_VER,      # version of db_governor/libgovernor.so
            integrations = [LoggingIntegration(event_level=logging.WARNING)],  # this kind of integration is set manually only to set non-default 'event_level'
            send_client_reports = False      # our Sentry server doesn't like 'client_report' events and responds with HTTP '400 Bad Request'
        )
        with sentry_sdk.configure_scope() as scope:  # set permanent tags
            scope.set_user({ "id":        VIS(get_rhn_systemid_value('system_id'))})
            scope.set_context("device", {
                "architecture":           VIS(get_rhn_systemid_value("architecture") or platform.machine())
            })
            scope.set_context("os", {
                "name":                   VIS(os_name),
                "version":                VIS(os_version),
                "build":                  VIS(platform.version()),
                "Kernel-version":         VIS(platform.release()),
                "CloudLinux-edition":     VIS(get_cl_edition_readable())
            })
            scope.set_tag("lve.version",  VIS(get_lve_version()[0]))
            scope.set_tag("lvemanager",   VIS(get_pkg_version("lvemanager")))
            scope.set_tag("lve-stats",    VIS(get_pkg_version("lve-stats")))
            scope.set_tag("lve-utils",    VIS(get_pkg_version("lve-utils")))

        self.internal_logger = logging.getLogger("sentry_daemon")  # for internal, non-forwarded events
        self.preface_sent = False

    class TerminateException(Exception):
        def __init__(self):
            super().__init__()

    @staticmethod
    def handle_sigterm(signum, frame):
        """
        On SIGTERM signal, throw an exception
        caught in the outermost code and triggering daemon shutdown.
        Make sure this type of exception is re-thrown in all of inner try/except's.

        Args:
            signum (int): signal number.
            frame (frame): current stack frame.
        """
        raise SentryDaemon.TerminateException()

    @staticmethod
    def is_healthy():
        return sentry_sdk.Hub.current.client.transport.is_healthy()

    strip_event_pythonicity = False

    @staticmethod
    def before_send(event, hint):
        event.pop("transaction_info", None)  # our Sentry server doesn't understand it and throws a pink msg box "There was 1 error encountered while processing this event: transaction_info: Discarded unknown attribute". Possibly it will go away after Sentry server upgrade.
        if SentryDaemon.strip_event_pythonicity:  # remove irrelevant attributes - misleading and obstructing for events forwarded from C code
            if "extra" in event:
                event["extra"].pop("sys.argv", None)
            if "contexts" in event:
                event["contexts"].pop("runtime", None)
            for attr in ("modules", "sdk", "breadcrumbs"):
                event.pop(attr, None)
        return event

    @staticmethod
    def print(s):
        print(s, file=sys.stderr)

    @staticmethod
    def print_sentry_transport_status(prompt):  # use it for debugging, if you want to reconsider our interaction with Sentry transport
        SentryDaemon.print(f"{prompt}: queuse size={sentry_sdk.Hub.current.client.transport._worker._queue.qsize()}, healthy={SentryDaemon.is_healthy()}")

    def run(self):
        """
        Starts the daemon to read log files and send logs to Sentry.
        """
        self.print(f"Started reading log files in {self.db_governor_logs_wildcard} and {self.mysqld_logs_wildcard}")

        events_ever_lost, loss_report_sent, loss_reporting_complete = False, False, False

        while True:
            send_logs = True  # by default, all found logs will be sent to Sentry

            # Handle loss reporting
            if events_ever_lost and not loss_reporting_complete:  # Since the detection of event loss, we're struggling for reporting it. This reporting takes place only once per daemon session.
                send_logs = False    # For this period, we suspend transmission of regular log files - otherwise they can choke us again and leave us no chance to render the loss on Sentry server.
                healthy = self.is_healthy()  # It's vital to make no movements while this is False. 'sentry_sdk' is fragile enough under high load, and we need to report the loss reliably.
                self.print(f"Event loss reporting phase, regular log files are being skipped; transport healthy: {healthy}")
                if healthy:  # No state change while unhealthy. We wait for health _before_ sending the loss report, and once again _after_ sending it.
                    if loss_report_sent:
                        loss_reporting_complete = True         # We're healthy after the loss report transmission. Loss reporting is over.
                        self.print("Event loss reporting complete")  # On the next iteration we shall return to normal log file processing.
                    else:
                        self.internal_logger.warning("Errors possibly lost")  # We're healthy, but haven't yet sent the loss report. Send it now.
                        loss_report_sent = True                         # We send it only once per daemon session.
                        self.print("Event loss report sent")

            # Scan for log files
            report = ""
            for           wildcard,                   logger      in [
                    (self.db_governor_logs_wildcard, "db_governor"),
                    (self.mysqld_logs_wildcard,      "mysqld")]:
                try:
                    logs = glob.glob(wildcard)
                except TerminateException:  # handling it separately spares us of knowing possible exception types from glob()
                    raise
                except Exception as e:
                    self.internal_logger.error(f"Failed to scan '{wildcard}': {e}")  # bug, can't normally happen -> print locally + report to Sentry (loggers are intercepted by 'sentry_sdk')
                n_sent, n_deleted = 0, 0
                for log in logs:
                    if not os.path.exists(log):
                        self.print(f"Disappeared file '{log}'")                      # can be caused by races with sentry_cleaner.sh -> print only locally
                        continue
                    # MySQL version can be empty - it's not always available inside 'db_governor',
                    # and never available in 'mysqld'.
                    # The latter sounds so ridiculous, we surely have to fix it soon.
                    match = re.match(r"(.*)-mysql\.", os.path.basename(log))  # basename() must not throw - 'log' is a valid path, proven above
                    if not match:
                        self.internal_logger.error(f"Invalid file name '{log}'")     # bug -> print + Sentry
                    else:
                        ver_mysql = match.group(1)
                        if send_logs:
                            message = None
                            try:
                                with open(log, 'r') as f:
                                    try:
                                        message = f.read()
                                    except TerminateException:
                                        raise
                                    except Exception as e:
                                        self.print(f"Failed to read {log}: {e}")     # races -> print only
                            except TerminateException:
                                raise
                            except Exception as e:
                                self.print(f"Failed to open {log}: {e}")             # races -> print only
                            if message is not None:
                                self.process_message(logger, message.strip(), ver_mysql)
                                n_sent += 1
                    try:
                        os.remove(log)
                        n_deleted += 1
                    except TerminateException:
                        raise
                    except Exception as e:
                        self.print(f"Failed to delete {log}: {e}")                   # races -> print only
                if len(report):
                    report += ";  "
                report += f"{logger}: {n_sent} sent, {n_deleted} deleted"

            self.print(report)  # how many files were sent and deleted

            # Detect event loss
            if not events_ever_lost and not self.is_healthy():
                events_ever_lost = True  # this could trigger due to Rate Limiting response from Sentry server, or due to local queue overflow, or other internal problem
                self.print("Event loss first detected")

            # Sleep for a bit before checking the log files again
            time.sleep(DAEMON_INTERVAL)

    def process_message(self, logger, message, ver_mysql):
        """
        Processes a single message received from the client.

        Args:
            message (str): log message received.
            logger (str): logger to use for sending the message to Sentry.
        """

        # The purpose of this preface Sentry event is to guarantee that we see the complete Python attributes, like module list, at least once -
        # because we strip them from the following forwarded events.
        if not self.preface_sent:
            self.internal_logger.warning("Hello, bad news, errors follow...")
            self.preface_sent = True
            self.print("Preface sent")

        norsqr = r"([^]]+)"       # anything without right square bracket
        insqr = rf"\[{norsqr}\]"  # anything in square brackets
        message_format = rf"\s*{insqr}\s*\[(\d+):(\d+)\][\s!]*\[{norsqr}:(\d+):{norsqr}\]\s*{insqr}\s*(.*)$"
        match = re.match(message_format, message)
        if match:
            timestamp, process, thread, src_file, src_line, src_func, tags, text = match.groups()
            try:
                process, thread, src_line = int(process), int(thread), int(src_line)
            except ValueError:
                match = None   # use 'match' as a generic validity marker
            tags = tags.split(":")
            if not all(tags):  # empty tags not permitted
                match = None
            tags = [t for t in tags if t != "ERRSENTRY"]  # omit this one - it's always present in Sentry-reported log messages (unless we use some cryptic internal-use-only file flags)
            src_func += "()"
        if not match:
            self.internal_logger.error(f"Invalid message format in '{logger}' log: '{message}'")  # sends to Sentry and prints locally
            return

        with sentry_sdk.push_scope() as scope:  # set message-specific tags
            scope.set_tag("mysql.version", VIS(ver_mysql))
            scope.set_tag("actual_time", timestamp)
            scope.set_tag("process", process)
            scope.set_tag("thread", thread)
            for tag in tags:
                scope.set_tag(tag, True)
            match2 = re.search(r"\busername '(.+?)',\s*", text)  # hacky, to be exterminated
            if match2:
                scope.set_tag("username", match2.group(1))
                text = text.replace(match2.group(0), "")
            # Sentry server overrides the transmitted value of 'event.type' and sets it to 'error' only if it finds the actual error cause - the exception.
            # 'sentry_sdk' is designed to catch and report exceptions in its native language environment - Python in our case.
            # To emulate an error event with the appropriate type, logger name and source code attributes, I found no easier way than building it manually:
            event = {
                "level": "error",
                "logger": logger,
                "exception": {        # We need to trigger an error somehow. Alternatively, we could use 'threads'->'stacktrace', but it has its downsides.
                    "values": [ {
                        "type": text,  # SIC! This is shown as an event title in case of exceptions.
                        "value": "",
                        "thread_id": thread,
                        "stacktrace": {
                            "frames": [ {
                                "function": src_func,
                                "lineno":   src_line,
                                "filename": src_file
                            } ]
                        }
                    } ]
                }
            }
            self.__class__.strip_event_pythonicity = True  # tell before_send() to remove event attributes that are irrelevant for an event forwarded from C code
            sentry_sdk.capture_event(event)
            self.__class__.strip_event_pythonicity = False

    def cleanup(self):
        """
        Cleans up the resources used by the daemon.
        Does not clean the log files, so that they could be transmitted to Sentry on the next daemon run.
        """
        pass

def VIS(x):
    """
    Visualize - replace anything "pythonically Falsy" with an explicit "n/a".

    There are Sentry tags that we consider mandatory for a regular machine.
    Although, sometimes the corresponding values can be None,
    and set_tag(..., None) wouldn't make them visible on the Sentry page.
    We wrap them in this call to force visibility.
    """
    return x if x else "n/a"

if __name__ == "__main__":
    daemon = SentryDaemon(DB_GOVERNOR_LOGS_WILDCARD, MYSQLD_LOGS_WILDCARD, SENTRY_DSN_FILE)
    signal.signal(signal.SIGTERM, SentryDaemon.handle_sigterm)
    try:
        daemon.run()
    except SentryDaemon.TerminateException:
        daemon.print("SIGTERM received, shutting down gracefully...")
        daemon.cleanup()
    except KeyboardInterrupt:
        daemon.cleanup()
    finally:
        daemon.cleanup()
