#coding:utf-8

# Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
#
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENSE.TXT
#
"""
This module contains class for managing governor on DirectAdmin server
"""
import os
import shutil
from glob import glob

from utilities import (
    check_file,
    exec_command,
    exec_command_out,
    grep,
    read_file,
    remove_packages,
    write_file,
)

from .base import InstallManager


class DirectAdminManager(InstallManager):
    """
    Implementation for DA panel
    """
    CONF_FILE_MYSQL = "/usr/local/directadmin/conf/mysql.conf"

    def update_user_map_file(self):
        """
        Update user mapping file for cPanel
        """
        self._script("dbgovernor_map.py")

    def _delete(self, installed_packages):
        """
        Remove installed packages
        """
        check_file("/usr/local/directadmin/custombuild/build")

        print("Removing mysql for db_governor start")

        self._mysqlservice("stop")
        # remove governor package
        exec_command_out("rpm -e governor-mysql")
        # delete installed packages
        remove_packages(installed_packages)

        param = "mysql"
        if os.path.exists("/usr/share/lve/dbgovernor/da.tp.old"):
            param = read_file("/usr/share/lve/dbgovernor/da.tp.old")

        exec_command_out(f"/usr/local/directadmin/custombuild/build set mysql_inst {param}")
        exec_command_out("/usr/local/directadmin/custombuild/build mysql update")

        print("Removing mysql for db_governor completed")

    def _before_install_new_packages(self):
        """
        Specific actions before new packages installation
        """
        print("The installation of MySQL for db_governor has started")

        check_file("/usr/local/directadmin/custombuild/build")
        check_file("/usr/local/directadmin/custombuild/options.conf")

        # MYSQL_DA_TYPE=`cat /usr/local/directadmin/custombuild/options.conf | grep mysql_inst= | cut -d= -f2`
        try:
            MYSQL_DA_TYPE = grep("/usr/local/directadmin/custombuild/options.conf", "mysql_inst=")[0].split("=")[1]
        except IndexError:
            MYSQL_DA_TYPE = ""

        if os.path.exists("/usr/share/lve/dbgovernor/da.tp.old"):
            if MYSQL_DA_TYPE == "no":
                MYSQL_DA_TYPE = read_file("/usr/share/lve/dbgovernor/da.tp.old")
            else:
                write_file("/usr/share/lve/dbgovernor/da.tp.old", MYSQL_DA_TYPE)
        else:
            write_file("/usr/share/lve/dbgovernor/da.tp.old", MYSQL_DA_TYPE)

        exec_command_out("/usr/local/directadmin/custombuild/build set mysql_inst no")

        self._mysqlservice("stop")

    def get_mysql_user(self):
        """
        Retrieve MySQL user name and password and save it into self attributes
        """
        if not os.path.exists(self.CONF_FILE_MYSQL):
            return None
        try:
            self.MYSQLUSER = grep(self.CONF_FILE_MYSQL, "user=")[0].split("=")[1]
            self.MYSQLPASSWORD = grep(self.CONF_FILE_MYSQL, "passwd=")[0].split("=")[1]
        except IndexError:
            pass

    def _after_install_new_packages(self):
        """
        Specific actions after new packages installation
        """
        # call parent after_install
        InstallManager._after_install_new_packages(self)
        print("Rebuild php please... /usr/local/directadmin/custombuild/build php")

    def _get_custombuild_option(self, option_name):
        """
        Get an option from the DirectAdmin custombuild options.conf file
        """
        CUSTOMBUILD_OPTIONS = "/usr/local/directadmin/custombuild/options.conf"
        option_regex = "{}=".format(option_name)
        try:
            option_grep = grep(CUSTOMBUILD_OPTIONS, option_regex)
            if not option_grep:
                return None
            option_value = option_grep[0].split("=")[1].strip()
            return option_value
        except IndexError:
            return None

    def _detect_version_if_auto(self):
        """
        Detect vesrion of MySQL if mysql.type is auto
        """
        print("Detecting MySQL version for AUTO")

        try:
            # We can reach this section before calling _check_mysql_version in
            # InstallManager.install by calling manager.unsupported_db_version
            # from install\mysqlgovernor.py
            # self.prev_version won't be assigned then, try it now
            if not self.prev_version:
                self.prev_version = self._check_mysql_version()
            MYSQL_DA_VER = self.prev_version['full']
            print(f'Detected successfully from installed mysql binary: {MYSQL_DA_VER}')
        except (KeyError, AttributeError):
            print('Failed to detect from mysql binary, trying to detect from custombuild options')
            check_file("/usr/local/directadmin/custombuild/build")
            check_file("/usr/local/directadmin/custombuild/options.conf")

            # MYSQL_DA_TYPE=`cat /usr/local/directadmin/custombuild/options.conf | grep mysql_inst= | cut -d= -f2`
            # This parameter is used to indicate what type of DB should be installed.
            # Typical values are 'mysql', 'mariadb' or 'no'.
            MYSQL_DA_TYPE = self._get_custombuild_option("mysql_inst")

            # On newer versions of DirectAdmin, the config parameter used to define MariaDB version is mariadb.
            # On older ones, both MySQL and MariaDB versions are defined by mysql parameter.
            if MYSQL_DA_TYPE == "mariadb":
                MARIADB_DA_VER = self._get_custombuild_option("mariadb")

            MYSQL_DA_VER = self._get_custombuild_option("mysql")

            # If we have a specified MariaDB version, we should use it.
            # Otherwise, fall back to the older approach and use the mysql parameter for MariaDB versions too.
            if MYSQL_DA_TYPE == "mariadb" and MARIADB_DA_VER:
                MYSQL_DA_VER = MARIADB_DA_VER

            if MYSQL_DA_TYPE == "no":
                if os.path.exists("/usr/share/lve/dbgovernor/da.tp.old"):
                    MYSQL_DA_TYPE = read_file("/usr/share/lve/dbgovernor/da.tp.old")
                elif os.path.exists("/usr/bin/mysql"):
                    result = exec_command("/usr/bin/mysql -V | grep -c 'MariaDB' -i || true", True)
                    if result == "0":
                        MYSQL_DA_TYPE = "mysql"
                    else:
                        MYSQL_DA_TYPE = "mariadb"

            print("I got %s and %s" % (MYSQL_DA_VER, MYSQL_DA_TYPE))

            mysql_version_map = {
                "5.0": "mysql50",
                "5.1": "mysql51",
                "5.5": "mysql55",
                "5.6": "mysql56",
                "5.7": "mysql57",
                "8.0": "mysql80",
                "10.0.0": "mariadb100",
                "10.1.1": "mariadb101"
            }
            mariadb_version_map = {
                "10.11": "mariadb1011",
                "10.6": "mariadb106",
                "10.5": "mariadb105",
                "10.4": "mariadb104",
                "10.3": "mariadb103",
                "10.2": "mariadb102",
                "10.1": "mariadb101",
                "10.0": "mariadb100",
                "5.6": "mariadb100",
                "5.5": "mariadb100",
                "10.0.0": "mariadb100",
                "10.1.1": "mariadb101"
            }

            # Double-check that we actually have a valid version and type
            try:
                # Did we actually detect a version from the mapping?
                if not MYSQL_DA_TYPE or not MYSQL_DA_VER:
                    # It's OK not to reraise the exception here, the scenario being handled is different
                    # pylint: disable=raise-missing-from
                    raise AttributeError("MySQL/MariaDB version could not be detected")
                if MYSQL_DA_TYPE == "mysql":
                    MYSQL_DA_VER = mysql_version_map[MYSQL_DA_VER]
                elif MYSQL_DA_TYPE == "mariadb":
                    MYSQL_DA_VER = mariadb_version_map[MYSQL_DA_VER]
            # In case we have a version that is not in the mapping
            except KeyError as e:
                raise RuntimeError(f"Unsupported MySQL version: {MYSQL_DA_VER} ({MYSQL_DA_TYPE})") from e

        return MYSQL_DA_VER

    def _custom_download_of_rpm(self, package_name):
        """
        How we should to download installed MySQL package
        There could be a lot of packages in /usr/local/directadmin/custombuild/mysql,
        not all of them relevant (installed) or fine ones (not corrupted)
        """
        if package_name == "+":
            return "yes"

        bad_pkg = False
        list_of_rpm = glob("/usr/local/directadmin/custombuild/mysql/*.rpm") + glob(
            "/usr/local/directadmin/scripts/packages/*.rpm")
        for found_package in list_of_rpm:
            try:
                result = exec_command(f"/bin/rpm -qp {found_package}", True)
                if package_name in result:
                    pkg_name_real = found_package
                    if pkg_name_real != "" and os.path.exists(pkg_name_real):
                        return f"file:{pkg_name_real}"
            except RuntimeError as e:
                print(f"Failed to query package {found_package}: {e}\n")
                bad_pkg = True

        if bad_pkg:
            return f"bad_file:{package_name}"
        else:
            return ""

    def _custom_rpm_installer(self, package_name, indicator=False):
        """
        Specific package installer
        :param package_name:
        :param indicator:
        :return:
        """
        if not indicator:
            exec_command_out(f"/bin/rpm -ihv --force --nodeps {package_name}")
            return ""
        else:
            return "yes"

    def fix_mysqld_service(self):
        """
        Restore mysqld.service
        """
        try:
            shutil.copy(self._rel("scripts/mysqld.service"),
                        '/usr/local/directadmin/custombuild/configure/systemd/mysqld.service')
            print('mysqld.service restored!')
        except Exception:
            print('ERROR occurred while attempting to restore mysqld.service!')
