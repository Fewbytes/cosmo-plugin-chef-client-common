#/*******************************************************************************
# * Copyright (c) 2013 GigaSpaces Technologies Ltd. All rights reserved
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *       http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.
# *******************************************************************************/

"""
This module provides functions for installing, configuring and running chef-client against an existing chef-server or chef-solo.

This module is specifically meant to be used for the cosmo celery tasks
which import the `run_chef` function.
"""

from celery.utils.log import get_task_logger
from functools import wraps
import re
import requests
import os
import stat
import urllib
import tempfile
import subprocess
import json

CHEF_INSTALLER_URL = "https://www.opscode.com/chef/install.sh"
ROLES_DIR = "/var/chef/roles"

logger = get_task_logger(__name__)


class SudoError(Exception):
    """An internal exception for failures when running an os command with sudo"""
    pass


class ChefError(Exception):
    """An exception for all chef related errors"""
    pass


class ChefManager(object):

    @classmethod
    def can_handle(cls, *args, **kwargs):
        # Can handle if all required arguments present
        if cls.REQUIRED_ARGS.difference(kwargs.keys()):
            return False
        for arg in cls.REQUIRED_ARGS:
            if kwargs[arg] is None:
                return False
        return True

    @classmethod
    def assert_args(cls, *args, **kwargs):
        missing_fields = (cls.REQUIRED_ARGS).union({'chef_version'}).difference(kwargs.keys())
        if missing_fields:
            raise ChefError("The following required field(s) are missing: {0}".format(", ".join(missing_fields)))

    def get_version(self):
        """Check if chef-client is available and is of the right version"""
        binary = self._get_binary()
        if not self._prog_available_for_root(binary):
            return None

        return self._extract_chef_version(subprocess.check_output(["/usr/bin/sudo", binary, "--version"]))

    def install(self, *args, **kwargs):
        """If needed, install chef-client and point it to the server"""
        chef_version = kwargs['chef_version']
        current_version = self.get_version()
        if current_version:
            if current_version == self._extract_chef_version(chef_version):
                return
            else:
                self.uninstall()

        logger.info('Installing Chef [chef_version=%s]', chef_version)
        chef_install_script = tempfile.NamedTemporaryFile(suffix="install.sh", delete=False)
        chef_install_script.close()
        try:
            urllib.urlretrieve(CHEF_INSTALLER_URL, chef_install_script.name)
            os.chmod(chef_install_script.name, stat.S_IRWXU)
            self._sudo(chef_install_script.name, "-v", chef_version)
            os.remove(chef_install_script.name)  # on failure, leave for debugging
        except Exception as exc:
            raise ChefError("Chef install failed on:\n%s" % exc)

        logger.info('Setting up Chef [chef_server=\n%s]', kwargs.get('chef_server_url'))

        for directory in '/etc/chef', '/var/chef', '/var/log/chef', ROLES_DIR:
            self._sudo("mkdir", "-p", directory)

        self._install_files(*args, **kwargs)

    def uninstall(self):
        """Uninstall chef-client - currently only supporting apt-get"""
        #TODO: I didn't find a single method encouraged by opscode,
        #      so we need to add manually for any supported platform
        def apt_platform():  # assuming that if apt-get exists, it's how chef was installed
            return self._prog_available_for_root('apt-get')

        if apt_platform():
            logger.info("Uninstalling old Chef via apt-get")
            try:
                self._sudo("apt-get", "remove", "chef", "-y")
            except SudoError as exc:
                raise ChefError("chef-client uninstall failed on:\n%s" % exc)
        else:
            logger.info("Chef uninstall is unimplemented for this platform, proceeding anyway")

    def run(self, runlist, chef_attributes=None, *args, **kwargs):
        if chef_attributes is None:
            chef_attributes = {}
        self._prepare_for_run(runlist, *args, **kwargs)
        self.attribute_file = tempfile.NamedTemporaryFile(suffix="chef_attributes.json",
                                                     delete=False)
        json.dump(chef_attributes, self.attribute_file)
        self.attribute_file.close()

        cmd = self._get_cmd(runlist, *args, **kwargs)

        try:
            self._sudo(*cmd)
            os.remove(self.attribute_file.name) # on failure, leave for debugging
        except SudoError as exc:
            raise ChefError("The chef run failed\n"
                            "runlist: {0}\nattributes: {1}\nexception: \n{2}".format(runlist, kwargs.get('chef_attributes'), exc))


    def _prepare_for_run(self, *args, **kwargs):
        pass

    # Utilities from here to end of the class

    def _extract_chef_version(self, version_string):
        match = re.search(r'(\d+\.\d+\.\d+)', version_string)
        if match:
            return match.groups()[0]
        else:
            raise ChefError("Failed to read chef version - '%s'" % version_string)

    def _prog_available_for_root(self, prog):
        with open(os.devnull, "w") as fnull:
            which_exitcode = subprocess.call(["/usr/bin/sudo", "which", prog], stdout=fnull, stderr=fnull)
        return which_exitcode == 0

    def _sudo(self, *args):
        """a helper to run a subprocess with sudo, raises SudoError"""

        def get_file_contents(file_obj):
            file_obj.flush()
            file_obj.seek(0)
            return  ''.join(file_obj.readlines())

        command_list = ["/usr/bin/sudo"] + list(args)
        logger.info("Running: '%s'", ' '.join(command_list))

        #TODO: Should we put the stdout/stderr in the celery logger? should we also keep output of successful runs?
        #      per log level? Also see comment under run_chef()
        stdout = tempfile.TemporaryFile('rw+b')
        stderr = tempfile.TemporaryFile('rw+b')
        try:
            subprocess.check_call(command_list, stdout=stdout, stderr=stderr)
        except subprocess.CalledProcessError as exc:
            raise SudoError("{exc}\nSTDOUT:\n{stdout}\nSTDERR:{stderr}".format(
                exc=exc, stdout=get_file_contents(stdout), stderr=get_file_contents(stderr))
            )
        finally:
            stdout.close()
            stderr.close()


    def _sudo_write_file(self, filename, contents):
        """a helper to create a file with sudo"""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(contents)

        self._sudo("mv", temp_file.name, filename)


class ChefClientManager(ChefManager):

    NAME = 'client'
    REQUIRED_ARGS = {'chef_server_url', 'chef_validator_name', 'chef_validation', 'chef_environment'}

    def _get_cmd(self, runlist, *args, **kwargs):
        return ["chef-client", "-o", runlist, "-j", self.attribute_file.name, "--force-formatter"]
    def _get_binary(self):
        return 'chef-client'

    def _install_files(self, *args, **kwargs):
        if kwargs.get('chef_validation'):
            self._sudo_write_file('/etc/chef/validation.pem', kwargs['chef_validation'])
        self._sudo_write_file('/etc/chef/client.rb', """
log_level          :info
log_location       "/var/log/chef/client.log"
ssl_verify_mode    :verify_none
validation_client_name "{chef_validator_name}"
validation_key         "/etc/chef/validation.pem"
client_key             "/etc/chef/client.pem"
chef_server_url    "{chef_server_url}"
environment    "{chef_environment}"
file_cache_path    "/var/chef/cache"
file_backup_path   "/var/chef/backup"
pid_file           "/var/run/chef/client.pid"
Chef::Log::Formatter.show_time = true
            """.format(**kwargs)
        )


class ChefSoloManager(ChefManager):

    NAME = 'solo'
    REQUIRED_ARGS = {'chef_cookbooks'}

    def _prepare_for_run(self, *args, **kwargs):
        if kwargs.get('chef_roles'):
            import tarfile
            import StringIO
            with tarfile.open(fileobj=StringIO.StringIO(requests.get(kwargs['chef_roles']).content), mode="r:gz") as tar:
                for tarinfo in tar:
                    if tarinfo.isreg():
                        e = tar.extractfile(tarinfo)
                        with open(os.path.join(ROLES_DIR, os.path.basename(tarinfo.name)), 'w') as dst:
                            dst.write(e.read())

    def _get_cmd(self, runlist, *args, **kwargs):
        return ["chef-solo", "-o", runlist, "-j", self.attribute_file.name, "--force-formatter", "-r", kwargs['chef_cookbooks']]

    def _get_binary(self):
        return 'chef-solo'

    def _install_files(self, *args, **kwargs):
        self._sudo_write_file('/etc/chef/solo.rb', '')


def get_manager(*args, **kwargs):
    managers = ChefClientManager, ChefSoloManager
    for cls in managers:
        if cls.can_handle(*args, **kwargs):
            logger.info("Chef manager class: {}".format(cls))
            cls.assert_args(*args, **kwargs)
            return cls()
    arguments_sets = '; '.join(['(for ' + m.NAME + '): ' + ', '.join(list(m.REQUIRED_ARGS)) for m in managers])
    raise ChefError("Failed to find appropriate Chef manager for the specified arguments ({0}, {1}). Possible arguments sets are: {2}".format(args, kwargs, arguments_sets))


def run_chef(runlist, chef_attributes=None, **kwargs):
    """Run runlist with chef-client using these chef_attributes(json or dict)"""
    # I considered moving the attribute handling to the set-up phase but
    # eventually left it here, to allow specific tasks to easily override them.

    if runlist is None:
        return

    # relationship based task
    if '__source_properties' in kwargs:
        kwargs = kwargs['__source_properties']

    if isinstance(chef_attributes, str):  # assume we received json
        try:
            chef_attributes = json.loads(chef_attributes or "{}")
        except ValueError:
            raise ChefError("Failed json validation of chef chef_attributes:\n%s" % chef_attributes)

    kwargs = dict(chef_attributes=chef_attributes, **kwargs)
    chef_manager = get_manager(runlist, **kwargs)
    chef_manager.install(runlist, **kwargs)
    chef_manager.run(runlist, **kwargs)

if __name__ == '__main__':
    import argparse
    import logging as l
    parser = argparse.ArgumentParser(
        description="Installs and runs Chef (client or solo)"
    )
    # common
    parser.add_argument(
        '-r', '--run-list',
        type=str
    )
    parser.add_argument(
        '-a', '--attributes',
        type=str
    )
    # solo
    parser.add_argument(
        '--roles',
        help='Roles .tar.gz URL',
        type=str
    )
    parser.add_argument(
        '--cookbooks',
        help='Cookbooks .tar.gz URL',
        type=str
    )
    # client
    parser.add_argument(
        '-e', '--environment',
        type=str,
        default='_default',
    )
    parser.add_argument(
        '-u', '--url',
        help='Server URL',
        type=str,
    )
    parser.add_argument(
        '--val-c',
        help='Validation certificate. You can use caret (^) characters instead of newlines for convenience to pass the certificate in one line.',
        type=str,
    )

    parser.add_argument(
        '--val-n',
        help='Validator name',
        type=str,
    )

    parser.add_argument(
        '--as-source-properties',
        default=False,
        dest='as_source_properties',
        action='store_true',
    )

    parser.set_defaults(as_source_properties=False)
    args = parser.parse_args()

    if args.val_c:
        chef_validation = args.val_c.replace('^', '\n')
    else:
        chef_validation = None

    if args.attributes:
        chef_attributes = json.loads(args.attributes)
    else:
        chef_attributes = {}

    # Setup global logger:
    logger = l.getLogger('cosmo_plugin_chef_client_common')
    logger.setLevel(l.DEBUG)
    ch = l.StreamHandler()
    ch.setLevel(l.DEBUG)
    logger.addHandler(ch)

    kwargs = dict(
        chef_environment=args.environment,
        chef_version='11.4.4-2',
        chef_cookbooks=args.cookbooks,
        chef_roles=args.roles,
        chef_server_url=args.url,
        chef_validator_name=args.val_n,
        chef_validation=chef_validation
    )
    if args.as_source_properties:
        kwargs = {'__source_properties': kwargs}
    run_chef(args.run_list, chef_attributes, **kwargs)
