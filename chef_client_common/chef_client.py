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
This module provides functions for installing, configuring and running chef-client against an existing chef-server.

This module is specifically meant to be used for the cosmo celery tasks
which import the `set_up_chef_client` decorator and the `run_chef` function.
"""

from cosmo.celery import celery
import celery.utils.log
from functools import wraps
import re
import os
import stat
import urllib
import tempfile
import subprocess
import json

CHEF_INSTALLER_URL = "https://www.opscode.com/chef/install.sh"
logger = celery.utils.log.get_task_logger(__name__)

class SudoError(Exception):
    """An internal exception for failures when running an os command with sudo"""
    pass


class ChefError(Exception):
    """An exception for all chef related errors"""
    pass


def sudo(*args):
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


def sudo_write_file(filename, contents):
    """a helper to create a file with sudo"""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(contents)

    sudo("mv", temp_file.name, filename)


def equal_versions(version1, version2):
    """Are these two chef versions the same?"""
    def extract_numeric_version(version_string):
        """Extract the x.y.z part of the version"""
        match = re.search(r'(\d+\.\d+\.\d+)', version_string)
        if match:
            return match.groups()[0]
        else:
            raise ChefError("Failed to read chef version - '%s'" % version_string)

    return extract_numeric_version(version1) == extract_numeric_version(version2)


def uninstall_chef():
    """Uninstall chef-client - currently only supporting apt-get"""
    #TODO: I didn't find a single method encouraged by opscode,
    #      so we need to add manually for any supported platform
    def apt_platform():  # assuming that if apt-get exists, it's how chef was installed
        with open(os.devnull, "w") as fnull:
            which_exitcode = subprocess.call(["/usr/bin/sudo", "which", "apt-get"],
                                             stdout = fnull, stderr = fnull)
        return which_exitcode != 0

    if apt_platform():
        logger.info("Uninstalling old chef-client via apt-get")
        try:
            sudo("apt-get", "remove", "chef", "-y")
        except SudoError as exc:
            raise ChefError("chef-client uninstall failed on:\n%s" % exc)
    else:
        logger.info("Chef uninstall is unimplemented for this platform, proceeding anyway")


def current_chef_version():
    """Check if chef-client is available and is of the right version"""
    with open(os.devnull, "w") as fnull:
        which_exitcode = subprocess.call(["/usr/bin/sudo", "which", "chef-client"],
                                         stdout = fnull, stderr = fnull)

    if which_exitcode != 0:
        return None

    return subprocess.check_output(["/usr/bin/sudo", "chef-client", "--version"])


def install_chef(chef_version, chef_server_url, chef_environment,
                 chef_validator_name, chef_validation):
    """If needed, install chef-client and point it to the server"""
    current_version = current_chef_version()
    if current_version:  # we found an existing chef version
        if equal_versions(current_version, chef_version):
            return  # no need to do anything
        else:
            uninstall_chef()

    logger.info('Installing chef-client [chef_version=%s]', chef_version)
    chef_install_script = tempfile.NamedTemporaryFile(suffix="install.sh", delete=False)
    chef_install_script.close()
    try:
        urllib.urlretrieve(CHEF_INSTALLER_URL, chef_install_script.name)
        os.chmod(chef_install_script.name, stat.S_IRWXU)
        sudo(chef_install_script.name, "-v", chef_version)
        os.remove(chef_install_script.name)  # on failure, leave for debugging
    except Exception as exc:
        raise ChefError("chef-client install failed on:\n%s" % exc)


    logger.info('Setting up chef-client [chef_server=\n%s]', chef_server_url)
    for directory in '/etc/chef', '/var/chef', '/var/log/chef':
        sudo("mkdir", directory)

    sudo_write_file('/etc/chef/validation.pem', chef_validation)
    sudo_write_file('/etc/chef/client.rb', """
log_level          :info
log_location       "/var/log/chef/client.log"
ssl_verify_mode    :verify_none
validation_client_name "{chef_validator_name}"
validation_key         "/etc/chef/validation.pem"
client_key             "/etc/chef/client.pem"
chef_server_url    "{server_url}"
environment    "{server_environment}"
file_cache_path    "/var/chef/cache"
file_backup_path   "/var/chef/backup"
pid_file           "/var/run/chef/client.pid"
Chef::Log::Formatter.show_time = true
        """.format(server_url=chef_server_url,
                   server_environment=chef_environment,
                   chef_validator_name=chef_validator_name)
    )


def run_chef(runlist, attributes=None):
    """Run runlist with chef-client using these attributes(json or dict)"""
    # I considered moving the attribute handling to the set-up phase but
    # eventually left it here, to allow specific tasks to easily override them.
    if isinstance(attributes, str):  # assume we received json
        try:
            attributes = json.loads(attributes or "{}")
        except ValueError:
            raise ChefError("Failed json validation of chef attributes:\n%s" % attributes)

    attribute_file = tempfile.NamedTemporaryFile(suffix="chef_attributes.json",
                                                 delete=False)
    json.dump(attributes, attribute_file)
    attribute_file.close()

    try:
        #TODO: I chose to use --force-formatter here to push output through stdout to be caught inside sudo()
        #      so that it can be included in exceptions, but with current implementation of sudo(),
        #      I'm completely losing output of successful runs. If needed, we can perhaps put it back in /var/log/chef/
        sudo("chef-client", "-o", runlist, "-j", attribute_file.name, "--force-formatter")
        os.remove(attribute_file.name)  # on failure, leave for debugging
    except SudoError as exc:
        raise ChefError("The chef run failed\n"
                        "runlist: {runlist}\nattributes: {attributes}\nexception: \n{exc}".format(**locals()))


def set_up_chef_client(func):
    """Decorates a method with a call to install and set up chef-client, if needed"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        """Pass to install_chef the fields it needs"""
        required_fields = {'chef_version', 'chef_server_url', 'chef_environment',
                           'chef_validator_name', 'chef_validation'}

        missing_fields = required_fields.difference(kwargs.keys())
        if missing_fields:
            raise ChefError("The following required field(s) are missing: %s"
                               % ", ".join(missing_fields))

        install_args = {k: v for k, v in kwargs.items() if k in required_fields}
        install_chef(**install_args)

        return func(*args, **kwargs)

    return wrapper
