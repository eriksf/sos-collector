#!/usr/bin/env python

# Copyright (C) 2017, Kyle Squizzato <ksquizz@gmail.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

"""
Tool to run and collect sosreports from list of IPs or FQDNs
"""
import sys
import paramiko
import threading
import os
import logging
import argparse
import getpass
import time
import signal
import socket
import atexit
import validators
from subprocess import Popen, call, CalledProcessError, check_output, PIPE, STDOUT
from scp import SCPClient
from six.moves import input as raw_input

logger = logging.getLogger(__name__)


def is_valid(hostname):
    """
    Provide parser validation
    """
    # Test if hostname is either a valid IP address or FQDN
    if (validators.ip_address.ipv4(hostname) or validators.domain(hostname)):
        return True
    else:
        return False


def generate_host_list():
    """
    Generate the list of hosts to use
    """
    host_list = set(args.host_list.split(","))
    return host_list


def parse_host_list(host_list):
    """
    Parse the generated list and determine if the provided hostnames or IP addresses
    are truly valid using is_valid()
    """
    for item in host_list:
        if not is_valid(item):
            logger.error("{0} is not a valid FQDN or IPv4 address, please correct it and rerun sos-collector".format(item))
            sys.exit(1)


def parse_host_file(input_file):
    """
    Parse properly formatted host_file, similar to parse_host_list but for a file
    instead of a comma-delimted list of hosts
    """
    # Read input file
    try:
        open(input_file, "r+").read()
    except IOError as e:
        logger.error('Unable to parse host-file: {0}'.format(e))
        sys.exit(1)
    # Create a dictionary of 'hostname': 'rootPassword'
    host_dict = {}
    with open(input_file, 'r') as f:
        for line in f:
            x = line.split('::')
            host = x[0]
            password = x[1]
            password = password[:-1]
            host_dict[host] = password
    return host_dict


def ssh_precheck():
    """
    Perform ssh prechecks
    """
    homedir = os.path.expanduser('~')
    logger.info("Generating keyless ssh for the root user on each host.")
    # Check to make sure the user has an id_rsa.pub file before continuing
    logger.debug("Check for id_rsa.pub existence")
    if not os.path.isfile('{0}/.ssh/id_rsa.pub'.format(homedir)):
        # For now we'll just prompt the user to run ssh-keygen on their own.  We
        # can probably use the Crypto library in the future to do this for users
        # but that's a can of worms
        logger.error("No .ssh/id_rsa.pub file found in home directory \
        please create one using ssh-keygen and restart sos-collector")
        sys.exit(1)
    else:
        pass


def configure_ssh_for_list(host_list, rootPassword):
    """
    Configure keyless ssh for hosts where rootPassword matches (command line entry)
    """
    logger.debug("Run ssh-deploy-key on host_list")
    for each in host_list:
        ssh_deploy_key_args = ['ssh-deploy-key',
                               '-u', 'root',
                               '-p', '{0}'.format(rootPassword),
                               '{0}'.format(each)
                               ]
        ssh_deploy_key = Popen(ssh_deploy_key_args)
        ssh_deploy_key.wait()


def configure_ssh_for_file(host_dict, input_file):
    """
    Configure keyless ssh for each host in a given host_file, extra steps are needed
    here over configure_ssh_for_list() as the rootPassword's can differ here.
    Because of this, this function requires a dict built using parse_host_file()
    """
    logger.debug("Run ssh-deploy-key on given hosts in {0}".format(input_file))
    for key, value in host_dict.iteritems():
        ssh_deploy_key_args = ['ssh-deploy-key',
                               '-u', 'root',
                               '-p', '{0}'.format(value),
                               '{0}'.format(key)
                               ]
        ssh_deploy_key = Popen(ssh_deploy_key_args)
        ssh_deploy_key.wait()
    # return the host_list once ssh-deploy-key is finished
    host_list = []
    for key in host_dict.iteritems():
        # build a host_list
        host_list.append(key)
    # return a set of host_list to prevent duplicates
    return set(host_list)


def run_sos(host_list, customer_name, case_id, plugin_list=None, options=None):
    """
    Run sosreport on resulting host_list
    """
    # implement a way for users to set whatever sosreport flags they want
    if options is None:
        options = ""
    # sosreport command to run
    if plugin_list is None:
        sosreport_command = 'sosreport --name {0} --case-id={1} {2}'.format(customer_name, case_id, options)
    else:
        # sosreport_command should include plugin flag with appropriate
        # plugin_list string: 'PLUGNAME,PLUGNAME2'
        # implemented via the ONLY_PLUGINS option in sosreport, see man sosreport
        # for details
        # {3} denotes extra options to pass
        sosreport_command = 'sosreport -o {0} --name={1} --case-id={2} {3}'.format(plugin_list, customer_name, case_id, options)
    # Iterate through host_list and run sosreport on each host
    # Should be implemented via threading
    for each in host_list:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.load_system_host_keys()
        # Shouldn't need password since ssh-copy-key has already been configured
        # by now
        logger.debug('Connecting to host: {0} to run sosreport'.format(each))
        ssh.connect(each,
                    username="root",
                    #look_for_keys=False
                    )
        # FIXME: For debugging log the stdout of the command execution
        stdin, stdout, stderr = ssh.exec_command(sosreport_command)
        # Wait for the sosreport commands to finish before continuing
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logging.info('Successfully ran sosreport on host {0}'.format(each))
        else:
            logging.error('Error running sosreport on host {0}'.format(each))
            # We'll close the connection but proceed here to try to capture
            # sosreport on remaining hosts
            ssh.close()


def collect_sos(directory=None):
    """
    Copy resulting sosreports from run_sos from host_list into target directory
    Default is pwd
    """
    # Directory to use if argument is given, if None is supplied, just use
    # pwd for target
    if directory is not None:
        target = directory
    else:
        target = "."

    return target


def archive_sos():
    """
    Create one large archive of the resulting sosreport grab
    """
    pass


def exit_handler():
    """
    Cleanup and log on exit
    """
    logger.info('sos-collector has exited')


"""
Handle signals
"""
SIGNALS_TO_NAMES_DICT = dict((getattr(signal, n), n) for n in dir(signal) if n.startswith('SIG') and '_' not in n)


def signal_handler(signum, frame, retries=0):
    logger.error("Received signal: {0}({1})".format(SIGNALS_TO_NAMES_DICT[signum], signum))
    raise RuntimeError('Received signal: {0}({1})'.format(SIGNALS_TO_NAMES_DICT[signum], signum))
    sys.exit(signum)


def question(type_, question=None):
    # If no type_ is specified, the first arg becomes the question
    # and a string value is assumed
    if question is None:
        question = type_
        type_ = "string"
    answer = None
    while not answer:
        answer = raw_input(question + ": ")
    # If this is an array, we need to convert from string to array
    if type_ == "array":
        # Remove spaces
        answer = answer.replace(" ", "")
        answer = answer.split(",")
    return answer


def main():
    """
    Run it
    """
    # Define globals
    global args
    # Provide command line arguments
    parser = argparse.ArgumentParser(description="Capture sosreports from a \
                                    provided list of hosts. Resulting sosreports \
                                    are placed in a tarball.  Requires root \
                                    access on targetted machines.")
    parser.add_argument("-H",
                        "--hosts",
                        dest="host_list",
                        help="Define comma-delimited FQDNs or IP address where \
                        sosreports should be ran and captured. \
                        (Ex. server1.example.com,server2.example.com,192.168.1.224)")
    parser.add_argument("-p",
                        "--plugins",
                        dest="sosreport_plugins",
                        help="Define a list of comma-delimited sosreport plugins \
                        to be used in place of the default, which runs sosreport \
                        with all plugins. (Ex. ceph,devicemapper)")
    parser.add_argument("-f",
                        "--host-file",
                        dest="host_file",
                        help="Specify a file which contains a list of hosts \
                        to use instead of specifying with -h, --hosts. \
                        See README for information on how to format this list.")
    parser.add_argument("-d",
                        "--directory",
                        dest="directory",
                        help="Define the target directory the sosreports \
                        will be downloaded to and processed in.  Defaults to \
                        the present working directory")
    parser.add_argument("--no-root",
                        dest="no_root",
                        action='store_true',
                        help="Skips the root password asks.  Use this option \
                        if you've already configured keyless SSH on the \
                        selected target hosts and do not wish to use the built \
                        in keyless configuration in this script.")
    parser.add_argument("--threads",
                        dest="thread_count",
                        help="Control the number of ssh threads spawned by \
                        sos-collector to capture data in parallel.  Default 4.")
    parser.add_argument("-D",
                        "--debug",
                        dest="debug",
                        action='store_true',
                        help="Enable debug mode")
    args = parser.parse_args()

    # Control whether debug logging should be enabled or not
    if args.debug is True:
        logging.basicConfig(stream=sys.stdout,
                            level=logging.DEBUG,
                            format='%(asctime)s.%(msecs)d %(levelname)s %(module)s | %(funcName)s: %(message)s',
                            datefmt="%Y-%m-%d %H:%M:%S"
                            )
    else:
        logging.basicConfig(format='%(levelname)s: %(message)s',
                            level=logging.INFO
                            )

    # Check to ensure a host_list is provided
    if args.host_list is None and args.host_file is None:
        logger.error("No hosts were specified.  Use either -h or -F to specify a list of hosts.  See --help for more info.")
        sys.exit(1)
    # Prompt the user for the same information that sosreport requests during
    # initial start.  We'll follow the same design sosreport does here and not
    # perform any validation on these answers.
    username = question("string", "Please enter your first initial and last name")
    caseid = question("string", "Please enter the case id that you are generating this report for")
    if args.host_file is None:
        # If no host_file option is detected ask for rootPassword
        if args.no_root is False:
            rootPassword = getpass.getpass("Enter the root password for the machine \
(if you wish to use different root passwords you must specify them via a host \
file using -f, --host-file): ")
        # Then generate and parse the given host_list
        host_list = generate_host_list()
        parse_host_list(host_list)
    else:
        # Else assume host_file, parse the host_file instead
        dictionary = parse_host_file(args.host_file)
    if args.no_root is False:
        ssh_precheck()
        if args.host_file is not None:
            host_list = configure_ssh_for_file(dictionary, args.host_file)
        else:
            configure_ssh_for_list(host_list, rootPassword)
    run_sos(host_list, username, caseid)


"""
Main
"""
if __name__ == '__main__':
    atexit.register(exit_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    sys.exit(main())
