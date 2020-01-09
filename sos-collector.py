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
# import threading
import os
import logging
import argparse
# import getpass
# import time
import signal
# import socket
import atexit
import validators
# from subprocess import Popen, call, CalledProcessError, check_output, PIPE, STDOUT
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
        logger.error("{0} is not a valid FQDN or IPv4 address".format(hostname))
        return False


def generate_host_list(username, caseid):
    """
    Generate the list of hosts to use
    """
    host_list = set(args.host_list.split(","))
    host_dict = {}
    for host in host_list:
        if not is_valid(host):
            sys.exit(1)
        host_dict[host] = (username, caseid)

    return host_dict


def parse_host_file(input_file):
    """
    Parse properly formatted host_file, similar to parse_host_list but for a file
    instead of a comma-delimted list of hosts
    hostname::username::case-id
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
            if not is_valid(host):
                sys.exit(1)
            username = x[1]
            caseid = x[2]
            caseid = caseid[:-1]
            host_dict[host] = (username, caseid)
    return host_dict


def ssh_precheck():
    """
    Perform ssh prechecks
    """
    homedir = os.path.expanduser('~')
    logger.info("Checking for id_rsa.pub existence for keyless ssh...")
    if not os.path.isfile('{0}/.ssh/id_rsa.pub'.format(homedir)):
        # For now we'll just prompt the user to run ssh-keygen on their own.  We
        # can probably use the Crypto library in the future to do this for users
        # but that's a can of worms
        logger.error("No .ssh/id_rsa.pub file found in home directory \
        please create one using ssh-keygen and restart sos-collector")
        sys.exit(1)


def run_sos(host_dict, plugin_list=None, options=None):
    """
    Run sosreport on resulting host_list
    """
    report_files = {}

    # implement a way for users to set whatever sosreport flags they want
    if options is None:
        options = ""

    # Iterate through host_list and run sosreport on each host
    # FIXME: implement via threading
    for host in host_dict:
        # sosreport command to run
        customer_name = host_dict[host][0]
        case_id = host_dict[host][1]

        if plugin_list is None:
            sosreport_command = 'sosreport --batch --name {0} --case-id={1} {2}'.format(customer_name, case_id, options)
        else:
            # sosreport_command should include plugin flag with appropriate
            # plugin_list string: 'PLUGNAME,PLUGNAME2'
            # implemented via the ONLY_PLUGINS option in sosreport, see man sosreport
            # for details
            # {3} denotes extra options to pass
            sosreport_command = 'sosreport --batch -o {0} --name={1} --case-id={2} {3}'.format(plugin_list, customer_name, case_id, options)

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.load_system_host_keys()
            # Shouldn't need password since ssh-copy-key has already been configured
        #    by now
            logger.debug('Connecting to host: {0} to run sosreport'.format(host))
            ssh.connect(host,
                        username="root",
                        look_for_keys=True
                        )
        except paramiko.auth_handler.AuthenticationException as error:
            logger.error("Authentication failed, check proper public key: {}".format(error))
            raise error

        # FIXME: For debugging log the stdout of the command execution
        stdin, stdout, stderr = ssh.exec_command(sosreport_command)
        # Wait for the sosreport commands to finish before continuing
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info('Successfully ran sosreport on host {0}'.format(host))
            output = stdout.readlines()
            zipfile = (output[-6]).strip()
            logger.info("Report archive is '{}'".format(zipfile))
            report_files[host] = zipfile
        else:
            logger.error('Error running sosreport on host {0}'.format(host))
            # We'll close the connection but proceed here to try to capture
            # sosreport on remaining hosts
        ssh.close()
    return report_files


def progress(filename, size, sent):
    """
    Track progress of scp get.
    """
    sys.stdout.write("%s\'s progress: %.2f%%   \r" % (filename, float(sent) / float(size) * 100))


def collect_sos(report_files, directory=None):
    """
    Copy resulting sosreports from run_sos from host_list into target directory
    Default is cwd
    """
    # Directory to use if argument is given, if None is supplied, just use
    # pwd for target
    if directory is not None:
        target = directory
    else:
        target = "."

    for host in report_files:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.load_system_host_keys()
            # Shouldn't need password since ssh-copy-key has already been configured
        #    by now
            logger.debug('Grabbing report archive {0} from host {1}'.format(report_files[host], host))
            ssh.connect(host,
                        username="root",
                        look_for_keys=True
                        )
            scp = SCPClient(ssh.get_transport(), progress)
        except paramiko.auth_handler.AuthenticationException as error:
            logger.error("Authentication failed, check proper public key: {}".format(error))
            raise error

        scp.get(report_files[host], target)
        scp.close()
        ssh.close()


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

    if args.host_file is None:
        # Prompt the user for the same information that sosreport requests during
        # initial start.  We'll follow the same design sosreport does here and not
        # perform any validation on these answers.
        username = question("string", "Please enter your first initial and last name")
        caseid = question("string", "Please enter the case id that you are generating this report for")

        # Then generate and parse the given host_list
        host_dict = generate_host_list(username, caseid)
    else:
        # Else assume host_file, parse the host_file instead
        host_dict = parse_host_file(args.host_file)

    ssh_precheck()
    report_files = run_sos(host_dict)
    if report_files:
        collect_sos(report_files, args.directory)


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
