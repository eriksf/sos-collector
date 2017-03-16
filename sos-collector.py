#!/usr/bin/env python
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

"""
Provide parser validation
"""
def is_valid(hostname):
    # Test if hostname is either a valid IP address or FQDN
    if (
    validators.ip_address.ipv4(hostname) or
    validators.domain(hostname)
    ):
        return True
    else:
        return False

"""
Generate the list of hosts to use
"""
def generate_host_list():
    global host_list
    host_list = set(args.host_list.split(","))

"""
Parse the generated list and determine if the provided hostnames or IP addresses
are truly valid using is_valid_ipaddr() and is_valid_hostname()
"""
def parse_host_list():
    for item in host_list:
        if is_valid(item) == False:
            logging.error("{0} is not a valid FQDN or IPv4 address, \
please correct it and rerun sos-collector".format(item))
            sys.exit(1)

"""
Configure keyless ssh for each host in host_list
"""
def configure_ssh():
    homedir = os.path.expanduser('~')
    logging.info("Generating keyless ssh for the root user on each host.")
    # Check to make sure the user has an id_rsa.pub file before continuing
    logging.debug("Check for id_rsa.pub existence")
    if os.path.isfile('{0}/.ssh/id_rsa.pub'.format(homedir)) == False:
        # For now we'll just prompt the user to run ssh-keygen on their own.  We
        # can probably use the Crypto library in the future to do this for users
        # but that's a can of worms
        logging.error("No .ssh/id_rsa.pub file found in home directory \
        please create one using ssh-keygen and restart sos-collector")
        sys.exit(1)
    else:
        pass
    logging.debug("Run ssh-deploy-key on host_list")
    for each in host_list:
        ssh_deploy_key_args = [ 'ssh-deploy-key',
                    '-u', 'root',
                    '-p', '{0}'.format(rootPassword),
                    '{0}'.format(each)]
        ssh_deploy_key = Popen(ssh_deploy_key_args)
        ssh_deploy_key.wait()

"""
Cleanup and log on exit
"""
def exit_handler():
    logging.info('sos-collector has exited')

"""
Handle signals
"""
SIGNALS_TO_NAMES_DICT = dict((getattr(signal, n), n) \
    for n in dir(signal) if n.startswith('SIG') and '_' not in n )

def signal_handler(signum, frame, retries=0):
    logging.error("Received signal: {0}({1})".format(SIGNALS_TO_NAMES_DICT[signum], signum))
    raise RuntimeError('Received signal: {0}({1})'.format(SIGNALS_TO_NAMES_DICT[signum], signum))
    sys.exit(signum)

def question(type_,question = None):
    # If no type_ is specified, the first arg becomes the question
    # and a string value is assumed
    if question == None:
        question = type_
        type_ = "string"
    answer = None
    while not answer:
        answer = raw_input(question + ": ")
    # If this is an array, we need to convert from string to array
    if type_ == "array":
        # Remove spaces
        answer = answer.replace(" ","")
        answer = answer.split(",")
    return answer

"""
Run it
"""
def main():
    # Define globals
    global args, rootPassword
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
                        help="Define the targetted directory the sosreports \
                        will be downloaded to and processed in.  Defaults to \
                        the present working directory")
    parser.add_argument("-D",
                        "--debug",
                        dest="debug",
                        action='store_true',
                        help="Enable debug mode")
    args = parser.parse_args()
    # Control whether debug logging should be enabled or not
    logger = logging.getLogger(name=None)
    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=logging.INFO
                        )
    if args.debug == True:
        logging.basicConfig(stream=sys.stdout,
                            level=logging.DEBUG,
                            format='%(asctime)s.%(msecs)d %(levelname)s %(module)s | %(funcName)s: %(message)s',
                            datefmt="%Y-%m-%d %H:%M:%S"
                            )
    # Check to ensure a host_list is provided
    if args.host_list == None and args.host_file == None:
        logging.error("No hosts were specified.  Use either -h or -F to specify a list of hosts.  See --help for more info.")
        sys.exit(1)
    # Generate and parse the host-list before we ask any questions
    generate_host_list()
    parse_host_list()
    # Prompt the user for the same information that sosreport requests during
    # initial start.  We'll follow the same design sosreport does here and not
    # perform any validation on these answers.
    username = question("string","Please enter your first initial and last name")
    caseid = question("string","Please enter the case id that you are generating this report for")
    #FIXME: Find out a way to handle different rootpw's
    rootPassword = getpass.getpass("Enter the root password for the machines \
(if you wish to use different root passwords you must specify them via a host \
file using -f, --host-file): ")
    configure_ssh()

if __name__ == '__main__':
    atexit.register(exit_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    sys.exit(main())
