#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time

import argparse

import devices
import globalsx

# Summary:
#   Function to check for root on linux
# Args:
#   none
def root_check():
    # Check for root.
    if os.getuid() != 0:

        print("User is not Root.")
        sys.exit(103)

    if "linux" not in sys.platform.lower():

        print("Wrong OS.")
        sys.exit(104)

    return 0


# Handler for ctrl+c Event.
def signal_handler(*args):
    # Set global flag to false to kill daemon threads.
    globalsx.gALIVE = False

    print("\r[+] Commit to exit.")

    # Sleep to allow one final execution of threads.
    time.sleep(2.5)

    # Kill Program.
    sys.exit(0)


# Function to gather all arguments passed by CLI
def args_parser(caller):

    version_file = open("../VERSION", 'r')
    __VERSION__ = version_file.read().strip()
    version_file.close()

    # Instantiate parser object
    parser = argparse.ArgumentParser()

    # Arg for version number.
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version=__VERSION__)

    # Arg for channel.
    parser.add_argument(
        "-c",
        "--channel",
        action="store",
        default=[],
        dest="channel",
        nargs="*",
        help="select a channel")

    # Flag for kill commands.
    parser.add_argument(
        "-k",
        "--kill",
        action="store_true",
        dest="kill",
        help="sudo kill interfering processes.")

    # Start monitor args:
    if caller == "monitor":
        parser.add_argument(
            "-n",
            "--name",
            action="store",
            default=None,
            dest="name",
            help="select a new card name")

        # Arg for interface.
        parser.add_argument(
            "-i",
            "--interface",
            action="store",
            dest="interface",
            help="select an interface",
            choices=devices.get_devices(),
            required=True)

    elif caller == "deauth":
        parser.add_argument(
            "-s",
            "--skip",
            action="store",
            default=None,
            dest="skip",
            help="Mac to not deauth (Usually your own...)")

        parser.add_argument(
            "-p",
            "--packets",
            action="store",
            default=5,
            dest="packets",
            help="How many deauth packets to send, more than 5 is usually unneccessary.")

    elif caller == "sniffer":
        # Flag for unassociated clients.
        parser.add_argument(
            "-u",
            "--unassociated",
            action="store_true",
            dest="unassociated",
            help="Whether to show unassociated clients.")

        # No show client or open networks.
        parser.add_argument(
            "-N",
            "--No-clients",
            action="store_true",
            default=False,
            dest="clients",
            help="Switch for displaying any clients at all")

        parser.add_argument(
            "-O",
            "--No-open",
            action="store_true",
            default=False,
            dest="open",
            help="Switch for displaying open networks")

        # Arg for diagnostic mode.
        parser.add_argument(
            "-D",
            "--Diagnose",
            action="store_true",
            default=False,
            dest="diagnose",
            help="Switch for diagnostic mode.")

    if caller == "monitor" or caller == "sniffer":
        parser.add_argument(
            "-m",
            "--mac",
            action="store",
            dest="mac",
            default=None,
            help="Set Mac Address.")

    if caller == "deauth" or caller == "sniffer":
        # Arg for interface.
        parser.add_argument(
            "-i",
            "--interface",
            action="store",
            dest="interface",
            help="select an interface",
            choices=devices.get_mon_devices(),
            required=True)

        # Arg for frequency.
        parser.add_argument(
            "-f",
            "--frequency",
            action="store",
            default="2",
            dest="freq",
            help="select a frequency (2/5/all)",
            choices=["2", "5", "all"])

        # Arg for target to sniff.
        parser.add_argument(
            "-t",
            "--target",
            action="store",
            default=[],
            dest="target",
            nargs="*",
            help="Command for targeting a specific network.")

        parser.add_argument(
            "-T",
            "--Timeout",
            action="store",
            default=None,
            type=int,
            dest="time",
            help="Command for killing after a certain amount of time.")

    # return dict of args.
    return vars(parser.parse_args())
