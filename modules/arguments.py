#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time

import argparse

import devices
import globalsx

__VERSION__ = "1.1.4"

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
def sniffer_args():

    # Instantiate parser object
    parser = argparse.ArgumentParser()

    # Arg for version number.
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version=__VERSION__)

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
        help="select a frequency (2/5)",
        choices=["2", "5", "7"])

    # Arg for channel.
    parser.add_argument(
        "-c",
        "--channel",
        action="store",
        default=[],
        dest="channel",
        nargs="*",
        help="select a channel")

    # Arg for custom mac address.
    parser.add_argument(
        "-m",
        "--mac",
        action="store",
        default=None,
        dest="mac",
        help="Custom Mac Address")

    # Flag for kill commands.
    parser.add_argument(
        "-k",
        "--kill",
        action="store_true",
        dest="kill",
        help="sudo kill interfering processes.")

    # Flag for unassociated clients.
    parser.add_argument(
        "-u",
        "--unassociated",
        action="store_true",
        dest="unassociated",
        help="Whether to show unassociated clients.")

    # Arg for target to sniff.
    parser.add_argument(
        "-t",
        "--target",
        action="store",
        default=None,
        dest="target",
        help="Command for targeting a specific network.")

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

    parser.add_argument(
        "-T",
        "--Timeout",
        action="store",
        default=None,
        type=int,
        dest="time",
        help="Command for killing after a certain amount of time.")

    # Arg for diagnostic mode.
    parser.add_argument(
        "-D",
        "--Diagnose",
        action="store_true",
        default=False,
        dest="diagnose",
        help="Switch for diagnostic mode.")

    # return dict of args.
    return vars(parser.parse_args())

# Summary:
#   Function to handle args for monitor mode script
# Args:
#   None
def monitor_args():
    '''
        Function for handling the sys.arg's;

        author: Jarad
    '''

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="interface",
        help="select an interface",
        required=True,
        choices=devices.get_devices())

    parser.add_argument(
        "-n",
        "--name",
        action="store",
        default=None,
        dest="name",
        help="select a new card name")

    parser.add_argument(
        "-m",
        "--mac",
        action="store",
        dest="mac",
        default=None,
        help="Set Mac Address.")

    parser.add_argument(
        "-c",
        "--channel",
        action="store",
        default=None,
        dest="channel",
        help="select a channel")

    parser.add_argument(
        "-k",
        "--kill",
        action="store_true",
        dest="kill",
        default=False,
        help="kill interfering processes.")

    return vars(parser.parse_args())

# Summary:
#   Function to get args for deauth script
# Args:
#   none
def deauth_args():

    # Instantiate parser object
    parser = argparse.ArgumentParser()

    # Arg for version number.
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version=__VERSION__)

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
        help="select a frequency (2/5)",
        choices=["2", "5", "7"])

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

    # Arg for target to sniff.
    parser.add_argument(
        "-t",
        "--target",
        action="store",
        default=None,
        dest="target",
        help="Command for targeting a specific network.")

    parser.add_argument(
        "-T",
        "--Timeout",
        action="store",
        default=None,
        type=int,
        dest="time",
        help="Command for killing after a certain amount of time.")

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
        default=1,
        dest="packets",
        help="How many deauth packets to send, more than 5 is usually unneccessary.")

    # return dict of args.
    return vars(parser.parse_args())
