#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import signal

# Add Parent Directory to path
parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.sys.path.insert(0, parentdir)

from modules import arguments
from modules import taskkill
from modules import sniffer

from modules import clients
from modules import networks

__VERSION__ = "2.0.0"

# Add Color classes somewhere

# Summary:
#   Function to print credits
# Args:
#   None
def welcome():
    os.system("clear")

    print("BoopMon "+__VERSION__)

    return 0

# Summary:
#   Function to create Directory for pcaps
# Args:
#   None
def pcap_dir_create():

    if not os.path.exists("pcaps"):
        os.makedirs("pcaps")

    return 0

# Summary:
#   Function to clean arguments from sys call
# Args:
#   dict of arguments.
def clean_args(args):

    mac_regex = "[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"

    five_hertz = [
        36, 40, 44, 48, 52, 56,
        60, 64, 100, 104, 108, 112,
        116, 132, 136, 140, 149, 153,
        157, 161, 165]

    if args['freq'] == "7":
        channels = [int(x) for x in args['channel'] if int(x) in xrange(12)]
        channels += [int(x) for x in args['channel'] if int(x) in five_hertz]

        if not channels:
            channels = list(xrange(12)) + five_hertz

    elif args['freq'] == "2":
        channels = [int(x) for x in args['channel'] if int(x) in xrange(12)]

        if not channels:
            channels = list(xrange(12))

    elif args['freq'] == "5":
        channels = [int(x) for x in args['channel'] if int(x) in five_hertz]

        if not channels:
            channels = five_hertz

    # Check if mac is of valid length.
    if args['mac'] and not re.match(mac_regex, args["mac"].lower()):
        print("Invalid mac option selected.")
        exit(101)

    # Check if task kill flag is set.
    if args['kill']:
        taskkill.Kill_blocking_tasks()

    # Check if target mac is of valid length.
    if args['target'] and not re.match(mac_regex, args['target'].lower()):
        print("Invalid Target Selected.")
        exit(102)

    channels = [x for x in channels if x != 0]

    return channels

# Summary:
#   Function to control program
# Args:
#   none
def main():

    welcome()
    arguments.root_check()
    pcap_dir_create()

    # intercept ctrl+c key event
    signal.signal(signal.SIGINT, arguments.signal_handler)

    args = arguments.sniffer_args()
    channels = clean_args(args)

    sniffer_object = sniffer.Sniffer(
        args['interface'],
        channels,
        args['target'],
        args['mac'],
        args['unassociated'],
        args['diagnose'],
        args['open'],
        args['clients'],
        args['time']
    )

    #try:
    sniffer_object.run()
    #except AttributeError:
    #    exit(0)

    return 0


if __name__ == "__main__":
    main()
