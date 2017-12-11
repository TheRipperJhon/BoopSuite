#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import requests
import signal

# Add Parent Directory to path
parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.sys.path.insert(0, parentdir)

from modules import arguments
from modules import taskkill
from modules import sniffer

from modules import clients
from modules import networks

version_file = open("../VERSION", 'r')
__VERSION__ = version_file.read().strip()
version_file.close()

# Add Color classes somewhere

# Summary:
#   Function to print credits
# Args:
#   None
def welcome():
    os.system("clear")

    print("BoopSniff "+__VERSION__)

    return 0

# Summary:
#   Function to create Directory for pcaps
# Args:
#   None
def pcap_dir_create():

    if not os.path.exists("pcaps"):
        os.makedirs("pcaps")

    return 0

def checkUpdate():
    gitlink = "https://github.com/MisterBianco/BoopSuite/raw/master/VERSION"
    page = requests.get(gitlink)
    version = page.text.strip()

    if version != __VERSION__:
        os.system("clear")
        update = raw_input("[Update Available] > (Y/n): ")

        if update.lower() == "y":

            update_file = open("../../update.sh", 'w')
            update_file.write("#!/bin/sh\n")
            update_file.write("rm -rf BoopSuite/\n")
            update_file.write("git clone https://github.com/MisterBianco/BoopSuite.git\n")
            update_file.write("BoopSuite/./install.py")
            update_file.write("\n")

            os.system("sudo chmod +x ../../update.sh")
            os.system("sudo ../.././update.sh")
            sys.exit()

        else:
            pass
    sys.exit(0)

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

    if args['freq'] == "all":
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
    args['target'] = [x for x in args['target'] if re.match(mac_regex, x.lower())]

    channels = [x for x in channels if x != 0]

    return channels

# Summary:
#   Function to control program
# Args:
#   none
def main():
    #checkUpdate()

    welcome()
    arguments.root_check()
    pcap_dir_create()

    # intercept ctrl+c key event
    signal.signal(signal.SIGINT, arguments.signal_handler)

    args = arguments.args_parser("sniffer")
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
