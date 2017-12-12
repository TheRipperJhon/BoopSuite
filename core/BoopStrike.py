#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import signal

from sys import exit, stdout, stderr

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.sys.path.insert(0, parentdir)

from modules import sniffer
from modules import arguments
from modules import taskkill

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

    # Check if task kill flag is set.
    if args['kill']:
        taskkill.kill_blocking_tasks()

    # Check if target mac is of valid length.
    args['target'] = [x for x in args['target'] if re.match(mac_regex, x.lower())]

    channels = [x for x in channels if x != 0]

    return channels

# Summary:
#   Function to control program
# Args:
#   None
def main():
    arguments.root_check()

    signal.signal(signal.SIGINT, arguments.signal_handler)

    args = arguments.args_parser("deauth")
    channels = clean_args(args)

    sniffer_object = sniffer.Sniffer(
        args['interface'],
        channels,
        args['target'],
        None,
        None,
        False,
        None,
        None,
        args['time'],
        True,
        args['packets']
    )

    sniffer_object.run()

    return 0


if __name__ == "__main__":
    main()
