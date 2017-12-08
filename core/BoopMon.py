#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import sys
import time

# Add Parent Directory to path
parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.sys.path.insert(0, parentdir)

from modules import devices
from modules import arguments
from modules import taskkill

version_file = open("../VERSION", 'r')
__VERSION__ = version_file.read().strip()
version_file.close()

# Moved reused code to WeeHelper

# Summary:
#   Function to change card mode
# Args:
#   interface -> String: name of card
#   name      -> String: new name of card
#   mac       -> String: new mac of card
#   ch        -> int: channel of card
def pymon(interface, name, mac, kill, ch=None):
    '''
        Function for Setting card mode and calling other functions;

        author: Jarad
    '''

    mac_regex = "[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"

    if kill:
        taskkill.kill_blocking_tasks()

    card = devices.get_device(interface)

    info = devices.get_info(card)
    sinfo = devices.get_phy_info(card)

    mode = devices.get_mode(interface)

    print("Driver:  {0}".format(info["driver"]))
    print("Address: {0}".format(info["hwaddr"]))
    print("Mode:    {0}".format(mode))
    print("Vendor:  {0}".format(info["manufacturer"]))

    if name:
        name = name.decode('unicode_escape').encode('ascii', 'ignore')

    devices.card_down(card)

    if mode == "managed":
        print("managed")
        newcard = devices.set_monitor_mode(card, name)

    elif mode == "monitor":
        newcard = devices.set_managed_mode(card, name)

    else:
        print("Card mode unrecognized")
        sys.exit(0)

    if mac and re.match(mac_regex, mac.lower()):

        try:
            devices.set_mac(newcard, mac)
            print("Mac:     " + devices.get_mac(newcard) + "\n")

        except:
            print("Cannot Assign Requested Address.\n\n")

    devices.card_up(newcard)

    if ch:
        devices.set_channel(newcard, int(ch))

    print("Card:    " + newcard.dev)
    print("Mode:    " + devices.get_mode(newcard.dev))

    return


if __name__ == "__main__":
    start = time.time()

    arguments.root_check()

    sys.stdout.write("[ WeeMon ]\n\n")
    sys.stdout.write("Version: " + __VERSION__ + "\n\n")

    results = arguments.args_parser("monitor")

    pymon(
        results['interface'],
        results['name'],
        results['mac'],
        results['kill'],
        results['channel'])

    sys.stdout.write("\nTime: " + str(round(time.time() - start, 4)) + "\n")
