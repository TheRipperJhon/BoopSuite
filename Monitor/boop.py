#!/usr/bin/env python

import time

import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl

import argparse

from os import system, path, getuid, uname
from sys import exit, stdout, exc_info


class c:
    HEADER    = "\033[95m"
    OKBLUE    = "\033[94m"
    OKGREEN   = "\033[92m"
    WARNING   = "\033[93m"
    FAIL      = "\033[91m"
    WHITE     = "\033[37m"
    ENDC      = "\033[0m"
    BOLD      = "\033[1m"
    UNDERLINE = "\033[4m"


class Configuration:
    def __init__(self):
        self.check_root()
        self.check_op()

        parser = argparse.ArgumentParser()

        parser.add_argument(
            "-i",
            "--interface",
            action="store",
            dest="interface",
            help="select an interface",
            required=True)

        parser.add_argument(
            "-n",
            "--name",
            action="store",
            default=None,
            dest="name",
            help="select a new card name")

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

        results = parser.parse_args()

        self.parse_interface(results.interface)
        self.parse_channel(results.channel)
        self.parse_name(results.name)
        self.parse_kill(results.kill)

        self.make_card_changes()

        return

    def check_root(self):
        if getuid() != 0:
            print(c.FAIL+" [-] User is not Root.")
            exit()
        return

    def check_op(self):
        if uname()[0].startswith("Linux") and not "Darwin" not in uname()[0]:
            print(c.FAIL+" [-] Wrong OS.")
            exit()
        return

    def parse_interface(self, interface):
        if interface in pyw.interfaces():
            print(c.OKGREEN+" [+] "+c.WHITE+"Valid Card Selected.")

            info = pyw.ifinfo(pyw.getcard(interface))

            print("   '->  Driver: "+info["driver"])
            print("   '->  Hardware Address: "+info["hwaddr"])
            print("   '->  manufacturer: "+info["manufacturer"])

            if pyw.modeget(pyw.getcard(interface)) == "monitor":
                self.monitor = True
            else:
                self.monitor = False
            self.interface = interface
            return

        print(c.FAIL+" [+] Invalid Card Selected.")
        exit(0)
        return

    def parse_name(self, name):
        if str(name) not in pyw.interfaces() or self.interface == name:
            self.name = name
        else:
            print(c.FAIL+" [-] "+c.WHITE+" Address already in use.")
            exit(0)
        return

    def parse_kill(self, kill):
        if kill:
            self.kill_interfering_tasks()
            print(c.WARNING+" [+] Killing Tasks")
        return

    def parse_channel(self, channel):
        five_ghz = [
            36, 40, 44, 48, 52,
            56, 60, 64, 100, 104,
            108, 112, 116, 132,
            136, 140, 149, 153,
            157, 161, 165
            ]
        if channel == None:
            self.channel = None
            return

        elif int(channel) in xrange(1, 12):

            print(c.OKGREEN+" [+] "+c.WHITE+"Channel in range: 2GHz")
            self.frequency = "2GHz"

            if self.frequency in pyw.phyinfo(pyw.getcard(self.interface))['bands'].keys():
                print(c.OKGREEN+" [+] "+c.WHITE+"Valid Channel selected.")
                self.channel = channel
                return

            else:
                print(c.FAIL+" [-] "+c.WHITE+" Invalid Channel selected.")
                exit(0)

        elif int(channel) in five_ghz:

            print(" [+] Channel in range: 5GHz")
            self.frequency = "5GHz"

            if self.frequency in pyw.phyinfo(pyw.getcard(self.interface))['bands'].keys():
                print(c.OKGREEN+" [+] "+c.WHITE+"Valid Channel selected.")
                self.channel = channel
                return

            else:
                print(c.FAIL+" [-] "+c.WHITE+" Invalid Channel selected.")
                exit(0)

        else:
            print(c.FAIL+" [-] "+c.WHITE+" Channel is invalid in either frequency")
            exit(0)
        return

    def kill_interfering_tasks():
        commandlist = [
            "service avahi-daemon stop",
            "service network-manager stop",
            "pkill wpa_supplicant",
            "pkill dhclient"
        ]

        for item in commandlist:
            try:
                system("sudo "+item)
            except:
                pass
        return

    def make_card_changes(self):
        if self.monitor == True:
            print(c.OKGREEN+" [+] "+c.WARNING+"Disabling monitor mode")
            self.turn_monitor_off()
        else:
            print(c.OKGREEN+" [+] "+c.WARNING+"Enabling monitor mode")
            self.turn_monitor_on()
        return

    def turn_monitor_on(self):
        self.card = pyw.getcard(self.interface)
        if self.name:
            self.newcard = pyw.devset(self.card, self.name)
            pyw.modeset(self.newcard, "monitor")
            pyw.up(self.newcard)
        else:
            self.newcard = pyw.devset(self.card, self.card.dev+"mon")
            pyw.modeset(self.newcard, "monitor")
            pyw.up(self.newcard)

        print(c.OKGREEN+" [+] "+c.WHITE+"New Card Name: "+c.HEADER+self.newcard.dev)

        if self.channel != None:
            self.set_channel()

        return

    def turn_monitor_off(self):
        self.card = pyw.getcard(self.interface)
        if self.name:
            self.newcard = pyw.devset(self.card, self.name)
            pyw.modeset(self.newcard, "managed")
            pyw.up(self.newcard)
        else:
            if len(self.card.dev) < 4:
                self.newcard = pyw.devset(self.card, "boopmon")
            else:
                self.newcard = pyw.devset(self.card, self.card.dev[:-3])
            pyw.modeset(self.newcard, "managed")
            pyw.up(self.newcard)

        print(c.OKGREEN+" [+] "+c.WHITE+"New Card Name: "+c.HEADER+self.newcard.dev)

        if self.channel != None:
            self.set_channel()
        return

    def set_channel(self):
        if str(self.frequency) == "2GHz":
            __FREQS__ = {
                1: "2.412",
                2: "2.417",
                3: "2.422",
                4: "2.427",
                5: "2.432",
                6: "2.437",
                7: "2.442",
                8: "2.447",
                9: "2.452",
                10: "2.457",
                11: "2.462"
            }

        elif str(self.frequency) == "5GHz":
            __FREQS__ = {
                36:"5.180",
                40: "5.200",
                44: "5.220",
                48: "5.240",
                52: "5.260",
                56: "5.280",
                60: "5.300",
                64: "5.320",
                100: "5.500",
                104: "5.520",
                108: "5.540",
                112: "5.560",
                116: "5.580",
                132: "5.660",
                136: "5.680",
                140: "5.700",
                149: "5.745",
                153: "5.765",
                157: "5.785",
                161: "5.805",
                165: "5.825"
            }

        channel = __FREQS__[int(self.channel)]
        system("sudo iwconfig "+str(self.newcard.dev)+" freq "+channel+"G")
        print(c.OKGREEN+" [+] "+c.WHITE+"Card Set to Channel: "+c.HEADER+str(self.channel))
        return


def display_art():
    print(c.OKBLUE+"""
 /$$$$$$$
| $$__  $$
| $$  \ $$  /$$$$$$   /$$$$$$   /$$$$$$
| $$$$$$$  /$$__  $$ /$$__  $$ /$$__  $$
| $$__  $$| $$  \ $$| $$  \ $$| $$  \ $$
| $$  \ $$| $$  | $$| $$  | $$| $$  | $$
| $$$$$$$/|  $$$$$$/|  $$$$$$/| $$$$$$$/
|_______/  \______/  \______/ | $$____/
                              | $$
                              | $$
                              |__/
    """)
    print(c.HEADER+"     Codename: Inland Taipan\r\n"+c.BOLD)
    return


def main():
    stdout.write("\x1b[8;{rows};{cols}t".format(rows=35, cols=75))
    start = time.time()
    display_art()
    try:
        configuration = Configuration()
    except Exception,e:
        print(" [-]An error occured: "+str(e))

    print(c.OKBLUE+" [+] "+c.WHITE+"Time: "+c.OKGREEN+str(round(time.time() - start, 5)))
    return (0)


if __name__ == "__main__":
    main()
