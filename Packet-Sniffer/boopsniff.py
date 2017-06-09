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

from getpass import getuser
from netaddr import *
from os import system, path, getuid, uname
from random import choice
from scapy.all import *
from sys import exit, stdout
from tabulate import tabulate
from threading import Thread
from time import sleep, time

conf.verb = 0

# GLOBALS
Global_Access_Points = {}   # MAC, AP OBJECT
Global_Clients = {}         # MAC, CLIENT OBJECT

Global_Mac_Filter_Channel = ""

Global_Hidden_SSIDs = []
Global_Ignore_Broadcast = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:80:c2:00:00:00"]
Global_Ignore_Multicast = ["01:00", "01:80:c2", "33:33"]

Global_Print_Flag = True
Global_Channel_Hopper_Flag = True

Global_Handshakes = {} # "NETWORKS", "EAPOLS"
Global_Mac_Filter = None
Global_Start_Time = ""
Global_Recent_Key_Cap = ""
Global_Handshake_Captures = 0

# CLASSES
class bcolors:
    HEADER    = "\033[95m"
    OKBLUE    = "\033[94m"
    OKGREEN   = "\033[92m"
    WARNING   = "\033[93m"
    FAIL      = "\033[91m"
    ENDC      = "\033[0m"
    BOLD      = "\033[1m"
    UNDERLINE = "\033[4m"

class Configuration:
    def __init__(self):
        self.check_root()
        self.check_op()
        return

    def user_force_variables_static(self):
        self.printer = True
        return

    def parse_interface(self, interface):
        if interface in pyw.interfaces() and pyw.modeget(interface) == "monitor":
            self.interface = interface
        else:
            print(bcolors.FAIL + " [-] Non Monitor card selected.")
            exit(0)
        return

    def parse_report(self, report):
        if report:
            try:
                system("touch "+report)
                self.report = open(report, "w")
            except:
                print(bcolors.FAIL+" [-] Report Location Invalid.")
        else:
            self.report = None
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
                print(bcolors.FAIL+" [-] Channel Setting incorrect.")
                exit(0)

            self.channel = None

        elif channel != None:
            if str(self.frequency) == "2" and int(channel) in xrange(1, 12):
                    self.hop = False
            elif str(self.frequency) == "5" and int(channel) in _5_channels_:
                    self.hop = False
            else:
                print(bcolors.FAIL+" [-] Channel Setting incorrect."+bcolors.ENDC)
                exit(0)

            self.channel = channel

        return

    def parse_kill(self, kill):
        if kill != False:
            commandlist = [
        "service avahi-daemon stop",
        "service network-manager stop",
        "pkill wpa_supplicant",
        "pkill dhclient"
        ]

            for item in commandlist:
                try:
                    os.system("sudo "+item)
                except:
                    pass
        return

    def parse_unassociated(self, un):
        self.unassociated = un
        return

    def parse_mac_filter(self, mac_filter):
        self.mac_filter = mac_filter
        return

    def parse_args(self):
        parser = argparse.ArgumentParser()

        parser.add_argument(
            "-i",
            action="store",
            dest="interface",
            help="select an interface",
            required=True)

        parser.add_argument(
            "-r",
            action="store",
            default=False,
            dest="report",
            help="select a report location")

        parser.add_argument(
            "-f",
            action="store",
            default="2",
            dest="freq",
            help="select a frequency (2/5)",
            choices=["2", "5"])

        parser.add_argument(
            "-c",
            action="store",
            default=None,
            dest="channel",
            help="select a channel")

        parser.add_argument(
            "-k",
            action="store_true",
            dest="kill",
            help="sudo kill interfering processes.")

        parser.add_argument(
            "-u",
            action="store_true",
            dest="unassociated",
            help="Whether to show unassociated clients.")

        parser.add_argument(
            "-a",
            action="store",
            default=None,
            dest="access_mac",
            help="Command for a specific mac addr.")

        results = parser.parse_args()

        self.parse_interface(results.interface)
        self.parse_report(results.report)
        self.parse_freq(results.freq)
        self.parse_channel(results.channel)
        self.parse_kill(results.kill)
        self.parse_unassociated(results.unassociated)
        self.parse_mac_filter(results.access_mac)

        self.user_force_variables_static()
        return

    def check_root(self):
        if getuid() != 0:
            print(bcolors.FAIL+" [-] User is not Root.")
            exit()
        print(bcolors.OKGREEN+" [+] User:     " + getuser())
        return

    def check_op(self):
        if uname()[0].startswith("Linux") and not "Darwin" not in uname()[0]:
            print(bcolors.FAIL+" [-] Wrong OS.")
            exit()

        print(bcolors.OKGREEN+" [+] Host OS:  " + str(uname()[0]))
        print(bcolors.OKGREEN+" [+] Hostname: " + str(uname()[1])+bcolors.ENDC+bcolors.BOLD)
        return

class Access_Point:
    def __init__(self, ssid, enc, ch, mac, ven, sig):
        self.mssid = ssid[:20]
        self.menc = enc
        self.mch = str(ch)
        self.mmac = mac
        self.mven = ven[:8]
        self.msig = sig
        self.mbeacons = 1
        self.meapols = 0
        return

    def update_ssid(self, ssid):
        self.mssid = ssid
        return

class Client:
    def __init__(self, mac, bssid, rssi):
        self.mmac   = mac
        self.mbssid = bssid
        self.msig   = rssi
        self.mnoise = 0
        return

# HANDLER
def handler_beacon(packet):
    global Global_Access_Points
    global Global_Clients
    global Global_Mac_Filter
    global Global_Mac_Filter_Channel

    source = packet.addr2

    if source in Global_Access_Points:
        Global_Access_Points[source].msig = (get_rssi(packet.notdecoded))
        Global_Access_Points[source].mbeacons += 1

    else:
        mac = packet.addr3
        destination = packet.addr1

        Global_Handshakes[mac] = []
        Global_Handshakes[mac].append(packet)

        if packet.info and u"\x00" not in "".join([x if ord(x) < 128 else "" for x in packet.info]):
            name = packet.info.decode("utf-8")
        else:
            Global_Hidden_SSIDs.append(mac)
            name = "<len: "+str(len(packet.info))+">"

        p = packet[Dot11Elt]
        cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
        "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split("+")

        sec = set()

        while isinstance(p, Dot11Elt):
            if p.ID == 3:
                try:
                    channel = ord(p.info)
                except:
                    pass
            elif p.ID == 48:
                sec.add("WPA2")
            elif p.ID == 61:
                if not channel:
                    channel = ord(p.info[-int(p.len):-int(p.len)+1])
            elif p.ID == 221 and p.info.startswith("\x00P\xf2\x01\x01\x00"):
                if "WPA2" not in sec:
                    sec.add("WPA")

            p = p.payload

        if not sec:
            if "privacy" in cap:
                sec.add("WEP")
            else:
                sec.add("OPEN")

        if "0050f204104a000110104400010210" in str(packet).encode("hex"):
            sec.add("WPS")

        try:
            oui = ((EUI(mac)).oui).registration().org
        except:
            oui = "<Unknown>"

        Global_Access_Points[source] = Access_Point(
            name,
            ":".join(sec),
            channel,
            mac,
            unicode(oui),
            get_rssi(packet[0].notdecoded))

        if mac == Global_Mac_Filter:
            Global_Mac_Filter_Channel = channel

    return

def handler_data(packet):
    global Global_Access_Points
    global Global_Clients

    address1 = packet.addr1
    address2 = packet.addr2
    address3 = packet.addr3

    if Global_Access_Points.has_key(address1):
        if Global_Clients.has_key(address2):

            if Global_Clients[address2].mbssid != address1:
                Global_Clients[address2].mssid = (address1)

            Global_Clients[address2].mnoise += 1
            Global_Clients[address2].msig = (get_rssi(packet.notdecoded))

        elif check_valid(address2):
            Global_Clients[address2] = Client(address2, address1, get_rssi(packet.notdecoded))
            Global_Clients[address2].mnoise += 1

            print(address1, address2, address3, packet.subtype, 1)

    elif Global_Access_Points.has_key(address2):
        if Global_Clients.has_key(address1):

            if Global_Clients[address1].mbssid != address2:
                Global_Clients[address1].mssid = (address2)

            Global_Clients[address1].mnoise += 1
            Global_Clients[address1].msig = (get_rssi(packet.notdecoded))

        elif check_valid(address1):
            Global_Clients[address1] = Client(address1, address2, get_rssi(packet.notdecoded))
            Global_Clients[address1].mnoise += 1

            print(address1, address2, address3, packet.subtype, 2)


    return

def handler_eap(packet):
    global Global_Access_Points
    global Global_Handshakes
    global Global_Recent_Key_Cap
    global Global_Handshake_Captures

    if packet.addr3 in Global_Handshakes and not Global_Access_Points[packet.addr3].mssid.startswith("<len: "):
        Global_Handshakes[packet.addr3].append(packet)
        Global_Access_Points[packet.addr3].meapols += 1

        folder_path = ("/root/pcaps/")
        filename = (str(Global_Access_Points[packet.addr3].mssid)+"_"+str(packet.addr3)[-5:].replace(":", "")+".pcap")

        if len(Global_Handshakes[packet.addr3]) >= 6:
            if not os.path.isfile(folder_path+filename):
                os.system("touch "+folder_path+filename)

            wrpcap(folder_path+filename, Global_Handshakes[packet.addr3], append=True)
            Global_Handshakes[packet.addr3] = []
            Global_Recent_Key_Cap = (" - [BOOPED: " + str(packet.addr3).upper() + "]")
            Global_Handshake_Captures += 1
    return

def handler_probereq(packet):
    global Global_Clients

    if Global_Clients.has_key(packet.addr2):
        Global_Clients[packet.addr2].msig = (get_rssi(packet.notdecoded))

    elif check_valid(packet.addr2):
        Global_Clients[packet.addr2] = Client(packet.addr2, "", get_rssi(packet.notdecoded))

    Global_Clients[packet.addr2].mnoise += 1

    return

def handler_proberes(packet):
    global Global_Access_Points
    global Global_Hidden_SSIDs
    global Global_Handshakes

    Global_Access_Points[packet.addr3].update_ssid(packet.info)
    Global_Hidden_SSIDs.remove(packet.addr3)
    Global_Handshakes[packet.addr3].append(packet)
    return

def get_rssi(decoded):
    rssi = -(256 - ord(decoded[-2:-1]))

    if int(rssi) not in xrange(-100, 0):
        return(-(256 - ord(decoded[-4:-3])))

    if rssi < -100:
        return -1
    return rssi

def channel_hopper(configuration):
    global Global_Channel_Hopper_Flag
    global Global_Mac_Filter_Channel

    interface = configuration.interface
    frequency = configuration.frequency

    if frequency == "2":
        __FREQS__ = {
            "2.412": 1,
            "2.417": 2,
            "2.422": 3,
            "2.427": 4,
            "2.432": 5,
            "2.437": 6,
            "2.442": 7,
            "2.447": 8,
            "2.452": 9,
            "2.457": 10,
            "2.462": 11
            }

        for channel in ["2.412", "2.437", "2.462"]:
            system("sudo iwconfig "+interface+" freq "+channel+"G")
            configuration.channel = __FREQS__[channel]
            sleep(5)

    elif frequency == "5":
        __FREQS__ = {
            "5.180": 36,
            "5.200": 40,
            "5.220": 44,
            "5.240": 48,
            "5.260": 52,
            "5.280": 56,
            "5.300": 60,
            "5.320": 64,
            "5.500": 100,
            "5.520": 104,
            "5.540": 108,
            "5.560": 112,
            "5.580": 116,
            "5.660": 132,
            "5.680": 136,
            "5.700": 140,
            "5.745": 149,
            "5.765": 153,
            "5.785": 157,
            "5.805": 161,
            "5.825": 165
        }

    while Global_Channel_Hopper_Flag == True:
        if Global_Mac_Filter_Channel != "":
            channel = __FREQS__.keys()[__FREQS__.values().index(Global_Mac_Filter_Channel)]
            system("sudo iwconfig "+interface+" freq "+channel+"G")
            configuration.channel = Global_Mac_Filter_Channel
            break

        channel = str(choice(__FREQS__.keys()))
        system("sudo iwconfig "+interface+" freq "+channel+"G")

        configuration.channel = __FREQS__[channel]
        sleep(3)
    return

def get_access_points(AP):
    global Global_Access_Points

    return [
        Global_Access_Points[AP].mmac,
        Global_Access_Points[AP].menc,
        Global_Access_Points[AP].mch,
        Global_Access_Points[AP].mven,
        Global_Access_Points[AP].msig,
        Global_Access_Points[AP].mbeacons,
        Global_Access_Points[AP].mssid
    ]

def get_clients():
    global Global_Access_Points

    clients = []
    for cl in Global_Clients:
        try:
            if len(Global_Access_Points[Global_Clients[cl].mbssid].mssid) > 0:
                clients.append([
                    Global_Clients[cl].mmac,
                    Global_Access_Points[Global_Clients[cl].mbssid].mmac,
                    str(Global_Clients[cl].mnoise),
                    str(Global_Clients[cl].msig),
                    Global_Access_Points[Global_Clients[cl].mbssid].mssid
                ])
        except:
            pass
    return clients

def get_un_clients():
    global Global_Access_Points
    global Global_Clients

    clients = []
    for cl in Global_Clients:
        try:
            clients.append([
                Global_Clients[cl].mmac,
                Global_Access_Points[Global_Clients[cl].mbssid].mmac,
                str(Global_Clients[cl].mnoise),
                str(Global_Clients[cl].msig),
                Global_Access_Points[Global_Clients[cl].mbssid].mssid
            ])
        except:
            clients.append([
                Global_Clients[cl].mmac,
                "",
                str(Global_Clients[cl].mnoise),
                str(Global_Clients[cl].msig),
                ""
            ])
    return clients

def printer_thread(configuration):
    global Global_Clients
    global Global_Access_Points
    global Global_Start_Time
    global Global_Recent_Key_Cap
    global Global_Print_Flag
    global Global_Handshake_Captures

    typetable = "simple"
    timeout = 1.5

    while Global_Print_Flag == True:
        wifis = list(map(get_access_points, Global_Access_Points))
        wifis.sort(key=lambda x: (x[6]))

        if configuration.unassociated == True:		# print all clients no matter what
            clients = get_un_clients()
        else:
            clients = get_clients()	     		# only print associated clients

        clients.sort(key=lambda x: (x[4]))

        time_elapsed = int(time() - Global_Start_Time)

        if time_elapsed < 60:
            printable_time = seconds = str(int(time_elapsed % 60))+" s"
        else:
            printable_time = str(int(time_elapsed / 60))+" m"

        system('clear')

        print(bcolors.ENDC+"[+] Time: [" + printable_time + "] Slithering: ["+str(configuration.channel)+"]" + Global_Recent_Key_Cap + " - ["+str(Global_Handshake_Captures)+"]")
        print("")
        print(tabulate(wifis, headers=["Mac Addr", "Enc", "Ch", "Vendor", "Sig", "Bea", "SSID"], tablefmt=typetable))
        print(bcolors.ENDC)
        print(tabulate(clients, headers=["Mac", "AP Mac", "Noise", "Sig", "AP SSID"], tablefmt=typetable))

        if timeout < 4:
            timeout += .05

        sleep(timeout)
    return

def sniff_packets(packet):
    global Global_Mac_Filter
    global Global_Ignore_Broadcast
    global Global_Hidden_SSIDs

    if (Global_Mac_Filter == None or (packet.addr1 == Global_Mac_Filter or packet.addr2 == Global_Mac_Filter)):

        if packet.type == 0:
            if packet.subtype == 4:
                handler_probereq(packet)

            elif packet.subtype == 5 and packet.addr3 in Global_Hidden_SSIDs:
                handler_proberes(packet)

            elif packet.subtype == 8:
                handler_beacon(packet)

        elif packet.type == 1:
            if packet.addr1 not in Global_Ignore_Broadcast and packet.addr2 and packet.addr2 not in Global_Ignore_Broadcast:
                # print(packet.addr1, packet.addr2, packet.subtype)
                handler_data(packet)

        elif packet.type == 2:
            if packet.addr1 not in Global_Ignore_Broadcast and packet.addr2 not in Global_Ignore_Broadcast:
                handler_data(packet)

            if packet.haslayer(EAPOL):
                handler_eap(packet)

    return

# MISC
def set_size(height, width):
    stdout.write("\x1b[8;{rows};{cols}t".format(rows=height, cols=width))
    return

def display_art():
    print(bcolors.OKBLUE+"""
    ____                   _____       _ ________
   / __ )____  ____  ____ / ___/____  (_) __/ __/
  / __  / __ \/ __ \/ __ \\\__ \/ __ \/ / /_/ /_
 / /_/ / /_/ / /_/ / /_/ /__/ / / / / / __/ __/
/_____/\____/\____/ .___/____/_/ /_/_/_/ /_/
                 /_/
    """)
    print(bcolors.HEADER+"     Codename: Horned Viper\r\n"+bcolors.BOLD)
    return

def check_valid(mac):
    global Global_Ignore_Broadcast
    global Global_Ignore_Multicast

    if mac in Global_Ignore_Broadcast:
        return False

    for item in Global_Ignore_Multicast:
        if mac.startswith(item):
            return False
    return True

def create_pcap_filepath():
    if not os.path.isdir("/root/pcaps"):
        os.system("mkdir /root/pcaps")
    return

def start_sniffer(configuration):
    sniff(iface=configuration.interface, prn=sniff_packets, store=0)
    return

# MAIN CONTROLLER
def int_main(configuration):
    global Global_Mac_Filter
    global Global_Print_Flag
    global Global_Channel_Hopper_Flag
    global Global_Access_Points
    global Global_Clients
    global Global_Start_Time

    Global_Mac_Filter = configuration.mac_filter

    def signal_handler(*args):
        Global_Print_Flag = False
        Global_Channel_Hopper_Flag  = False

        if configuration.report != None:
            wifis = list(map(get_Global_Access_Points, Global_Access_Points))

            clients = list(map(get_clients, Global_Clients))
            clients.sort(key=lambda x: x[4])

            configuration.report.write(tabulate(wifis, headers=["M", "E", "Ch", "V", "S", "B", "SS"], tablefmt="psql")+"\r\n")
            configuration.report.write(tabulate(clients, headers=["M", "AP M", "N", "S", "AP"], tablefmt="psql")+"\r\n")
            configuration.report.close()

        print(bcolors.OKGREEN+"\r [+] "+bcolors.ENDC+"Commit to Exit.")
        exit(0)
        return 0

    signal.signal(signal.SIGINT, signal_handler)

    if configuration.hop == True:
        Hopper_Thread = Thread(target=channel_hopper, args=[configuration])
        Hopper_Thread.daemon = True
        Hopper_Thread.start()
    else:
        os.system("iwconfig " + configuration.interface + " channel " + configuration.channel)

    Global_Start_Time = time()

    Sniffer_Thread = Thread(target=start_sniffer, args=[configuration])
    Sniffer_Thread.daemon = True
    Sniffer_Thread.start()

    create_pcap_filepath()
    set_size(30, 81)

    if configuration.printer == True:
        printer_thread(configuration)

    return 0

if __name__ == "__main__":
    display_art()

    configuration = Configuration()
    configuration.parse_args()

    int_main(configuration)
