#!/usr/bin/env python
# -*- coding: utf-8 -*-

__year__    = [2016, 2017];
__status__  = "Stable";
__contact__ = "jacobsin1996@gmail.com";

# Imports
import argparse
import logging
import signal

import pyric.pyw as pyw

logging.getLogger("scapy.runtime").setLevel(logging.ERROR);

from netaddr import *
from os import system, path, getuid, uname
from random import choice
from scapy.contrib.wpa_eapol import WPA_key
from scapy.all import *
from sys import exit, stdout, stderr, setcheckinterval
from threading import Thread
from time import sleep, time

conf.verb = 0;
setcheckinterval = 1000;

class c:
    H  = "\033[95m"; # Magenta
    B  = "\033[94m"; # Blue
    W  = "\033[93m"; # Yellow
    G  = "\033[92m"; # Green
    F  = "\033[91m"; # Red
    E  = "\033[0m";  # Clear
    Bo = "\033[1m";  # Bold


class Access_Point:
    def __init__(self, ssid, enc, ch, mac, ven, sig, packet):
        self.mssid = ssid;
        self.menc  = enc;
        self.mch   = ch;
        self.mmac  = mac;
        self.mven  = ven[:8];
        self.msig  = sig;

        self.mbeacons = 1;

        self.frame2 = None;
        self.frame3 = None;
        self.frame4 = None;
        self.replay_counter = None;
        self.packets = [packet];
        self.found   = False;
        return;


class Client:
    def __init__(self, mac, bssid, rssi, essid):
        self.mmac   = mac;
        self.mbssid = bssid;
        self.msig   = rssi;
        self.mnoise = 1;
        self.essid  = essid;
        return;


class Sniffer_Configuration:
    def __init__(self, interface, channel, hop, freq, kill, mfilter, unassociated):
        self.mface    = interface;
        self.mchannel = channel;
        self.mfreq    = freq;
        self.mkill    = kill;
        self.mfilter  = mfilter;
        self.hop      = hop;
        self.mfilter_channel = None;
        self.unassociated = unassociated;
        self.cap_message  = "";

        self.ignore = [
            "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00",
            "01:80:c2:00:00:00", "01:00:5e", "01:80:c2",
            "33:33"];

        self.hidden = [];
        self.valid_channels = [];

        self.aps = {};
        self.cls = {};
        self.un_cls = {};

        return;


    def run(self):
        sniff(iface=self.mface, prn=self.sniff_packets, store=0);
        return;


    def check_valid(self, mac=None):
        if not mac:
            return False;

        else:
            for item in self.ignore:
                if mac.startswith(item):
                    return False;
        return True;


    def hopper(self):
        interface = pyw.getcard(self.mface);
        timeout = 1.0;

        if self.mfreq == 2:
            __FREQS__ = [
                1, 2, 3, 4, 5, 6,
                7, 8, 9, 10, 11
                ];

        elif self.mfreq == 5:
            __FREQS__ = [
                36, 40, 44, 48, 52, 56,
                60, 64, 100, 104, 108, 112,
                116, 132, 136, 140, 149, 153,
                157, 161, 165
            ];

        while True:

            if not self.mfilter_channel:
                channel = choice(__FREQS__);
                pyw.chset(interface, channel, None);
                self.mchannel = channel;

            else:
                channel = self.mfilter_channel;
                pyw.chset(interface, channel, None);
                self.mchannel = self.mfilter_channel;
                break;

            while timeout < 3:
                timeout += .05;
            sleep(timeout);
        return;


    def get_access_points(self, AP):
        return [
            self.aps[AP].mmac,
            self.aps[AP].menc,
            self.aps[AP].mch,
            self.aps[AP].mven,
            self.aps[AP].msig,
            self.aps[AP].mbeacons,
            self.aps[AP].mssid[:22]
        ];


    def get_clients(self, cl):
        return [
            self.cls[cl].mmac,
            self.cls[cl].mbssid,
            self.cls[cl].mnoise,
            self.cls[cl].msig,
            self.cls[cl].essid
        ];


    def get_un_clients(self, cl):
        return [
            self.un_cls[cl].mmac,
            "",
            self.un_cls[cl].mnoise,
            self.un_cls[cl].msig,
            ""
        ];


    def printer(self):
        start_time = time();
        timeout = 1.1;
        buffer_message = "";

        while True:
            wifis = list(map(self.get_access_points, self.aps));
            wifis.sort(key=lambda x: (x[6]));

            clients = list(map(self.get_clients, self.cls));

            if self.unassociated == True:		# print all clients no matter what
                clients += list(map(self.get_un_clients, self.un_cls));

            clients.sort(key=lambda x: (x[4]));

            time_elapsed = int(time() - start_time);

            hours = time_elapsed / 3600;
            mins = (time_elapsed % 3600) / 60;
            secs = time_elapsed % 60;

            if hours > 0:
                printable_time = "%d h %d m %d s" % (hours, mins, secs);

            elif mins > 0:
                printable_time = "%d m %d s" % (mins, secs);

            else:
                printable_time = "%d s" % secs;

            stderr.write("\x1b[2J\x1b[H");

            sys.stdout.write("{0}[+] {1}Time: {2}[{3}{4}{5}] {6}Slithering: {7}[{8}{9}{10}] {11}{12} {13}\n".format(c.G, c.E, c.B, c.W, printable_time, c.B, c.E, c.B, c.W, self.mchannel, c.B, c.E, self.cap_message, buffer_message));

            sys.stdout.write( "\r\n{0}{1}{2}{3}{4}{5}{6}\n".format(c.F+"Mac Addr".ljust(19, " "), "Enc".ljust(10, " "), "Ch".ljust(4, " "), "Vendor".ljust(9, " "), "Sig".ljust(5, " "), "Beacons".ljust(8, " "), "SSID"+c.E) );
            for item in wifis:
                sys.stdout.write( " {0}{1}{2:<4}{3}{4:<5}{5:<8}{6}\n".format(item[0].ljust(19, " "), item[1].ljust(10, " "), item[2], item[3].ljust(9, " "), item[4], item[5], item[6].encode('utf-8') ));

            sys.stdout.write("\n{0}{1}{2}{3}{4}\n".format(c.F+"Mac".ljust(19, " "), "AP Mac".ljust(19, " "), "Noise".ljust(7, " "), "Sig".ljust(5, " "), "AP SSID"+c.E) );

            for item in clients:
                sys.stdout.write( " {0}{1}{2:<7}{3:<5}{4}\n".format(item[0].ljust(19, " "), item[1].ljust(19, " "), item[2], item[3], item[4].encode('utf-8')) );

            if timeout < 4.5:
                timeout += .05;

            sleep(timeout);
        return;


    def get_rssi(self, decoded):
        rssi = int(-(256 - ord(decoded[-2:-1])));

        if rssi not in xrange(-100, 0):
            rssi = (-(256 - ord(decoded[-4:-3])));

        if rssi < -100:
            return -1;
        return rssi;


    def handler_proberequest(self, packet):
        if packet.addr2 in self.un_cls:
            self.un_cls[packet.addr2].msig = (self.get_rssi(packet.notdecoded));
            self.un_cls[packet.addr2].mnoise += 1;

        elif self.check_valid(packet.addr2):
            self.un_cls[packet.addr2] = Client(packet.addr2, "", self.get_rssi(packet.notdecoded), "");

        return;


    def handler_proberesponse(self, packet):
        self.aps[packet.addr3].mssid = packet.info;
        self.hidden.remove(packet.addr3);
        self.aps[packet.addr3].packets.append(packet);

        return;


    def handler_beacon(self, packet):
        if packet.addr2 in self.aps:
            self.aps[packet.addr2].msig = (self.get_rssi(packet.notdecoded));
            self.aps[packet.addr2].mbeacons += 1;

        else:
            if packet.info and u"\x00" not in "".join([x if ord(x) < 128 else "" for x in packet.info]):
                name = packet.info.decode("utf-8");
            else:
                self.hidden.append(packet.addr3);
                name = (("< len: {0} >").format(len(packet.info)));

            p = packet[Dot11Elt];
            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
            "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split("+");

            sec = set();
            channel = "";

            while isinstance(p, Dot11Elt):
                if p.ID == 3:
                    try:
                        channel = ord(p.info);
                    except:
                        pass;
                elif p.ID == 48:
                    if "WPA" in sec:
                        sec.remove("WPA");
                    sec.add("WPA2");
                elif p.ID == 61:
                    if channel == "":
                        channel = ord(p.info[-int(p.len):-int(p.len)+1]);
                elif p.ID == 221 and p.info.startswith("\x00P\xf2\x01\x01\x00"):
                    if "WPA2" not in sec:
                        sec.add("WPA");

                p = p.payload;

            if self.hop == False and channel != self.mchannel:
                return;

            if not sec:
                if "privacy" in cap:
                    sec.add("WEP");
                else:
                    sec.add("OPEN");

            if "0050f204104a000110104400010210" in str(packet).encode("hex"):
                sec.add("WPS"); #204104a000110104400010210 < May not be necessary...

            try:
                oui = ((EUI(packet.addr3)).oui).registration().org;
            except:
                oui = "< NA >";

            self.aps[packet.addr2] = Access_Point(
                name,
                ":".join(sec),
                channel,
                packet.addr3,
                unicode(oui),
                self.get_rssi(packet.notdecoded),
                packet
                );

            if packet.addr3 == self.mfilter:
                self.mfilter_channel = channel;

            return;


    def handler_ctrl(self, packet):
        if packet.addr1 in self.aps:
            self.aps[packet.addr1].msig = (self.get_rssi(packet.notdecoded));
        return;


    def handler_data(self, packet):
        if packet.addr1 in self.aps:
            if packet.addr2 in self.cls:

                if self.cls[packet.addr2].mbssid != packet.addr1:
                    self.cls[packet.addr2].mssid = (packet.addr1);

                self.cls[packet.addr2].mnoise += 1;
                self.cls[packet.addr2].msig = (self.get_rssi(packet.notdecoded));

            elif packet.addr2 in self.un_cls:
                self.cls[packet.addr2] = Client(packet.addr2, packet.addr1, self.get_rssi(packet.notdecoded), self.aps[packet.addr1].mssid);
                del self.un_cls[packet.addr2]

            elif self.check_valid(packet.addr2):
                self.cls[packet.addr2] = Client(packet.addr2, packet.addr1, self.get_rssi(packet.notdecoded), self.aps[packet.addr1].mssid);
                self.cls[packet.addr2].mnoise += 1;

        elif packet.addr2 in self.aps:
            if packet.addr1 in self.cls:

                if self.cls[packet.addr1].mbssid != packet.addr2:
                    self.cls[packet.addr1].mssid = (packet.addr2);

                self.cls[packet.addr1].mnoise += 1;
                self.cls[packet.addr1].msig = (self.get_rssi(packet.notdecoded));

            elif packet.addr1 in self.un_cls:
                self.cls[packet.addr1] = Client(packet.addr1, packet.addr2, self.get_rssi(packet.notdecoded), self.aps[packet.addr2].mssid);
                del self.un_cls[packet.addr1];

            elif self.check_valid(packet.addr1):
                self.cls[packet.addr1] = Client(packet.addr1, packet.addr2, self.get_rssi(packet.notdecoded), self.aps[packet.addr2].mssid);
                self.cls[packet.addr1].mnoise += 1;

        if packet.haslayer(WPA_key):
            if packet.addr3 not in self.aps:
                return;

            if self.aps[packet.addr3].found == True:
                return;

            else:
                layer = packet.getlayer(WPA_key);

                if (packet.FCfield & 1):
                        # From DS = 0, To DS = 1
                    STA = packet.addr2;
                elif (packet.FCfield & 2):
                        # From DS = 1, To DS = 0
                    STA = packet.addr1;
                else:
                    return;

                key_info = layer.key_info;
                wpa_key_length = layer.wpa_key_length;
                replay_counter = layer.replay_counter;
                WPA_KEY_INFO_INSTALL = 64;
                WPA_KEY_INFO_ACK = 128;
                WPA_KEY_INFO_MIC = 256;
                    # check for frame 2
                if ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK == 0) and (key_info & WPA_KEY_INFO_INSTALL == 0) and (wpa_key_length > 0)):
                    self.aps[packet.addr3].frame2 = 1;
                    self.aps[packet.addr3].packets.append(packet[0]);
                    # check for frame 3
                elif ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK) and (key_info & WPA_KEY_INFO_INSTALL)):
                    self.aps[packet.addr3].frame3 = 1;
                    self.aps[packet.addr3].replay_counter = replay_counter;
                    self.aps[packet.addr3].packets.append(packet[0]);
                    # check for frame 4
                elif ((key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK == 0) and (key_info & WPA_KEY_INFO_INSTALL == 0) and self.aps[packet.addr3].replay_counter == replay_counter):
                    self.aps[packet.addr3].frame4 = 1;
                    self.aps[packet.addr3].packets.append(packet[0]);

                if (self.aps[packet.addr3].frame2 and self.aps[packet.addr3].frame3 and self.aps[packet.addr3].frame4):
                    folder_path = ("pcaps/");
                    filename = ("{0}_{1}.pcap").format(self.aps[packet.addr3].mssid.encode('utf-8'), packet.addr3[-5:].replace(":", ""));

                    wrpcap(folder_path+filename, self.aps[packet.addr3].packets);

                    self.aps[packet.addr3].found = True;
                    self.cap_message = (" - [Booped: %s%s%s]" % (c.F, packet.addr3, c.E));


    def sniff_packets(self, packet):
        if (self.mfilter == None or (packet.addr1 == self.mfilter or packet.addr2 == self.mfilter)):

            if packet.type == 0:
                if packet.subtype == 4:
                    self.handler_proberequest(packet);

                elif packet.subtype == 5 and packet.addr3 in self.hidden:
                    self.handler_proberesponse(packet);

                elif packet.subtype == 8 and self.check_valid(packet.addr3):
                    self.handler_beacon(packet);

            elif packet.type == 1:
                self.handler_ctrl(packet);

            elif packet.type == 2:
                self.handler_data(packet);
        return;


def startup_checks():
    if getuid() != 0:
        sys.stderr(c.F+" [-] User is not Root.");
        exit();

    if uname()[0].startswith("Linux") and not "Darwin" not in uname():
        sys.stderr(c.F+" [-] Wrong OS.");
        exit();
    return;


def parse_args():
    parser = argparse.ArgumentParser();

    parser.add_argument(
        '--version',
        action='version',
        version="{0}{1}".format(c.G, "Version: 1.0.0"));

    parser.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="interface",
        help="select an interface",
        required=True);

    parser.add_argument(
        "-f",
        "--frequency",
        action="store",
        default=2,
        dest="freq",
        type=int,
        help="select a frequency (2/5)",
        choices=[2, 5]);

    parser.add_argument(
        "-c",
        "--channel",
        action="store",
        default=None,
        dest="channel",
        type=int,
        help="select a channel");

    parser.add_argument(
        "-k",
        "--kill",
        action="store_true",
        dest="kill",
        help="sudo kill interfering processes.");

    parser.add_argument(
        "-u",
        "--unassociated",
        action="store_true",
        dest="unassociated",
        help="Whether to show unassociated clients.");

    parser.add_argument(
        "-a",
        "--accesspoint",
        action="store",
        default=None,
        dest="access_mac",
        help="Command for a specific mac addr.");

    results = parser.parse_args();

    interface = results.interface;
    channel   = results.channel;
    frequency = results.freq;
    kill      = results.kill;
    mfilter   = results.access_mac;
    unassociated = results.unassociated;

    if interface not in pyw.interfaces() or  pyw.modeget(interface) != "monitor":
        print(c.F + " [-] Non Monitor card selected.");
        exit(0);


    if channel == None:

        if frequency == 2:
            hop = True;

        elif frequency == 5:
            hop = True;

        else:
            print(c.F+" [-] Channel Setting incorrect.");
            exit(0);


    elif channel != None:

        if frequency == 2 and channel in xrange(1, 12):
            hop = False;

        elif frequency == "5" and channel in [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161, 165]:
            hop = False;

        else:
            print(c.F+" [-] Channel Setting incorrect."+c.E);
            exit(0);

    if kill != False:
        commandlist = [
            "service avahi-daemon stop",
            "service network-manager stop",
            "pkill wpa_supplicant", "pkill dhclient"
            ];

        for item in commandlist:
            try:
                system("sudo %s" % (item));
            except:
                pass

    return [interface, channel, hop, frequency, kill, mfilter, unassociated];


def main():
    os.system("mkdir pcaps/");
    os.system("chmod 1777 pcaps/");

    def signal_handler(*args):
        print(c.G+"\r [+] "+c.E+"Commit to Exit.");
        exit(0);
        return;

    signal.signal(signal.SIGINT, signal_handler);

    startup_checks();
    args = parse_args();

    Sniffer = Sniffer_Configuration(args[0], args[1], args[2], args[3], args[4], args[5], args[6]);

    if args[2] == True:
        hop_thread = Thread(target=Sniffer.hopper);
        hop_thread.daemon = True;
        hop_thread.start()

    printer_thread = Thread(target=Sniffer.printer);
    printer_thread.daemon = True;
    printer_thread.start()

    Sniffer.run();
    return;


if __name__ == "__main__":
    main();
