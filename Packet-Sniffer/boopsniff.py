#!/usr/bin/env python
# -*- coding: utf-8 -*-

__year__    = [2017];
__status__  = "Development";
__contact__ = "jacobsin1996@gmail.com";

# Imports
import signal
import argparse
import logging

import pyric.pyw as pyw;

logging.getLogger("scapy.runtime").setLevel(logging.ERROR);

from netaddr import *

from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key
from random import choice
from threading import Thread
from time import sleep, time
from os import path, getuid, uname, makedirs
from sys import exit, stdout, stderr

conf.verb = 0;
# Tell scapy to do less "talking"

# Global Thread Check
gAlive = True;

gStartTime = time();

################################################################################
#
#           Classes
#
################################################################################

class c:
    H  = "\033[95m"; # Magenta
    B  = "\033[94m"; # Blue
    W  = "\033[93m"; # Yellow
    G  = "\033[92m"; # Green
    F  = "\033[91m"; # Red
    E  = "\033[0m";  # Clear
    Bo = "\033[1m";  # Bold

# Class for Sniffer Objects
class Sniffer:

    # Init method for Sniffer Objects
    def __init__(self, args):
        self.mInterface    = args['interface'];     # String
        self.mFrequency    = args['freq'];          # Int
        self.mChannel      = args['channel'];       # Int
        self.mKill         = args['kill'];          # Bool
        self.mTarget       = args['target'];        # String
        self.mMAC          = args['mac'];           # String
        self.mUnassociated = args['unassociated'];  # Bool
        self.mDiagnose     = args['diagnose'];      # Bool

        self.mCapMessage    = "";                   # String

        self.mFilterChannel = None;                 # Int
        self.mPackets       = 0;                    # Int

        self.mIgnore = [
            "ff:ff:ff:ff:ff:ff",                    # Broadcast
            "00:00:00:00:00:00",                    # Multicast
            "01:80:c2:00:00:00",                    # Multicast
            "01:00:5e",                             # Multicast
            "01:80:c2",                             # Multicast
            "33:33"                                 # Multicast
        ];

        self.mHidden = [];                          # List

        self.mAPs  = {};                            # Dict
        self.mCls  = {};                            # Dict
        self.mUCls = {};                            # Dict

        if self.mChannel:
            self.mHop = True;                       # Bool

        else:
            self.mHop = False;                      # Bool

        return;

    # Method for handling the cards channel hopping.
    def hopper(self):
        global gAlive

        # Create pyric card object.
        interface = pyw.getcard(self.mInterface);

        # Set channel hopping timeout.
        timeout = 1.0;

        # Get channels if frequency is 2.4 ghz
        if self.mFrequency == 2:
            freqs = [
                1, 2, 3,
                4, 5, 6,
                7, 8, 9,
                10, 11
            ];

        # Get channels if frequency is 5.8 ghz
        elif self.mFrequency == 5:
            freqs = [
                36, 40, 44,
                48, 52, 56,
                60, 64, 100,
                104, 108, 112,
                116, 132, 136,
                140, 149, 153,
                157, 161, 165
            ];

        # Repeat until program exits.
        while gAlive:

            try:

                # If target not found yet.
                if not self.mFilterChannel:

                    # Choose channel at random.
                    channel = choice(freqs);

                    # Set channel
                    pyw.chset(interface, channel, None);

                    # Set channel variable
                    self.mChannel = channel;

                # If target found.
                else:

                    # Set Channel
                    pyw.chset(interface, self.mFilterChannel, None);

                    # Set channel variable
                    self.mChannel = self.mFilterChannel;

                    # Set cap messages
                    self.mCapMessage = "[:Hopper Thread Exited:]"

                    # Break out of loop and return.
                    break;

                if self.mDiagnose:
                    prints("Channel Set to: {0}".format(self.mChannel));

                # Increase timeout every iteration.
                if timeout < 3:

                    # Increment timeout.
                    timeout += .05;

                # Sleep program for timeout.
                sleep(timeout);

            except AttributeError:
                printf("Thread-1 Error: Most likely interpreter shutdown. Disregard.")

        # Exit hopper.
        return;

    # C-extension map method for retrieving access points
    def getAccessPoints(self, AP):
        return [
            self.mAPs[AP].mMAC,                  # Mac
            self.mAPs[AP].mEnc,                  # Encryption
            self.mAPs[AP].mCh,                   # Channel
            self.mAPs[AP].mVen,                  # Vendor
            self.mAPs[AP].mSig,                  # Signal
            self.mAPs[AP].mBeacons,              # Beacons
            self.mAPs[AP].mSSID[:22]             # SSID
        ];


    # C-extension map method for retrieving Clients
    def getClients(self, cl):
        return [
            self.mCls[cl].mMAC,                  # Mac
            self.mCls[cl].mBSSID,                # BSSID
            self.mCls[cl].mNoise,                # Noise
            self.mCls[cl].mSig,                  # Signal
            self.mCls[cl].mESSID                 # ESSID
        ];


    # C-extension map method for retrieving unassociated clients
    def getUClients(self, cl):
        return [
            self.mUCls[cl].mMAC,               # Mac
            "",                                # NULL
            self.mUCls[cl].mNoise,             # Noise
            self.mUCls[cl].mSig,               # Signal
            ""                                 # NULL
        ];


    # Printer method for discovered clients and APS
    def printer(self):
        global gAlive

        # Create a time object to measure elapsed time.
        start_time = gStartTime;

        # Timeout for printer
        timeout = 1.1;

        # Message to display at top. < Captured handshake.
        buffer_message = "";

        # Loop until program exit.
        while gAlive:

            # Get all access points in a list of lists.
            wifis = list(map(self.getAccessPoints, self.mAPs));

            # Sort access points on 6th key index.
            wifis.sort(key=lambda x: (x[6]));

            # Get clients
            clients = list(map(self.getClients, self.mCls));

            # Check if user wants unassociated clients displayed.
            if self.mUnassociated:

                # Get unassociated clients
                clients += list(map(self.getUClients, self.mUCls));

            # Sort clients on key index 4
            clients.sort(key=lambda x: (x[4]));

            # Create new time object based on time subtract start time
            time_elapsed = int(time() - start_time);

            # Perform math to get elapsed time.
            hours = (time_elapsed / 3600);
            mins  = (time_elapsed % 3600) / 60;
            secs  = (time_elapsed % 60);

            # Create time messages.
            if hours > 0:
                printable_time = "%d h %d m %d s" % (hours, mins, secs);

            elif mins > 0:
                printable_time = "%d m %d s" % (mins, secs);

            else:
                printable_time = "%d s" % secs;


            # Clear the console.
            clearConsole();

            # Write top line to terminal.
            stdout.write(
                "{3}[{6}]{0}{2} T: {3}[{4}] {0}C: {3}[{5}] {7}\n\n".format(
                    c.G,
                    c.E,
                    c.Bo,
                    c.W,
                    printable_time,
                    self.mChannel,
                    self.mPackets,
                    self.mCapMessage
                )
            );

            # Print first header line in red.
            stdout.write(
                "{0}{1}{2}{3}{4}{5}{6}\n".format(
                    c.F+"Mac Addr".ljust(19, " "),
                    "Enc".ljust(10, " "),
                    "Ch".ljust(4, " "),
                    "Vendor".ljust(9, " "),
                    "Sig".ljust(5, " "),
                    "Beacons".ljust(8, " "),
                    "SSID"+c.E
                )
            );

            for item in wifis:
                # Print access points
                sys.stdout.write(
                    " {0}{1}{2:<4}{3}{4:<5}{5:<8}{6}\n".format(
                        item[0].ljust(19, " "),
                        item[1].ljust(10, " "),
                        item[2],
                        item[3].ljust(9, " "),
                        item[4],
                        item[5],
                        item[6].encode('utf-8')
                    )
                );

            # Print second header in red.
            stdout.write(
                "\n{0}{1}{2}{3}{4}\n".format(
                    c.F+"Mac".ljust(19, " "),
                    "AP Mac".ljust(19, " "),
                    "Noise".ljust(7, " "),
                    "Sig".ljust(5, " "),
                    "AP SSID"+c.E
                )
            );

            for item in clients:
                # Print clients.
                stdout.write(
                    " {0}{1}{2:<7}{3:<5}{4}\n".format(
                        item[0].ljust(19, " "),
                        item[1].ljust(19, " "),
                        item[2],
                        item[3],
                        item[4].encode('utf-8')
                    )
                );

            # If timeout is less than max then increment timeout.
            if timeout < 4.5:

                # increment timeout.
                timeout += .05;

            # Timeout for other thread execution.
            sleep(timeout);

        # If exits.
        return;


    # Method for checking if a mac address is valid.
    def checkValidMac(self, mac=None):

        # if mac == None
        if not mac:
            # Not a valid mac.
            return False;

        else:
            # if mac is in list of ignore addresses.
            for item in self.mIgnore:

                # Check is mac is == to any in ignore list.
                if mac.startswith(item):

                    # Mac is invalid.
                    return False;

        # Mac is valid.
        return True;


    # Method for parsing packets.
    def sniff_packets(self, packet):

        # Increment total sniffed packets.
        self.mPackets += 1;

        # check if packet is mgmt
        if packet.type == 0:

            # Check if packet is probe request
            if packet.subtype == 4:
                self.handlerProbeRequest(packet);

            # Check if packet is probe response
            elif packet.subtype == 5 and packet.addr3 in self.mHidden:
                self.handlerProbeResponse(packet);

            # check if packet is beacon.
            elif packet.subtype == 8 and self.checkValidMac(packet.addr3):
                self.handlerBeacon(packet);

        # Check if packet is ctrl
        elif packet.type == 1:
            self.handlerCtrl(packet);

        # check if packet is data
        elif packet.type == 2:
            self.handlerData(packet);
        return;


    # Method for starting the actual sniffing of the program.
    def run(self):

        # Check if a target is set.
        if self.mTarget:

            self.mCapMessage = "[:Filter Set:]"

            sniff(
                iface=self.mInterface,
                filter="ether host "+self.mTarget.lower(),
                prn=self.sniff_packets,
                store=0
            );


        # If no target is set.
        else:

            sniff(
                iface=self.mInterface,
                prn=self.sniff_packets,
                store=0
            );


        return;


    # Handler for probe requests
    def handlerProbeRequest(self, packet):

        # if client in unassociated.
        if packet.addr2 in self.mUCls:

            # Update signal and noise
            self.mUCls[packet.addr2].mSig = (getRssi(packet.notdecoded));
            self.mUCls[packet.addr2] + 1;

        # If client not seen.
        elif self.checkValidMac(packet.addr2):

            # Create unassociated client object.
            self.mUCls[packet.addr2] = Client(packet.addr2, "", getRssi(packet.notdecoded), "");

            if self.mDiagnose:
                prints("New Un Client: {0}".format(packet.addr2));

        return;


    # Handler probe responses
    def handlerProbeResponse(self, packet):
        '''
            This method only runs on previouly identified hidden networks.
        '''

        # update ssid info
        self.mAPs[packet.addr3].mSSID = packet.info;

        # Remove from hidden list
        self.mHidden.remove(packet.addr3);

        # Append this packet as beacon packet for later cracking.
        self.mAPs[packet.addr3].packets.append(packet);

        if self.mDiagnose:
            prints("Hidden Network Uncovered: {0}".format(packet.info));

        return;


    # Handler for beacons
    def handlerBeacon(self, packet):

        # If AP already seen.
        if packet.addr2 in self.mAPs:

            # Update signal strength
            self.mAPs[packet.addr2].mSig = (getRssi(packet.notdecoded));
            # Add a packet.
            self.mAPs[packet.addr2] + 1;

        # If beacon is a new AP.
        else:

            # Get name of Access Point.
            if packet.info and u"\x00" not in "".join([x if ord(x) < 128 else "" for x in packet.info]):

                try:
                    # Encode it in case the asshole admin puts a damn emoji in the SSID.
                    name = packet.info.decode("utf-8"); # Cause dickheads exist.
                except:
                    name = unicode(packet.info, errors='ignore')

            # If name is hidden.
            else:

                # Add packet to
                self.mHidden.append(packet.addr3);
                # Default name for hidden network
                name = (("< len: {0} >").format(len(packet.info)));

            # Grab first Dot11Elt layer
            p = packet[Dot11Elt];

            # Need to figure out what this line does because honestly i have no clue.
            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
            "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split("+");

            # create a set to store all security properties. <- So no values get repeated.
            sec = set();

            # set channel to 0 in case its not found. <- not likely but possible.
            channel = 0;

            # Loop over layers in packet.
            while isinstance(p, Dot11Elt):

                if p.ID == 3:

                    try:
                        channel = ord(p.info);
                    except TypeError:
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

                # Increment payload
                p = p.payload;

            if channel == 0:
                channel = self.mChannel;

            # Check if channel matches sniffing channel.
            if self.mHop and channel != self.mChannel:
                # If not discard. < Might need to change this.
                return;

            # If encryption != WPA/WPA2
            if not sec:

                # Check for wep
                if "privacy" in cap:
                    sec.add("WEP");

                # Must be an open network.
                else:
                    sec.add("OPEN");

            # Check for WPS
            if "0050f204104a000110104400010210" in str(packet).encode("hex"):
                # Used to check: 0050f204104a000110104400010210
                sec.add("WPS"); # 204104a000110104400010210 < is absolutely necessary

            # Test if oui in mac address
            try:
                oui = ((EUI(packet.addr3)).oui).registration().org;

            # if not in mac database.
            except NotRegisteredError:
                oui = "< NA >";

            # Create AP object.
            self.mAPs[packet.addr2] = Access_Point(
                name,
                ":".join(sec),
                channel,
                packet.addr3,
                unicode(oui),
                getRssi(packet.notdecoded),
                packet
                );

            # If target found set filter and cancel hopper thread.
            if packet.addr3 == self.mTarget:

                # Set Filter Channel to active.
                self.mFilterChannel = channel;

            if self.mDiagnose:
                prints("New Network: {0}".format(name));

        return;


    # Handler for ctrl packets
    def handlerCtrl(self, packet):

        # If AP has been seen
        if packet.addr1 in self.mAPs:

            # Update signal and return.
            self.mAPs[packet.addr1].mSig = (getRssi(packet.notdecoded));

        return;


    # Handler for data packets.
    def handlerData(self, packet):

        # if ap has been seen
        if packet.addr1 in self.mAPs:

            # if client has been seen
            if packet.addr2 in self.mCls:

                # if client changed access points
                if self.mCls[packet.addr2].mBSSID != packet.addr1:

                    # Update access point
                    self.mCls[packet.addr2].mSSID = (packet.addr1);

                    if self.mDiagnose:
                        prints("Client changed networks: {0}".format(packet.addr2));

                # Update signal and noise
                self.mCls[packet.addr2] + 1;
                self.mCls[packet.addr2].mSig = (getRssi(packet.notdecoded));

            # If client was previously unassociated
            elif packet.addr2 in self.mUCls:

                # Create a new client object
                self.mCls[packet.addr2] = Client(packet.addr2, packet.addr1, getRssi(packet.notdecoded), self.mAPs[packet.addr1].mSSID);

                # Destroy previous client object
                del self.mUCls[packet.addr2];

                if self.mDiagnose:
                    prints("New Client: {0}".format(packet.addr2));

            # if client previously unseen
            elif self.checkValidMac(packet.addr2):

                # Create new client object
                self.mCls[packet.addr2] = Client(packet.addr2, packet.addr1, getRssi(packet.notdecoded), self.mAPs[packet.addr1].mSSID);

                if self.mDiagnose:
                    prints("New Client: {0}".format(packet.addr1));

        # If access point seen
        elif packet.addr2 in self.mAPs:

            # If client seen.
            if packet.addr1 in self.mCls:

                # if client changed access points
                if self.mCls[packet.addr1].mBSSID != packet.addr2:

                    self.mCls[packet.addr1].mSSID = (packet.addr2);

                    if self.mDiagnose:
                        prints("New Un Client: {0}".format(packet.addr1));

                # Update noise and signal
                self.mCls[packet.addr1] + 1;
                self.mCls[packet.addr1].mSig = (getRssi(packet.notdecoded));

            # if client was previously unassociated
            elif packet.addr1 in self.mUCls:

                # Create new client and delete old object
                self.mCls[packet.addr1] = Client(packet.addr1, packet.addr2, getRssi(packet.notdecoded), self.mAPs[packet.addr2].mSSID);

                del self.mUCls[packet.addr1];

                if self.mDiagnose:
                    prints("New Client: {0}".format(packet.addr1));

            # Check if mac is valid before creating new object.
            elif self.checkValidMac(packet.addr1):

                # Create new client object
                self.mCls[packet.addr1] = Client(packet.addr1, packet.addr2, getRssi(packet.notdecoded), self.mAPs[packet.addr2].mSSID);

                if self.mDiagnose:
                    prints("New Un Client: {0}".format(packet.addr1));

        # Check if packet is part of a wpa handshake
        if packet.haslayer(WPA_key):

            # If mac has not been seen.
            if packet.addr3 not in self.mAPs:
                return;

            # If mac has been seen
            else:

                # Get wpa layer
                layer = packet.getlayer(WPA_key);

                if (packet.FCfield & 1):
                    # From DS = 0, To DS = 1
                    STA = packet.addr2;

                elif (packet.FCfield & 2):
                    # From DS = 1, To DS = 0
                    STA = packet.addr1;

                # This info may be unnecessary.
                key_info = layer.key_info;
                wpa_key_length = layer.wpa_key_length;
                replay_counter = layer.replay_counter;

                WPA_KEY_INFO_INSTALL = 64;
                WPA_KEY_INFO_ACK = 128;
                WPA_KEY_INFO_MIC = 256;

                # check for frame 2
                if (key_info & WPA_KEY_INFO_MIC) and ((key_info & WPA_KEY_INFO_ACK == 0) and (key_info & WPA_KEY_INFO_INSTALL == 0) and (wpa_key_length > 0)):

                    if self.mDiagnose:
                        prints("Key part 1 found: {0}".format(packet.addr3));

                    self.mAPs[packet.addr3].frame2 = 1;
                    self.mAPs[packet.addr3].packets.append(packet[0]);

                # check for frame 3
                elif (key_info & WPA_KEY_INFO_MIC) and ((key_info & WPA_KEY_INFO_ACK) and (key_info & WPA_KEY_INFO_INSTALL)):

                    if self.mDiagnose:
                        prints("Key part 2 found: {0}".format(packet.addr3));

                    self.mAPs[packet.addr3].frame3 = 1;
                    self.mAPs[packet.addr3].replay_counter = replay_counter;
                    self.mAPs[packet.addr3].packets.append(packet[0]);

                    # check for frame 4
                elif (key_info & WPA_KEY_INFO_MIC) and ((key_info & WPA_KEY_INFO_ACK == 0) and (key_info & WPA_KEY_INFO_INSTALL == 0) and self.mAPs[packet.addr3].replay_counter == replay_counter):

                    if self.mDiagnose:
                        prints("Key part 3 found: {0}".format(packet.addr3));

                    self.mAPs[packet.addr3].frame4 = 1;
                    self.mAPs[packet.addr3].packets.append(packet[0]);

                if (self.mAPs[packet.addr3].frame2 and self.mAPs[packet.addr3].frame3 and self.mAPs[packet.addr3].frame4):

                    if self.mDiagnose:
                        prints("Whole key found: {0}".format(packet.addr3));

                    folder_path = ("pcaps/");
                    filename = ("{0}_{1}.pcap").format(self.mAPs[packet.addr3].mSSID.encode('utf-8'), packet.addr3[-5:].replace(":", ""));

                    wrpcap(folder_path+filename, self.mAPs[packet.addr3].packets);

                    self.mCapMessage = ("Capped: "+packet.addr3);
        return;


# Class for Access Point objects
class Access_Point:

    def __init__(self, ssid, enc, ch, mac, ven, sig, packet):
        self.mSSID = ssid;              # String
        self.mEnc  = enc;               # String
        self.mCh   = ch;                # int
        self.mMAC  = mac;               # String
        self.mVen  = ven[:8];           # String
        self.mSig  = sig;               # Int

        self.mBeacons = 1;              # Int

        self.frame2 = None;            # Bool
        self.frame3 = None;            # Bool
        self.frame4 = None;            # Bool
        self.replay_counter = None;     # Int
        self.packets = [packet];           # List
        return;

    def __add__(self, value=1):
        self.mBeacons += value;
        return;

class Client:

    def __init__(self, mac, bssid, rssi, essid):
        self.mMAC   = mac;
        self.mBSSID = bssid;
        self.mSig   = rssi;
        self.mNoise = 1;
        self.mESSID  = essid;
        return;

    def __add__(self, value=1):
        self.mNoise += value;
        return;


################################################################################
#
#           Functions
#
################################################################################

# get signal strength from non-decoded slice of data in packet.
def getRssi(decoded):

    # for 2.4 ghz packets most rssi appears here
    rssi = int(-(256 - ord(decoded[-2:-1])));

    # Else it can also appear here
    if rssi not in xrange(-100, 0):
        rssi = (-(256 - ord(decoded[-4:-3])));

    # If rssi value is invalid.
    if rssi < -100:
        return -1;

    # If rssi is valid.
    return rssi;

# Use ascii code to clear terminal.
def clearConsole():
    stdout.write("\x1b[2J\x1b[H");
    return;

# Print success
def prints(*args, **kwargs):

    stdout.write("[{4:<3}] -> {0}[{1}+{2}]{3}: ".format(c.G, c.E, c.G, c.E, int(time() - gStartTime)));
    stdout.write(*args);
    stdout.write("\n");

    return;


# Print failure
def printf(*args, **kwargs):

    stderr.write("[  {4:<3}] -> {0}[{1}!{2}]{3}: ".format(c.F, c.E, c.F, c.E, int(time() - gStartTime)));
    stderr.write(*args);
    stderr.write("\n");

    return;


# Create directory for pcaps
def createPcapDirectory():
    # Check if pcap directory already exists
    if not path.exists("pcaps"):

        # If not create directory.
        makedirs("pcaps");
        prints("Created Pcap Directory.")

    return 0;


# Handler for ctrl+c Event.
def signal_handler(*args):
    global gAlive

    # Set global flag to false to kill daemon threads.
    gAlive = False;

    print("\r[+] Commit to exit.")

    # Sleep to allow one final execution of threads.
    sleep(3.5);

    # Kill Program.
    exit(0);


# Checks for proper OS and UID
def startupChecks():

    # Check for root.
    if getuid() != 0:
        printf("User is not Root.");
        exit();

    # Check for proper OS.
    if uname()[0].startswith("Linux") and not "Darwin" not in uname():
        printf("Wrong OS.");
        printf("Remember Macs are for Assholes")
        exit();

    return;

# Function to gather all arguments passed by CLI
def parseArgs():

    # Instantiate parser object
    parser = argparse.ArgumentParser();

    # Arg for version number.
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version="{0}".format("Version: 1.0.0"));

    # Arg for interface.
    parser.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="interface",
        help="select an interface",
        required=True);

    # Arg for frequency.
    parser.add_argument(
        "-f",
        "--frequency",
        action="store",
        default=2,
        dest="freq",
        type=int,
        help="select a frequency (2/5)",
        choices=[2, 5]);

    # Arg for channel.
    parser.add_argument(
        "-c",
        "--channel",
        action="store",
        default=None,
        dest="channel",
        type=int,
        help="select a channel");

    # Arg for custom mac address.
    parser.add_argument(
        "-m",
        "--mac",
        action="store",
        default=None,
        dest="mac",
        help="Custom Mac Address");

    # Flag for kill commands.
    parser.add_argument(
        "-k",
        "--kill",
        action="store_true",
        dest="kill",
        help="sudo kill interfering processes.");

    # Flag for unassociated clients.
    parser.add_argument(
        "-u",
        "--unassociated",
        action="store_true",
        dest="unassociated",
        help="Whether to show unassociated clients.");

    # Arg for target to sniff.
    parser.add_argument(
        "-t",
        "--target",
        action="store",
        default=None,
        dest="target",
        help="Command for targeting a specific network.");

    # Arg for diagnostic mode.
    parser.add_argument(
        "-D",
        "--Diagnose",
        action="store_true",
        default=False,
        dest="diagnose",
        help="Switch for diagnostic mode.");

    # return dict of args.
    return vars(parser.parse_args());


def main():
    '''
        The main controller for the program.

        Instantiates all threads and processes.
    '''

    # list of all channels in 5ghz spectrum
    fspectrum = [
        36, 40, 44, 48, 52, 56, 60, 64,
        100, 104, 108, 112, 116, 132, 136,
        140, 149, 153, 157, 161, 165
    ];

    # Get all arguments from terminal
    results = parseArgs();

    # Check if interface exists.
    if results['interface'] not in pyw.interfaces():
        printf("Interface is not valid.");
        exit(1);

    # Check if interface in monitor mode.
    if pyw.modeget(results['interface']) != "monitor":
        printf("Non monitor interface selected.");
        exit(1);

    # Check if channel specified
    if results['channel']:

        # Check if channel is valid.
        if results['freq'] == 2 and results['channel'] not in range(1, 12):
            printf("Channel selected is invalid");
            exit(1);

        # Check if channel is valid.
        elif results['freq'] == 5 and results['channel'] not in fspectrum:
            printf("Channel selected is invalid");
            exit(1);

    # Check if mac is of valid length.
    if results['mac'] and len(results['mac']) != 17:
        printf("Invalid mac option selected.");
        exit(1);

    # Check if task kill flag is set.
    if results['kill']:
        killBlockingTasks();

    # Check if target mac is of valid length.
    if results['target'] and len(results['target']) != 17:
        printf("Invalid Target Selected.");
        exit(1);

    # Set ctrl+c interceptor.
    signal.signal(signal.SIGINT, signal_handler);

    # Check values at start up: OS and UID.
    startupChecks();

    # Create directory for captured handshakes.
    createPcapDirectory();

    # Create Sniffer object
    sniffer = Sniffer(results);

    # If channel isnt set then create channel hopping thread.
    if not results['channel']:

        # Create hopper thread.
        hop_thread = Thread(target=sniffer.hopper);

        # Set thread object as a daemon.
        hop_thread.daemon = True;

        # Start thread.
        hop_thread.start()

    # If channel is set.
    else:

        # set channel and continue.
        pyw.chset(pyw.getcard(results['interface']), results['channel'], None);

    if not results['diagnose']:
        printer_thread = Thread(target=sniffer.printer);
        printer_thread.daemon = True;
        printer_thread.start();

    try:
        sniffer.run();
    except AttributeError:
        printf("AttributeError: Disregard This Error.");

main();
