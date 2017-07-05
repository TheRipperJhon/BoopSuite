#!/usr/bin/env python
# -*- coding: utf-8 -*-

__year__    = [2016, 2017];
__status__  = "Testing";
__contact__ = "jacobsin1996@gmail.com";

import argparse
import logging
import string

import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl

logging.getLogger("scapy.runtime").setLevel(logging.ERROR);

from tkinter import *
import tkMessageBox

from getpass import getuser
from netaddr import *
from scapy.contrib.wpa_eapol import WPA_key
from os import system, path, getuid, uname
from random import choice
from scapy.all import *
from sys import exit, stdout
from tabulate import tabulate
from threading import Thread
from time import sleep, time

class c:
    # A class library for the colors that will be used
    # by the program. Uses a converter for Tkinter.
    HEADER           = '#%02x%02x%02x' % (30, 144, 255);
    BACKGROUND       = '#%02x%02x%02x' % (255, 255, 255);
    BUTTON_COLOR     = '#%02x%02x%02x' % (242, 163, 189);
    TITLE_BACKGROUND = '#%02x%02x%02x' % (69, 79, 89);
    OPTION_MENU      = '#%02x%02x%02x' % (196, 173, 201);

class MainWindow:
    # An initializer for the tkinter window.
    # Will have:
        # Title bar with exit button.
        # Canvas on left side with wifis
        # Frame in middle with updatable info based on selection.
    # A settings menu?
    def __init__(self, master):
        # Initializes window and acts as main controller.
        # Calls other methods.
        self.master = master;

        master.configure(background=c.TITLE_BACKGROUND);
        master.geometry('%dx%d+%d+%d' % (760, 700, 100, 100));
        self.create_start();

        self.create_title_bar();
        self.create_options();
        self.create_body();
        self.create_info_window();
        self.create_canvas();

        # VARS
        self.ignore = [
            "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00",
            "01:80:c2:00:00:00", "01:00:5e", "01:80:c2",
            "33:33"];

        self.hidden = [];
        self.handshakes = {};

        self.aps = {};
        self.cls = {};

        return;

    def create_title_bar(self):
        # Creates title bar with exit button, Needs color scheme to be approved.
        # Clean up button with better text than "X"
        self.title_bar = Frame(
            self.master, bg=c.TITLE_BACKGROUND,
            bd=2
            );

        self.title = Label(
            self.title_bar, text="BoopSniff v1.0.0",
            fg=c.HEADER, bg=c.TITLE_BACKGROUND,
            font="Helvetica 16 bold"
            );

        self.title_bar.bind("<ButtonPress-1>", self.StartMove);
        self.title_bar.bind("<ButtonRelease-1>", self.StopMove);
        self.title_bar.bind("<B1-Motion>", self.OnMotion);

        self.close_button = Button(
            self.title_bar, bg=c.BUTTON_COLOR,
            text='X', highlightthickness = 0,
            bd = 0, relief=FLAT,
            command=self.master.destroy
            );

        self.title_bar.pack(fill=X, anchor="n");
        self.close_button.pack(side=RIGHT, padx=(0, 3));
        self.title.pack(side=LEFT, padx=(10,0));
        return;

    def create_options(self):
        self.options_frame = Frame(self.master, bg=c.TITLE_BACKGROUND, width=900, height=50);
        self.options_frame.pack(fill=BOTH);

        self.flag_frame = Frame(self.master, bg=c.TITLE_BACKGROUND, width=900, height=50);
        self.flag_frame.pack(fill=BOTH);

        interfaces = pyw.interfaces();

        self.inter_options   = [];
        self.freq_options    = [];
        self.channel_options = [];

        for interface in interfaces:
            try:
                if pyw.modeget(interface) == "monitor":
                    self.inter_options.append(interface);
            except:
                pass

        self.INTERFACE = StringVar();
        self.FREQUENCY = StringVar();
        self.CHANNEL   = StringVar();

        try:
            self.INTERFACE.set(self.inter_options[0]);

            interface = pyw.getcard(self.inter_options[0]);
            pinfo = pyw.phyinfo(interface)['bands'];
            self.freq_options = pinfo.keys();

            self.FREQUENCY.set(self.freq_options[0]);

            if self.FREQUENCY.get() == "2GHz":
                self.channel_options = ["all", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
            else:
                self.channel_options = ["all", 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161, 165];
            self.CHANNEL.set(self.channel_options[0]);

        except:
            print("No Valid Monitor Interfaces.");
            sys.exit(0);

        self.interface_label = Label(self.options_frame, text="Face: ", bg=c.TITLE_BACKGROUND, fg="white", font="14");
        self.interface_label.pack(padx=(25,0), pady=(15,0), anchor=NW, side=LEFT);

        self.interface_options = apply(OptionMenu, (self.options_frame, self.INTERFACE) + tuple(self.inter_options));
        self.interface_options.pack(padx=(0, 5), pady=(11, 0), anchor=NW, side=LEFT);

        self.frequency_label = Label(self.options_frame, text="Freq: ", bg=c.TITLE_BACKGROUND, fg="white", font="14");
        self.frequency_label.pack(padx=(7, 0), pady=(15,0), anchor=NW, side=LEFT);

        self.frequency_options = apply(OptionMenu, (self.options_frame, self.FREQUENCY) + tuple(self.freq_options));
        self.frequency_options.pack(padx=(0, 5), pady=(11, 0), anchor=NW, side=LEFT);

        self.channel_label = Label(self.options_frame, text="Ch: ", bg=c.TITLE_BACKGROUND, fg="white", font="14");
        self.channel_label.pack(padx=(7, 0), pady=(15,0), anchor=NW, side=LEFT);

        self.ch_options = apply(OptionMenu, (self.options_frame, self.CHANNEL) + tuple(self.channel_options));
        self.ch_options.pack(padx=(0, 5), pady=(11, 0), anchor=NW);

        self.INTERFACE.trace('w', self.update_freq_options);
        self.FREQUENCY.trace('w', self.update_channel_options);
        ########## FLAGS ################
        self.KILL = StringVar();
        self.UNASSOCIATED = StringVar();
        self.MACFILTER = StringVar();

        self.kill = Checkbutton(
            self.flag_frame, text="Kill blocking tasks",
            fg="white", selectcolor=c.TITLE_BACKGROUND,
            activeforeground="white", activebackground=c.TITLE_BACKGROUND,
            variable=self.KILL, highlightthickness = 0,
            bd = 0, relief=FLAT, font="10",
            bg=c.TITLE_BACKGROUND
            );
        self.kill.pack(padx=(25, 0), pady=(10, 0), anchor=W, side=LEFT);

        self.filter_label = Label(self.flag_frame, text="AP Filter: ", bg=c.TITLE_BACKGROUND, fg="white", font="14");
        self.filter_label.pack(padx=(12, 0), pady=(10, 0), anchor=W, side=LEFT);

        self.filter_entry = Entry(self.flag_frame, exportselection=0, state=DISABLED, takefocus=True, textvariable=self.MACFILTER);
        self.filter_entry.pack(padx=(5, 0), pady=(11, 0), anchor=W);
        self.filter_entry.config(state=NORMAL);
        return;

    def create_body(self):
        # Creates the frame for the wifi canvas and the updatable frame.
        self.body = Frame(self.master, bg=c.TITLE_BACKGROUND );

        self.wifi_side_bar = Frame(self.body, width=250, height=490, bg=c.TITLE_BACKGROUND );
        self.wifi_side_bar.pack(side=LEFT, padx=5);

        self.body.pack(side=LEFT, padx=5, pady=5 );
        return;

    def create_canvas(self):
        self.frame=Frame(self.wifi_side_bar, bg=c.HEADER);
        self.frame.pack();

        self.wifi_title = Label(self.frame, fg="black", text="Wifis: ", bg=c.HEADER);
        self.wifi_title.pack(padx=5);

        self.wifi_vbar=Scrollbar(self.frame,orient=VERTICAL);
        self.wifi_vbar.pack(side=RIGHT,fill=Y, expand=True);

        self.wifi_canvas=Canvas(
            self.frame, bg=c.TITLE_BACKGROUND,
            width=250, height=490,
            scrollregion=(0,0,0,500), yscrollcommand=self.wifi_vbar.set
            );

        self.wifi_inner_card = Frame(self.wifi_canvas, bg=c.TITLE_BACKGROUND);
        self.wifi_inner_card.pack(fill="both", expand="true");

        self.wifi_vbar.config(command=self.wifi_canvas.yview);

        self.wifi_vbar.config(command=self.wifi_canvas.yview);
        self.wifi_canvas.config(scrollregion=self.wifi_canvas.bbox("all"));

        self.wifi_canvas.pack(expand=True,fill=BOTH, pady=(5));
        self.wifi_canvas.create_window((0,0), window=self.wifi_inner_card, anchor='nw');
        ################################################################################
        self.frame=Frame(self.info_window, bg=c.HEADER);
        self.frame.pack();

        self.details_title = Label(self.frame, fg="black", text="Details: ", bg=c.HEADER);
        self.details_title.pack(padx=5);

        self.details_vbar=Scrollbar(self.frame,orient=VERTICAL);
        self.details_vbar.pack(side=RIGHT,fill=Y, expand=True);

        self.details_canvas=Canvas(
            self.frame, bg=c.TITLE_BACKGROUND,
            width=600, height=490,
            scrollregion=(0, 0, 0, 1000), yscrollcommand=self.details_vbar.set
            );

        self.details_inner_card = Frame(self.details_canvas, bg=c.TITLE_BACKGROUND);
        self.details_inner_card.pack(fill="both", expand="true");

        self.details_vbar.config(command=self.details_canvas.yview);

        self.details_vbar.config(command=self.details_canvas.yview);
        self.details_canvas.config(scrollregion=self.details_canvas.bbox("all"));

        self.details_canvas.pack(expand=True,fill=BOTH, pady=(5));
        self.details_canvas.create_window((0,0), window=self.details_inner_card, anchor='nw');

        self.ap_title = Label(self.details_inner_card, text="  SSID:", font=12, fg="white", bg=c.TITLE_BACKGROUND);
        self.ap_title.pack(anchor="w");

        self.ap_mac = Label(self.details_inner_card, text="  Mac:", font=12, fg="white", bg=c.TITLE_BACKGROUND);
        self.ap_mac.pack(anchor="w");

        self.ap_enc     = Label(self.details_inner_card, text="  Enc:", font=12, fg="white", bg=c.TITLE_BACKGROUND);
        self.ap_enc.pack(anchor="w");

        self.ap_wps     = Label(self.details_inner_card, text="  WPS:", font=12, fg="white", bg=c.TITLE_BACKGROUND);
        self.ap_wps.pack(anchor="w");

        self.ap_ch      = Label(self.details_inner_card, text="  Channel:", font=12, fg="white", bg=c.TITLE_BACKGROUND);
        self.ap_ch.pack(anchor="w");

        self.ap_ven     = Label(self.details_inner_card, text="  Vendor:", font=12, fg="white", bg=c.TITLE_BACKGROUND);
        self.ap_ven.pack(anchor="w");

        self.ap_sig     = Label(self.details_inner_card, text="  Signal:", font=12, fg="white", bg=c.TITLE_BACKGROUND);
        self.ap_sig.pack(anchor="w");

        self.ap_beacons = Label(self.details_inner_card, text="  Beacons:", font=12, fg="white", bg=c.TITLE_BACKGROUND);
        self.ap_beacons.pack(anchor="w");

        self.ap_booped = Label(self.details_inner_card, text="  Handshake Capped:", font=12, fg="white", bg=c.TITLE_BACKGROUND);
        self.ap_booped.pack(anchor="w");

        self.ap_clients = Label(self.details_inner_card, text="Clients: ", font=12, fg="white", bg=c.TITLE_BACKGROUND);
        self.ap_clients.pack(anchor="w", pady=(10,0));

        self.ap_clients_listbox = Listbox(self.details_inner_card, width=45, height=50, font=10)
        self.ap_clients_listbox.pack(anchor="w", fill=BOTH)

        return;

    def create_info_window(self):
        # Creates the updatable window.
        self.info_window = Frame(self.body, width=600, height=490);
        self.info_window.pack(side=LEFT, padx=5);
        return;

    def create_start(self):
        self.bottom_frame = Frame(self.master, width=900, bg=c.TITLE_BACKGROUND);
        self.bottom_frame.pack(side=BOTTOM, fill=BOTH);

        self.start_button = Button(self.bottom_frame, text="Start Scanning", command=self.start_sniffing);
        self.start_button.pack(side=RIGHT, padx=15, pady=(10, 15));
        return;

    def StartMove(self, event):
        self.x = event.x;
        self.y = event.y;
        return;

    def StopMove(self, event):
        self.x = None;
        self.y = None;
        return;

    def OnMotion(self,event):
        x = (event.x_root - self.x - self.master.winfo_rootx() + self.master.winfo_rootx());
        y = (event.y_root - self.y - self.master.winfo_rooty() + self.master.winfo_rooty());
        self.master.geometry("+%s+%s" % (x, y));
        return;

    def update_channel_options(self, *args):
        if str(self.FREQUENCY.get()) == "5GHz":
            self.channel_options = ["all", 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161, 165];
            self.CHANNEL.set(self.channel_options[0]);
        else:
            self.channel_options = ["all", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
            self.CHANNEL.set(self.channel_options[0]);

        menu = self.ch_options["menu"];
        menu.delete(0, "end");

        for string in self.channel_options:
            menu.add_command(
                label=string, command=lambda value=string: self.CHANNEL.set(value));
        return;

    def update_freq_options(self, *args):
        interface = pyw.getcard(self.INTERFACE.get());
        pinfo = pyw.phyinfo(interface)['bands'];

        self.freq_options = pinfo.keys();

        self.FREQUENCY.set(self.freq_options[0]);

        menu = self.frequency_options["menu"];
        menu.delete(0, "end");

        for string in self.freq_options:
            menu.add_command(
                label=string, command=lambda value=string: self.FREQUENCY.set(value));

        return;

    def add_wifi(self, ap_object):
        self.new_name = Button(
            self.wifi_inner_card,
            bg="white",
            width=37,
            anchor=W,
            text=(ap_object.mssid),
            font="10",
            command=lambda name=ap_object.mmac:self.enumerate_info(name)
            );
        self.new_name.pack(pady=2, fill=BOTH, anchor=NW, expand=1);
        self.wifi_canvas.config(scrollregion=(0, 0, 0, self.wifi_canvas.bbox("all")[3] + 50));
        return;

    def enumerate_info(self, mac):
        self.ap_title.config(text="  SSID:   "+self.aps[mac].mssid);
        self.ap_mac.config(text="  Mac:   "+self.aps[mac].mmac);
        self.ap_enc.config(text="  Enc:   "+self.aps[mac].menc);
        self.ap_wps.config(text="  WPS:   "+str(self.aps[mac].mwps));
        self.ap_ch.config(text="  Channel:   "+str(self.aps[mac].mch));
        self.ap_ven.config(text="  Vendor:   "+self.aps[mac].mven);
        self.ap_sig.config(text="  Signal:   "+str(self.aps[mac].msig));
        self.ap_beacons.config(text="  Beacons:   "+str(self.aps[mac].mbeacons));

        self.ap_booped.config(text="  Handshake Capped: "+str(self.aps[mac].mbooped));

        self.ap_clients_listbox.delete(0, END);

        for client in self.aps[mac].mclients:
            self.ap_clients_listbox.insert(END, "Mac: "+self.cls[client].mmac);
            self.ap_clients_listbox.insert(END, " \t Noise: "+str(self.cls[client].mnoise));
            self.ap_clients_listbox.insert(END, " \t Signal: "+str(self.cls[client].msig));
            self.ap_clients_listbox.insert(END, "");

        # Enumerate info in details pane. < ADD list of clients to AP.

    def start_sniffing(self):
        self.start_button.config(state=DISABLED);
        sniffer_thread = Thread(target=self.sniff_);
        sniffer_thread.daemon = True;
        sniffer_thread.start();
        return;

    def sniff_(self):
        if str(self.KILL.get()) == "1":
            tasklist = [
                "service avahi-daemon stop",
                "service network-manager stop",
                "pkill wpa_supplicant",
                "pkill dhclient"
            ];

            for item in tasklist:
                try:
                    os.system("sudo "+item);
                except:
                    pass;

        if str(self.CHANNEL.get()) == "all":
            Hopper_Thread = Thread(target=self.channel_hopper);
            Hopper_Thread.daemon = True;
            Hopper_Thread.start();
        else:
            os.system('iwconfig ' + self.INTERFACE.get() + ' channel ' + self.CHANNEL.get());

        try:
            self.FILTER = self.MACFILTER.get();
        except:
            self.FILTER = "";

        sniff(iface=self.INTERFACE.get(), prn=self.sniff_packets, store=0);
        return;

    def sniff_packets(self, packet):
        if self.FILTER == "" or (packet.addr1 == self.FILTER or packet.addr2 == self.FILTER):
            if packet.type == 0:
                if packet.subtype == 4:
                    self.handler_probereq(packet);

                elif packet.subtype == 5:
                    self.handler_proberes(packet);

                elif packet.subtype == 8:
                    self.handler_beacon(packet);

            elif packet.type == 2:
                if self.check_valid(packet.addr1) and self.check_valid(packet.addr2):
                    self.handler_data(packet);

        return;

    def check_valid(self, mac=None):
        if not mac:
            return False;

        else:
            for item in self.ignore:
                if mac.startswith(item):
                    return False;
        return True;

    def get_rssi(self, DECODED):
        rssi = -(256 - ord(DECODED[-2:-1]));

        if int(rssi) > 0 or int(rssi) < -100:
            rssi = -(256 - ord(DECODED[-4:-3]));

        if int(rssi) not in range(-100, 0):
            return "-1";

        return rssi;

    def channel_hopper(self):
        interface = self.INTERFACE.get();
        frequency   = self.FREQUENCY.get();

        if frequency == "2GHz":
            __FREQS__ = {
                '2.412': 1, '2.417': 2, '2.422': 3, '2.427': 4, '2.432': 5,
                '2.437': 6, '2.442': 7, '2.447': 8, '2.452': 9, '2.457': 10,
                '2.462': 11
                };

        elif frequency == "5GHz":
            __FREQS__ = {
                '5.180': 36, '5.200': 40, '5.220': 44, '5.240': 48,
                '5.260': 52, '5.280': 56, '5.300': 60, '5.320': 64,
                '5.500': 100, '5.520': 104, '5.540': 108, '5.560': 112,
                '5.580': 116, '5.660': 132, '5.680': 136, '5.700': 140,
                '5.745': 149, '5.765': 153, '5.785': 157, '5.805': 161,
                '5.825': 165
                };

        while True:
            channel = str(choice(__FREQS__.keys()));
            system('sudo iwconfig '+interface+' freq '+channel+"G");
            sleep(1.5);
        return;

    # FUNCTIONS
    def handler_beacon(self, packet):
        source = packet.addr2;

        if source in self.aps:
            self.aps[source].msig = self.get_rssi(packet.notdecoded);
            self.aps[source].mbeacons += 1;

        else:
            destination = packet.addr1;
            mac         = packet.addr3;
            self.handshakes[mac] = [];

            if u'\x00' in "".join([x if ord(x) < 128 else "" for x in packet[0].info]) or not packet[0].info:
                self.hidden.append(mac);
                name = "<len: "+str(len(packet.info))+">";
            else:
                name = "".join([x if ord(x) < 128 else "" for x in packet[0].info]);

            rssi = self.get_rssi(packet.notdecoded);

            p = packet[Dot11Elt];
            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                                    "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+');

            sec     = set();
            channel = "-";
            while isinstance(p, Dot11Elt):
                if p.ID == 3:
                    try:
                        channel = ord(p.info);
                    except:
                        pass
                elif p.ID == 48:
                    sec.add('WPA2');
                elif p.ID == 61:
                    if channel == "-":
                        channel = ord(p.info[-int(p.len):-int(p.len)+1]);
                elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
                    if "WPA2" in sec:
                        pass;
                    else:
                        sec.add('WPA');
                p = p.payload;

            if not sec:
                if 'privacy' in cap:
                    sec.add('WEP');
                else:
                    sec.add("OPEN");

            if '0050f204104a000110104400010210' in str(packet).encode('hex'):
                sec.add('WPS');

            try:
                oui = ((EUI(mac)).oui).registration().org;
            except:
                oui = "Unknown";

            self.aps[source] = Access_Point(name, ':'.join(sec), channel, mac, unicode(oui), rssi, packet);
            self.add_wifi(self.aps[source]);
        return

    def handler_data(self, packet):
        a1 = packet.addr1;
        a2 = packet.addr2;

        rssi = self.get_rssi(packet.notdecoded);

        if a1 in self.aps:
            if self.cls.has_key(a2):
                if self.cls[a2].mbssid != a1:
                    try:
                        self.aps[self.cls[a2].mbssid].mclients.discard(a1);
                    except:
                        pass;
                    self.cls[a2].mssid = (a1);
                    self.aps[a1].mclients.add(a2);

                self.cls[a2].mnoise += 1;
                self.cls[a2].msig = rssi;

            elif self.check_valid(a2):
                self.cls[a2] = Client(a2, a1, rssi);
                self.aps[a1].mclients.add(a2);
                self.cls[a2].mnoise += 1;
                # ADD CLIENT

        elif a2 in self.aps:
            if self.cls.has_key(a1):
                if self.cls[a1].mbssid != a2:
                    try:
                        self.aps[self.cls[a1].mbssid].mclients.discard(a2);
                    except:
                        pass
                    self.cls[a1].mssid = (a2);
                    self.aps[a2].mclients.add(a1);

                self.cls[a1].mnoise += 1;
                self.cls[a1].msig = rssi;

            elif self.check_valid(a1):
                self.cls[a1] = Client(a1, a2, rssi);
                self.aps[a2].mclients.add(a1);
                self.cls[a1].mnoise += 1;
                # ADD CLIENT

        if packet.haslayer(WPA_key):
            if packet.addr3 not in self.aps:
                return;

            if self.aps[packet.addr3].mbooped == True:
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
                    folder_path = ("/root/pcaps/");
                    filename = ("{0}_{1}.pcap").format(self.aps[packet.addr3].mssid.encode('utf-8'), packet.addr3[-5:].replace(":", ""));

                    wrpcap(folder_path+filename, self.aps[packet.addr3].packets);

                    self.aps[packet.addr3].mbooped = True;

        return;

    def handler_probereq(self, packet):
        rssi = self.get_rssi(packet.notdecoded);

        if self.cls.has_key(packet.addr2):
            self.cls[packet.addr2].msig = rssi;
            self.cls[packet.addr2].mnoise += 1;

        elif self.check_valid(packet.addr2):
            self.cls[packet.addr2] = Client(packet.addr2, '', rssi);
            self.cls[packet.addr2].mnoise += 1;

            # ADD CLIENT
        return;

    def handler_proberes(self, packet):
        if (packet.addr3 in self.hidden):
            self.aps[packet.addr3].mssid = packet.info;
            self.hidden.remove(packet.addr3);
            self.aps[packet.addr3].packets.append(packet);
        return;

class Access_Point:
    # Access point class for wifis.
    def __init__(self, ssid, enc, ch, mac, ven, sig, packet):
        self.mssid = str(ssid);
        self.menc     = enc;
        self.mch      = str(ch);
        self.mmac     = mac;
        self.mven     = ven;
        self.msig     = sig;
        self.mbeacons = 1;
        if "WPS" in enc:
            self.mwps = True;
        else:
            self.mwps = False;

        self.mbooped = False;
        self.frame2 = None;
        self.frame3 = None;
        self.frame4 = None;
        self.replay_counter = None;
        self.packets = [packet];

        self.mclients = set();
        return;

class Client:
    # Client class for devices connected to wifis.
    def __init__(self, mac, bssid, rssi):
        self.mmac   = mac;
        self.mbssid = bssid;
        self.msig = rssi;

        self.mnoise = 0;
        return;

def check_root():
    # Checks for correct permissions/
    if getuid() != 0:
        exit();
    return;

def check_op():
    # Checks for correct Operating System.
    if uname()[0].startswith("Linux") and not 'Darwin' not in uname()[0]:
        exit();
    return;

def create_pcap_filepath():
    if not os.path.isdir("/root/pcaps"):
        os.system("mkdir /root/pcaps");
    return;

def main():
    # Creates window and calls program.
    check_op();
    check_root();
    create_pcap_filepath();

    root = Tk();
    root.wm_attributes('-type', 'splash');
    Global_My_Gui = MainWindow(root);
    root.mainloop();

main();
