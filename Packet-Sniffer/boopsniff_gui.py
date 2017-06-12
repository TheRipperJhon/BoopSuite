#!/usr/bin/env python

__year__    = [2016, 2017]
__status__  = "Testing"
__contact__ = "jacobsin1996@gmail.com"

import argparse
import logging
import string

import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from tkinter import *
import tkMessageBox

from getpass import getuser
from netaddr import *
from os import system, path, getuid, uname
from random import choice
from scapy.all import *
from sys import exit, stdout
from tabulate import tabulate
from threading import Thread
from time import sleep, time


# GLOBALS
Global_Access_Points = {} # MAC, AP OBJECT
Global_Clients = {} # MAC, CLIENT OBJECT

Global_Hidden_SSIDs = [] # Non-broadcasting ssid mac addresses.
Global_Ignore_Broadcast = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"] # Broadcast addresses.
Global_IGNORE_MULTICAST = ["01:00:", "01:80:c2", "33:33"]

Global_Flag = True # Signal controller for program.

Global_Handshakes = {} # NETWORKS, EAPOLS
Global_Mac_Filter     = None
Global_Recent_Key_Cap = ""
Global_Start_Time = ""
Global_Handshake_Captures = 0

Global_My_Gui = ""


# CLASSES
class c:
    HEADER           = '#%02x%02x%02x' % (30, 144, 255)
    BACKGROUND       = '#%02x%02x%02x' % (255, 255, 255)
    BUTTON_COLOR     = '#%02x%02x%02x' % (242, 163, 189)
    TITLE_BACKGROUND = '#%02x%02x%02x' % (69,79,89)
    OPTION_MENU      = '#%02x%02x%02x' % (196, 173, 201)


class Configuration:
    def __init__(self):
        self.check_root()
        self.check_op()

        self.__REPORT__ = False
        self.__PRINT__  = True
        self.__HOP__    = False
        self.__KILL__   = None
        self.__FREQ__   = "2"
        self.__FACE__   = None
        self.__UN__     = False
        self.__CC__     = None
        return

    def check_root(self):
        if getuid() != 0:
            exit()

        return

    def check_op(self):
        if uname()[0].startswith("Linux") and not 'Darwin' not in uname()[0]:
            exit()

        return


class Access_Point:
    def __init__(self, ssid, enc, ch, mac, ven, sig):
        self.mssid = str(ssid)[:20]

        if "WPA2" in enc and "WPA" in enc:
            self.menc  = "WPA2"
            if "WPS" in enc:
                self.menc += ":WPS"
        else:
            self.menc = enc
        self.mch      = str(ch)
        self.mmac     = mac
        self.mven     = ven[:8]
        self.msig     = sig
        self.mbeacons = 1
        self.meapols  = 0
        self.mfound   = "F"
        return

    def update_sig(self, sig):
        self.msig = sig
        return

    def update_ssid(self, ssid):
        self.mssid = ssid
        return

    def add_eapol(self):
        self.meapols += 1
        if self.mfound != "T":
            if self.meapols > 4:
                self.mfound = "T"
        else:
            pass
        return


class Client:
    def __init__(self, mac, bssid, rssi):
        self.mmac   = mac
        self.mbssid = bssid
        self.msig = rssi

        self.mnoise = 0
        return

    def update_network(self, bssid):
        self.mbssid = bssid
        return


class MainWindow:
    def __init__(self, master, config):
        global configuration
        configuration = config
        self.master = master
        master.configure(background=c.BACKGROUND)
        master.geometry('%dx%d+%d+%d' % (500, 900, 100, 100))
        self.create_title_bar(master)
        self.create_menu(master)
        self.create_flags(master)
        self.create_canvas(master)
        self.create_start(master)
        master.after(5000, self.update_canvases)

    def create_title_bar(self, master):
        self.title_bar = Frame( master, bg=c.TITLE_BACKGROUND, bd=2 )

        self.title = Label( self.title_bar, text="BoopSniff", fg=c.HEADER, bg=c.TITLE_BACKGROUND, font="Helvetica 16 bold" )

        self.title_bar.bind("<ButtonPress-1>", self.StartMove)
        self.title_bar.bind("<ButtonRelease-1>", self.StopMove)
        self.title_bar.bind("<B1-Motion>", self.OnMotion)

        self.close_button = Button(self.title_bar, bg=c.BUTTON_COLOR, text='X', highlightthickness = 0, bd = 0, relief=FLAT, command=master.destroy)

        self.title_bar.pack(fill=X, anchor="n")
        self.close_button.pack(side=RIGHT, padx=(0, 3))
        self.title.pack(side=LEFT, padx=(10,0))
        return 0

    def create_menu(self, master):
        interfaces = pyw.interfaces()

        self.inter_options   = []
        self.freq_options    = []
        self.channel_options = []

        for interface in interfaces:
            try:
                if pyw.modeget(interface) == "monitor":
                    self.inter_options.append(interface)
            except:
                pass

        self.INTERFACE = StringVar()
        self.FREQUENCY = StringVar()
        self.CHANNEL   = StringVar()

        try:
            self.INTERFACE.set(self.inter_options[0])

            interface = pyw.getcard(self.inter_options[0])
            pinfo = pyw.phyinfo(interface)['bands']
            self.freq_options = pinfo.keys()

            self.FREQUENCY.set(self.freq_options[0])
            if self.FREQUENCY.get() == "2GHz":
                self.channel_options = ["all", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
            else:
                self.channel_options = ["all", 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161, 165]
            self.CHANNEL.set(self.channel_options[0])

        except:
            print("No Valid Monitor Interfaces.")
            sys.exit(0)

        self.header_frame = Frame(master, height=50, bg=c.BACKGROUND)
        self.header_frame.pack(fill=X)

        self.interface_label = Label(self.header_frame, text="Face: ", bg=c.BACKGROUND, fg="black", font="14")
        self.interface_label.pack(padx=(15,0), pady=(10,0), anchor=NW, side=LEFT)

        self.interface_options = apply(OptionMenu, (self.header_frame, self.INTERFACE) + tuple(self.inter_options))
        self.interface_options.pack(padx=(5, 0), pady=(7, 0), anchor=NW, side=LEFT)

        self.frequency_label = Label(self.header_frame, text="Freq: ", bg=c.BACKGROUND, fg="black", font="14")
        self.frequency_label.pack(padx=(5,0), pady=(10,0), anchor=NW, side=LEFT)

        self.frequency_options = apply(OptionMenu, (self.header_frame, self.FREQUENCY) + tuple(self.freq_options))
        self.frequency_options.pack(padx=(5, 0), pady=(7, 0), anchor=NW, side=LEFT)

        self.channel_label = Label(self.header_frame, text="Ch: ", bg=c.BACKGROUND, fg="black", font="14")
        self.channel_label.pack(padx=(5,0), pady=(10,0), anchor=NW, side=LEFT)

        self.ch_options = apply(OptionMenu, (self.header_frame, self.CHANNEL) + tuple(self.channel_options))
        self.ch_options.pack(padx=(5, 0), pady=(7, 0), anchor=NW)

        self.INTERFACE.trace('w', self.update_freq_options)
        self.FREQUENCY.trace('w', self.update_channel_options)
        return

    def create_flags(self, master):
        self.KILL = StringVar()
        self.UNASSOCIATED = StringVar()
        self.Global_Mac_Filter = StringVar()

        self.subhead_frame = Frame(master, height=8, bg=c.BACKGROUND)
        self.subhead_frame.pack(fill=X)

        self.kill = Checkbutton(self.subhead_frame, text="Kill blocking tasks", fg="black", selectcolor=c.BACKGROUND, activeforeground="black", activebackground=c.BACKGROUND, variable=self.KILL, highlightthickness = 0, bd = 0, relief=FLAT, font="10", bg=c.BACKGROUND)
        self.kill.pack(padx=(30, 0), pady=(10, 0), anchor=NW, side=LEFT)

        self.subhead2_frame = Frame(master, height=8, bg=c.BACKGROUND)
        self.subhead2_frame.pack(fill=X)

        self.filter_label = Label(self.subhead2_frame, text="AP Filter: ", bg=c.BACKGROUND, fg="black", font="14")
        self.filter_label.pack(padx=(20, 0), pady=(5, 0), anchor=NW, side=LEFT)

        self.filter_entry = Entry(self.subhead2_frame, exportselection=0, state=DISABLED, takefocus=True, textvariable=self.Global_Mac_Filter)
        self.filter_entry.pack(padx=(5, 0), pady=(8, 0), anchor=NW, side=LEFT)
        self.filter_entry.config(state=NORMAL)

        return

    def create_canvas(self, master):
        self.frame=Frame(master, bg=c.HEADER)
        self.frame.pack(pady=(10, 0))

        self.wifi_title = Label(self.frame, fg="black", text="APS: ", bg=c.HEADER)
        self.wifi_title.pack(padx=5)

        self.wifi_vbar=Scrollbar(self.frame,orient=VERTICAL)
        self.wifi_vbar.pack(side=RIGHT,fill=Y, expand=True)

        self.wifi_canvas=Canvas(self.frame,bg=c.BACKGROUND,width=400,height=300, scrollregion=(0,0,0,400), yscrollcommand=self.wifi_vbar.set)

        self.wifi_inner_card = Frame(self.wifi_canvas, bg=c.BACKGROUND)
        self.wifi_inner_card.pack(fill="both", expand="true")

        self.wifi_vbar.config(command=self.wifi_canvas.yview)

        self.wifi_vbar.config(command=self.wifi_canvas.yview)
        self.wifi_canvas.config(scrollregion=self.wifi_canvas.bbox("all"))

        self.wifi_canvas.pack(expand=True,fill=BOTH, pady=(5))
        self.wifi_canvas.create_window((0,0), window=self.wifi_inner_card, anchor='nw')

        ##########################################################################

        self.frame2=Frame(master, bg=c.HEADER)
        self.frame2.pack(pady=(10, 0))

        self.client_title = Label(self.frame2, fg="black", text="Clients: ", bg=c.HEADER)
        self.client_title.pack(padx=5)

        self.client_vbar=Scrollbar(self.frame2,orient=VERTICAL)
        self.client_vbar.pack(side=RIGHT,fill=Y, expand=True)

        self.client_canvas=Canvas(self.frame2,bg=c.BACKGROUND,width=400,height=300, scrollregion=(0,0,0,400), yscrollcommand=self.client_vbar.set)

        self.client_inner_card = Frame(self.client_canvas, bg=c.BACKGROUND)
        self.client_inner_card.pack(fill="both", expand="true")

        self.client_vbar.config(command=self.client_canvas.yview)


        self.client_vbar.config(command=self.client_canvas.yview)
        self.client_canvas.config(scrollregion=self.client_canvas.bbox("all"))

        self.client_canvas.pack(expand=True,fill=BOTH)
        self.client_canvas.create_window((0,0), window=self.client_inner_card, anchor='nw')

    def update_canvases(self):
        self.wifi_canvas.update()

        self.client_canvas.update()

        self.master.after(5000, self.update_canvases)

    def start_scanning(self):
        configuration.__Global_Mac_Filter__ = str(self.Global_Mac_Filter.get())
        configuration.__KILL__   = str(self.KILL.get())
        configuration.__FREQ__   = str(self.FREQUENCY.get())[:1]
        configuration.__FACE__   = str(self.INTERFACE.get())
        configuration.__UN__     = str(self.UNASSOCIATED.get())

        if len(configuration.__Global_Mac_Filter__) > 5:
            Global_Mac_Filter = configuration.__Global_Mac_Filter__

        if str(self.CHANNEL.get()) == "all":
            configuration.__HOP__ = True
            Hopper_Thread = Thread(target=channel_hopper, args=[configuration])
            Hopper_Thread.daemon = True
            Hopper_Thread.start()
        else:
            configuration.__HOP__ = True
            os.system('iwconfig ' + configuration.__FACE__ + ' channel ' + self.CHANNEL.get())

        if str(configuration.__KILL__) == "1":
            tasklist = [
                        "service avahi-daemon stop",
                        "service network-manager stop",
                        "pkill wpa_supplicant",
                        "pkill dhclient"
                        ]

            for item in tasklist:
                try:
                    os.system("sudo "+item)
                except:
                    pass

        Sniffer_Thread = Thread(target=self.thread_start_sniffer, args=[configuration])
        Sniffer_Thread.daemon = True
        Sniffer_Thread.start()

        return

    def thread_start_sniffer(self, configuration):
        sniff(iface=configuration.__FACE__, prn=sniff_packets, store=0)
        return

    def add_wifi(self, ap_object):
        try:
            self.new_name = Button(
                self.wifi_inner_card,
                bg="white",
                width=37,
                anchor=W,
                text=(ap_object.mssid),
                font="10",
                command=lambda name=ap_object.mmac:self.print_info(name, "AP")
                )
            self.new_name.pack(pady=2, fill=BOTH, anchor=NW, expand=1)

            self.wifi_canvas.config(scrollregion=(0, 0, 0, self.wifi_canvas.bbox("all")[3] + 50))
        except:
            pass

    def add_client(self, cl_object):
        try:
            self.new_name = Button(
                self.client_inner_card,
                bg="white",
                width=37,
                anchor=W,
                text=(Global_Access_Points[cl_object.mbssid].mssid+" :: "+cl_object.mmac),
                font="10",
                command=lambda name=cl_object.mmac:self.print_info(name, "client")
                )
            self.new_name.pack(pady=2, fill=BOTH, anchor=NW, expand=1)

            self.wifi_canvas.config(scrollregion=(0, 0, 0, self.client_canvas.bbox("all")[3] + 50))
        except:
            pass

    def print_info(self, object_name, object_type):
        if object_type == "AP":
            tkMessageBox.showinfo(Global_Access_Points[object_name].mssid,
                ( "Mac address: " + Global_Access_Points[object_name].mmac +
                "\nEncryption: " + Global_Access_Points[object_name].menc +
                "\nChannel: " + Global_Access_Points[object_name].mch +
                "\nVendor: " + Global_Access_Points[object_name].mven +
                "\nSignal strength: " + str(Global_Access_Points[object_name].msig) +
                "\nBeacons: " + str(Global_Access_Points[object_name].mbeacons))
                )
        else:
            tkMessageBox.showinfo("Client Info",
                ("Mac address: "+Global_Clients[object_name].mmac+
                "\nAccess Point Mac: "+Global_Access_Points[Global_Clients[object_name].mbssid].mmac+
                "\nNoise: "+str(Global_Clients[object_name].mnoise)+
                "\nSignal Strength: "+str(Global_Clients[object_name].msig)+
                "\nAccess Point Name: "+Global_Access_Points[Global_Clients[object_name].mbssid].mssid)
                )
        print(object_name)

    def create_start(self, master):
        self.start_button = Button(self.subhead2_frame, text="Start Scanning", command=self.start_scanning)
        self.start_button.pack(pady=(8, 0))

    def StartMove(self, event):
        self.x = event.x
        self.y = event.y

    def StopMove(self, event):
        self.x = None
        self.y = None

    def OnMotion(self,event):
        x = (event.x_root - self.x - self.master.winfo_rootx() + self.master.winfo_rootx())
        y = (event.y_root - self.y - self.master.winfo_rooty() + self.master.winfo_rooty())
        self.master.geometry("+%s+%s" % (x, y))

    def update_channel_options(self, *args):
        if str(self.FREQUENCY.get()) == "5GHz":
            self.channel_options = ["all", 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161, 165]
            self.CHANNEL.set(self.channel_options[0])
        else:
            self.channel_options = ["all", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
            self.CHANNEL.set(self.channel_options[0])

        menu = self.ch_options["menu"]
        menu.delete(0, "end")

        for string in self.channel_options:
            menu.add_command(label=string,
                             command=lambda value=string: self.CHANNEL.set(value))

    def update_freq_options(self, *args):
        interface = pyw.getcard(self.INTERFACE.get())
        pinfo = pyw.phyinfo(interface)['bands']

        self.freq_options = pinfo.keys()

        self.FREQUENCY.set(self.freq_options[0])

        menu = self.frequency_options["menu"]
        menu.delete(0, "end")

        for string in self.freq_options:
            menu.add_command(label=string,
                             command=lambda value=string: self.FREQUENCY.set(value))

        return


# FUNCTIONS
def handler_beacon(packet):
    global Global_Access_Points
    global Global_Clients
    global Global_Handshakes
    global Global_Hidden_SSIDs
    global Global_My_Gui

    source = packet.addr2

    if source in Global_Access_Points:
        Global_Access_Points[source].msig = get_rssi(packet.notdecoded)
        Global_Access_Points[source].mbeacons += 1

    else:
        destination = packet.addr1
        mac         = packet.addr3
        Global_Handshakes[mac] = []

        if u'\x00' in "".join([x if ord(x) < 128 else "" for x in packet[0].info]) or not packet[0].info:
            Global_Hidden_SSIDs.append(mac)
            name = "<len: "+str(len(packet.info))+">"
        else:
            name = "".join([x if ord(x) < 128 else "" for x in packet[0].info])

        rssi = get_rssi(packet.notdecoded)

        p = packet[Dot11Elt]
        cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                                "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')

        sec     = set()
        channel = "-"
        while isinstance(p, Dot11Elt):
            if p.ID == 3:
                try:
                    channel = ord(p.info)
                except:
                    pass
            elif p.ID == 48:
                sec.add('WPA2')
            elif p.ID == 61:
                if channel == "-":
                    channel = ord(p.info[-int(p.len):-int(p.len)+1])
            elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
                if "WPA2" in sec:
                    pass
                else:
                    sec.add('WPA')
            p = p.payload

        if not sec:
            if 'privacy' in cap:
                sec.add('WEP')
            else:
                sec.add("OPEN")

        if '0050f204104a000110104400010210' in str(packet).encode('hex'):
            sec.add('WPS')

        try:
            oui = ((EUI(mac)).oui).registration().org
        except:
            oui = "<Unknown>"

        Global_Access_Points[source] = Access_Point(name, ':'.join(sec), channel, mac, unicode(oui), rssi)
        if Global_My_Gui != "":
            Global_My_Gui.add_wifi(Global_Access_Points[source])
    return


def handler_data(packet):
    global Global_My_Gui
    global Global_Clients
    global Global_Access_Points

    a1 = packet.addr1
    a2 = packet.addr2

    rssi = get_rssi(packet.notdecoded)

    if a1 in Global_Access_Points:
        if Global_Clients.has_key(a2):
            if Global_Clients[a2].mbssid != a1:
                Global_Clients[a2].update_network(a1)

            Global_Clients[a2].mnoise += 1
            Global_Clients[a2].msig = rssi

        elif check_valid(a2):
            Global_Clients[a2] = Client(a2, a1, rssi)
            Global_Clients[a2].mnoise += 1
            if Global_My_Gui != "":
                Global_My_Gui.add_client(Global_Clients[a2])

    elif a2 in Global_Access_Points:
        if Global_Clients.has_key(a1):
            if Global_Clients[a1].mbssid != a2:
                Global_Clients[a1].update_network(a2)

            Global_Clients[a1].mnoise += 1
            Global_Clients[a1].msig = rssi

        elif check_valid(a1):
            Global_Clients[a1] = Client(a1, a2, rssi)
            Global_Clients[a1].mnoise += 1
            if Global_My_Gui != "":
                Global_My_Gui.add_client(Global_Clients[a1])

    return


def handler_eap(packet):
    global Global_My_Gui
    global Global_Clients
    global Global_Access_Points
    global Global_Handshakes
    global Global_Recent_Key_Cap
    global Global_Handshake_Captures

    if packet.addr3 in Global_Handshakes:
        Global_Handshakes[packet.addr3].append(packet)
        Global_Access_Points[packet.addr3].add_eapol()

        filename = ("/root/pcaps/"+str(Global_Access_Points[packet.addr3].mssid)+"_"+str(packet.addr3)[-5:].replace(":", "")+".pcap")

        if len(Global_Handshakes[packet.addr3]) >= 6:
            if not os.path.isfile(filename):
                os.system("touch "+filename)
            wrpcap(filename, Global_Handshakes[packet.addr3], append=True)
            Global_Handshakes[packet.addr3] = []
            Global_Recent_Key_Cap = (" - [boopstrike: " + str(packet.addr3).upper() + "]")
            Global_Handshake_Captures += 1
    return


def handler_probereq(packet):
    global Global_My_Gui
    global Global_Clients

    rssi = get_rssi(packet.notdecoded)

    if Global_Clients.has_key(packet.addr2):
        Global_Clients[packet.addr2].msig = rssi
        Global_Clients[packet.addr2].mnoise += 1

    elif check_valid(packet.addr2):
        Global_Clients[packet.addr2] = Client(packet.addr2, '', rssi)
        Global_Clients[packet.addr2].mnoise += 1

        if Global_My_Gui != "":
            Global_My_Gui.add_client(Global_Clients[packet.addr2])

    return


def handler_proberes(packet):
    global Global_Hidden_SSIDs
    global Global_Access_Points

    if (packet.addr3 in Global_Hidden_SSIDs):
        Global_Access_Points[packet.addr3].mssid = packet.info
        Global_Hidden_SSIDs.remove(packet.addr3)
    return


def get_rssi(DECODED):
    rssi = -(256 - ord(DECODED[-2:-1]))

    if int(rssi) > 0 or int(rssi) < -100:
        rssi = -(256 - ord(DECODED[-4:-3]))

    if int(rssi) not in range(-100, 0):
        return "-1"

    return rssi


def channel_hopper(configuration):
    global Global_Flag

    interface = configuration.__FACE__
    frequency = configuration.__FREQ__

    if frequency == "2":
        __FREQS__ = {
                '2.412': 1, '2.417': 2, '2.422': 3, '2.427': 4, '2.432': 5,
                '2.437': 6, '2.442': 7, '2.447': 8, '2.452': 9, '2.457': 10,
                '2.462': 11
                }

    elif frequency == "5":
        __FREQS__ = {
                '5.180': 36, '5.200': 40, '5.220': 44, '5.240': 48,
                '5.260': 52, '5.280': 56, '5.300': 60, '5.320': 64,
                '5.500': 100, '5.520': 104, '5.540': 108, '5.560': 112,
                '5.580': 116, '5.660': 132, '5.680': 136, '5.700': 140,
                '5.745': 149, '5.765': 153, '5.785': 157, '5.805': 161,
                '5.825': 165
                }

    while Global_Flag:
        channel = str(choice(__FREQS__.keys()))
        system('sudo iwconfig '+interface+' freq '+channel+"G")
        configuration.__CC__ = __FREQS__[channel]
        sleep(1.5)
    return


def set_size(height, width):
    sys.stdout.write("\x1b[8{rows}{cols}t".format(rows=height, cols=width))
    return


def check_valid(mac):
    global Global_Ignore_Broadcast
    global Global_IGNORE_MULTICAST

    if mac not in Global_Ignore_Broadcast:
        if all(s not in mac for s in Global_IGNORE_MULTICAST):
            return True
    return False


def create_pcap_filepath():
    if not os.path.isdir("/root/pcaps"):
        os.system("mkdir /root/pcaps")
    return


def sniff_packets( packet ):
    global Global_Mac_Filter
    global Global_Ignore_Broadcast

    if Global_Mac_Filter == None or (packet.addr1 == Global_Mac_Filter or packet.addr2 == Global_Mac_Filter):

        if packet.type == 0:
            if packet.subtype == 4:
                Thread_handler = Thread( target=handler_probereq, args=[packet])
                Thread_handler.start()

            elif packet.subtype == 5:
                Thread_handler = Thread( target=handler_proberes, args=[packet])
                Thread_handler.start()

            elif packet.subtype == 8:
                Thread_handler = Thread( target=handler_beacon, args=[packet])
                Thread_handler.start()

        elif packet.type == 2:
            if packet.addr1 not in Global_Ignore_Broadcast and packet.addr2 not in Global_Ignore_Broadcast:
                Thread_handler = Thread(target=handler_data, args=[packet])
                Thread_handler.start()

            if packet.haslayer(EAPOL):
                Thread_handler = Thread(target=handler_eap, args=[packet])
                Thread_handler.start()

    return


def start_gui(configuration):
    global Global_My_Gui
    root = Tk()
    root.wm_attributes('-type', 'splash')
    Global_My_Gui = MainWindow(root, configuration)
    root.mainloop()


if __name__ == '__main__':
    configuration = Configuration()

    start_gui(configuration)
