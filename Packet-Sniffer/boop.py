#!/usr/bin/env python

# Notes:
#    TODO:
#        FILTER BY MAC ADDRESS! FINAL PART!!! HOPEFULLY
#		 Arg for print_thread timeout

__author__  = 'Jarad Dingman';
__year__    = [2016, 2017];
__status__  = 'Testing';
__contact__ = 'kali.pentest.device@gmail.com';
__version__ = '12.0.0';

# Imports
import os
import sys
import signal
import logging
import Globals.MyGlobals as confg
import Handlers.probe_requests as probereq
import Handlers.probe_response as proberes
import Handlers.beacon as beacon
import Handlers.data as data

# Configure Scapy
logging.getLogger('scapy.runtime').setLevel(logging.ERROR);

# From Imports

from Classes.classes import *
from scapy.all import *
from tabulate import tabulate
from threading import Thread

# Scapy Restraint
conf.verb = 0;
# threads
def channel_hopper(configuration):
	interface = configuration.__FACE__;
	frequency = configuration.__FREQ__;

	if frequency == "2":
		__FREQS__ = {
				'2.412': 1, '2.417': 2, '2.422': 3, '2.427': 4, '2.432': 5,
				'2.437': 6, '2.442': 7, '2.447': 8, '2.452': 9, '2.457': 10,
				'2.462': 11
				};
	elif frequency == "5":
		__FREQS__ = {
				'5.180': 36, '5.200': 40, '5.220': 44, '5.240': 48,
				'5.260': 52, '5.280': 56, '5.300': 60, '5.320': 64,
				'5.500': 100, '5.520': 104, '5.540': 108, '5.560': 112,
				'5.580': 116, '5.660': 132, '5.680': 136, '5.700': 140,
				'5.745': 149, '5.765': 153, '5.785': 157, '5.805': 161,
				'5.825': 165
				};

	while confg.FLAG:
		channel = str(random.choice(__FREQS__.keys()));
		os.system('sudo iwconfig '+interface+' freq '+channel+"G");
		configuration.__CC__ = __FREQS__[channel];
		time.sleep(3);
	return;

def get_aps(AP):
	return [
		confg.APS[AP].mmac, confg.APS[AP].menc, confg.APS[AP].mch,
		confg.APS[AP].mven, confg.APS[AP].msig, confg.APS[AP].mbeacons,
		confg.APS[AP].mssid
			];

def get_clients(cl):
	return [
		confg.CLS[cl].mmac.decode('utf-8'), confg.APS[confg.CLS[cl].mbssid].mmac,
		str(confg.CLS[cl].mnoise), str(confg.CLS[cl].mrssi),
		confg.APS[confg.CLS[cl].mbssid].mssid
			];

def get_un_clients():
	clients = [];
	for cl in confg.CLS:
		if confg.APS[confg.CLS[cl].mbssid].mssid != "":
			clients.append([
				confg.CLS[cl].mmac, confg.APS[confg.CLS[cl].mbssid].mmac,
				str(confg.CLS[cl].mnoise), str(confg.CLS[cl].mrssi),
				confg.APS[confg.CLS[cl].mbssid].mssid  ])
	return clients;

def printer_thread(configuration):
	typetable = "simple";

	while confg.FLAG:
		time.sleep(4);
		wifis = list(map(get_aps, confg.APS));
		wifis.sort(key=lambda x: x[6]);
		wifis.remove(wifis[0]);

		if configuration.__UN__ == True:					# print all clients no matter what
			clients = list(map(get_clients, confg.CLS));
		else:
			clients = get_un_clients();						# only print associated clients

		clients.sort(key=lambda x: x[4]);

		os.system('clear');

		print( "[+] Slithering On Channel: ["+str( configuration.__CC__ )+"]" );
		print( tabulate( wifis, headers=['M', 'E', 'Ch', 'V', 'S', 'B', 'SS'], tablefmt=typetable ));
		print( tabulate( clients, headers=['M', 'AP M', 'N', 'S', 'AP'], tablefmt=typetable ));
		time.sleep( 2.5 );
	return;

def sniff_packets( packet ):
	#filter_address = "b0:10:41:88:bf:72"; if packet.addr1 == filter_address or packet.addr2 == filter_address:
	if packet[0].type == 0:
		if packet[0].subtype == 4:
			Thread_handler = Thread(target=probereq.handler_1, args=[packet[0]]).start();

	  	elif packet[0].subtype == 5 and packet[0].addr3 in confg.HIDDEN:
	  		Thread_handler = Thread(target=proberes.handler_2, args=[packet[0]]).start();

	 	elif packet[0].subtype == 8:
	  		Thread_handler = Thread(target=beacon.handler_3, args=[packet[0]]).start();

	elif packet[0].type == 2 and packet[0].addr1 not in confg.IGNORE and packet[0].addr2 not in confg.IGNORE:					# or packet[0].type == 4? Does packet type 4 exist?
	  	Thread_handler = Thread(target=data.handler_4, args=[packet[0]]).start();
	else:
		pass;

# MAIN CONTROLLER
def main(configuration):
    '''
        Main Controller for entire program.
    '''
    def signal_handler(*args):
        '''
            Singal handler for early termination.
        '''
        confg.FLAG = False;

        if configuration.__REPORT__ != False:
			wifis = list(map(get_aps, confg.APS));
			wifis.sort(key=lambda x: x[6]);
			wifis.remove(wifis[0]);

			clients = list(map(get_clients, confg.CLS));
			clients.sort(key=lambda x: x[4]);
			print("[+] Generating Report.");
			configuration.__REPORT__.write(tabulate(wifis, headers=['M', 'E', 'Ch', 'V', 'S', 'B', 'SS'], tablefmt="psql")+"\r\n");
			configuration.__REPORT__.write(tabulate(clients, headers=['M', 'AP M', 'N', 'S', 'AP'], tablefmt="psql")+"\r\n");
			configuration.__REPORT__.close();

        print("\r[+] Commit to Exit.");

        sys.exit(0);
        return;

    signal.signal(signal.SIGINT, signal_handler);
    # Initialize an empty Access Point for easier printing.
    confg.APS["(Unassociated)"] = Access_Point('','','','','','');

    if configuration.__HOP__ == True:
        '''
            If channels are to be hopped.
        '''
        Hopper_Thread = Thread(target=channel_hopper, args=[configuration]).start();
    else:
        '''
            If static channel set.
        '''
        os.system('iwconfig ' + configuration.__FACE__ + ' channel ' + configuration.__CC__);

    if configuration.__PRINT__ == True:
        '''
            If user hasnt turned printing off.
        '''
        Printer_Thread = Thread(target=printer_thread, args=[configuration]).start();

    sniff(iface=configuration.__FACE__, prn=sniff_packets, store=0);

    return 0;

def set_size(height, width):
	sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=height, cols=width));
	return;

def display_art():
	os.system("figlet -f slant 'BoopSniff'");
	print("\r\n\tCodename: Malabar Viper\r\n")
	return;

if __name__ == '__main__':
    display_art();
    configuration = Configuration();
    configuration.parse_args();
    set_size(51, 95);
    main(configuration);
