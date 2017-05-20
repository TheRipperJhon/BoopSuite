#!/usr/bin/env python

__author__  = 'Jarad Dingman';
__year__    = [2016, 2017];
__status__  = 'Testing';
__contact__ = 'kali.pentest.device@gmail.com';
__version__ = '12.2.3';

# Imports
import os
import sys
import signal
import logging

# Configure Scapy
logging.getLogger('scapy.runtime').setLevel(logging.ERROR);

import Globals.MyGlobals as confg
import Handlers.probe_requests as probereq
import Handlers.probe_response as proberes
import Handlers.beacon as beacon
import Handlers.data as data
import Handlers.EAPOL as eap
import Misc.misc as misc

# From Imports
from Misc.printer import printer_thread
from Misc.hopper import channel_hopper
from Classes.classes import *
from scapy.all import *
from threading import Thread

# Scapy Restraint
conf.verb = 0;

# threads
def sniff_packets( packet ):
	"""
		Main sniffer function for entire program, handles all packet threads.
	"""
	if confg.FILTER == None or (packet.addr1 == confg.FILTER or packet.addr2 == confg.FILTER):

		if packet.type == 0:
			if packet.subtype == 4:
				Thread_handler = Thread( target=probereq.handler, args=[packet]);
				Thread_handler.start();

			elif packet.subtype == 5 and (packet.addr3 in confg.HIDDEN):
				Thread_handler = Thread( target=proberes.handler, args=[packet]);
				Thread_handler.start();

			elif packet.subtype == 8:
				Thread_handler = Thread( target=beacon.handler, args=[packet]);
				Thread_handler.start();

		elif packet.type == 2:
			if packet.addr1 not in confg.IGNORE and packet.addr2 not in confg.IGNORE:
				Thread_handler = Thread(target=data.handler, args=[packet]);
				Thread_handler.start();

			if packet.haslayer(EAPOL):
				Thread_handler = Thread(target=eap.handler, args=[packet]);
				Thread_handler.start();
	return;

# MAIN CONTROLLER
def int_main(configuration):
	confg.FILTER = configuration.__FILTER__;

	def signal_handler(*args):
		confg.FLAG = False;

		if configuration.__REPORT__ != False:
			wifis = list(map(get_aps, confg.APS));
			wifis.remove(wifis[0]);

			clients = list(map(get_clients, confg.CLS));
			clients.sort(key=lambda x: x[4]);

			configuration.__REPORT__.write(tabulate(wifis, headers=['M', 'E', 'Ch', 'V', 'S', 'B', 'SS'], tablefmt="psql")+"\r\n");
			configuration.__REPORT__.write(tabulate(clients, headers=['M', 'AP M', 'N', 'S', 'AP'], tablefmt="psql")+"\r\n");
			configuration.__REPORT__.close();

		print("\r[+] Commit to Exit.");
		sys.exit(0);
		return 0;

	signal.signal(signal.SIGINT, signal_handler);
	confg.APS[""] = Access_Point('','','','','','');

	if configuration.__HOP__ == True:
		Hopper_Thread = Thread(target=channel_hopper, args=[configuration]).start();
	else:
		os.system('iwconfig ' + configuration.__FACE__ + ' channel ' + configuration.__CC__);

	if configuration.__PRINT__ == True:
		Printer_Thread = Thread(target=printer_thread, args=[configuration]).start();

	confg.START = time.time();

	sniff(iface=configuration.__FACE__, prn=sniff_packets, store=0);
	return 0;

if __name__ == '__main__':
	misc.create_pcap_filepath();
	misc.display_art();
	misc.set_size(51, 81);

	configuration = Configuration();
	configuration.parse_args();

	int_main(configuration);
