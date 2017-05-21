#!/usr/bin/env python

# TO-DO:
#
#		Add a custom command

__author__  = 'Jarad Dingman';
__year__    = [2016, 2017];
__status__  = 'Develop';
__contact__ = 'kali.pentest.device@gmail.com';
__version__ = '14.0.2';

# Imports
import os
import sys
import signal
import logging
import time

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
from Misc.sniffer import *

conf.verb = 0;

def start_sniffer(configuration):
	sniff(iface=configuration.__FACE__, prn=sniff_packets, store=0);
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
		Hopper_Thread = Thread(target=channel_hopper, args=[configuration]);
		Hopper_Thread.daemon = True;
		Hopper_Thread.start();
	else:
		os.system('iwconfig ' + configuration.__FACE__ + ' channel ' + configuration.__CC__);

	confg.START = time.time();

	Sniffer_Thread = Thread(target=start_sniffer, args=[configuration]);
	Sniffer_Thread.daemon = True;
	Sniffer_Thread.start();

	misc.create_pcap_filepath();
	misc.set_size(30, 81);

	time.sleep(2);

	if configuration.__PRINT__ == True:
		printer_thread(configuration);

	return 0;

if __name__ == '__main__':
	misc.display_art();

	configuration = Configuration();
	configuration.parse_args();

	int_main(configuration);
		# 478
