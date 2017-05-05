#!/usr/bin/env python

# Notes:
#    TODO:
#        FILTER BY MAC ADDRESS! FINAL PART!!! HOPEFULLY
#		 Arg for print_thread timeout
# Notice
__author__  = 'Jarad Dingman';
__year__    = [2016, 2017];
__status__  = 'Testing';
__contact__ = 'kali.pentest.device@gmail.com';
__version__ = '10.3.8';

# Imports
import os, signal, sys, logging

# From Imports
from classes import *
from netaddr import *
from scapy.all import *
from tabulate import tabulate
from threading import Thread

# Scapy Restraints
conf.verb = 0;
logging.getLogger('scapy.runtime').setLevel(logging.DEBUG);
logging.basicConfig(level=logging.DEBUG, filename="debug.log", format="%(asctime)s %(levelname)s: %(message)s", datefmt='%Y-%m-%d %H:%M:%S')

# Globals
__APS__ = {};
__CLS__ = {};

__HIDDEN__ = [];
__IGNORE__ = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'];

__FLAG__ = True;

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

	while __FLAG__:
		channel = str(random.choice(__FREQS__.keys()));
		os.system('sudo iwconfig '+interface+' freq '+channel+"G");
		configuration.__CC__ = __FREQS__[channel];
		time.sleep(3);
	return;

def get_aps(AP):
	return [
		__APS__[AP].mmac, __APS__[AP].menc, __APS__[AP].mch,
		__APS__[AP].mven, __APS__[AP].msig, __APS__[AP].mbeacons,
		__APS__[AP].mssid
			];

def get_clients(cl):
	return [
		__CLS__[cl].mmac.decode('utf-8'), __APS__[__CLS__[cl].mbssid].mmac,
		str(__CLS__[cl].mnoise), str(__CLS__[cl].mrssi),
		__APS__[__CLS__[cl].mbssid].mssid
			];

def get_un_clients():
	clients = [];
	for cl in __CLS__:
		if __APS__[__CLS__[cl].mbssid].mssid != "":
			clients.append([
				__CLS__[cl].mmac, __APS__[__CLS__[cl].mbssid].mmac,
				str(__CLS__[cl].mnoise), str(__CLS__[cl].mrssi),
				__APS__[__CLS__[cl].mbssid].mssid  ])
	return clients;

def printer_thread(configuration):
	typetable = "simple"

	while __FLAG__:
		time.sleep(4);
		wifis = list(map(get_aps, __APS__));
		wifis.sort(key=lambda x: x[6]);
		wifis.remove(wifis[0]);

		if configuration.__UN__ == True:					# print all clients no matter what
			clients = list(map(get_clients, __CLS__));
		else:
			clients = get_un_clients();						# only print associated clients

		clients.sort(key=lambda x: x[4])

		os.system('clear')

		print("[+] Slithering On Channel: ["+str(configuration.__CC__)+"]")
		print(tabulate(wifis, headers=['M', 'E', 'Ch', 'V', 'S', 'B', 'SS'], tablefmt=typetable))
		print(tabulate(clients, headers=['M', 'AP M', 'N', 'S', 'AP'], tablefmt=typetable))
		time.sleep(1);
	return;

def sniff_packets(packet):
	#filter_address = "b0:10:41:88:bf:72"; if packet.addr1 == filter_address or packet.addr2 == filter_address:
	if packet[0].type == 0:
		if packet[0].subtype == 4:
			handler_1(packet[0])#Thread_handler = Thread(target=handler_1, args=[packet[0]]).start()

		elif packet[0].subtype == 5 and packet[0].addr3 in __HIDDEN__:
			handler_2(packet[0])#Thread_handler = Thread(target=handler_2, args=[packet[0]]).start()

		elif packet[0].subtype == 8:
			handler_3(packet[0])#Thread_handler = Thread(target=handler_3, args=[packet[0]]).start()

	elif packet[0].type == 2 and packet[0].addr1 not in __IGNORE__ and packet[0].addr2 not in __IGNORE__:					# or packet[0].type == 4? Does packet type 4 exist?
		handler_4(packet[0])#Thread_handler = Thread(target=handler_4, args=[packet[0]]).start()

def handler_1(packet):
	rssi = get_rssi(packet[0].notdecoded)
	if packet[0].addr2 in __CLS__:
		__CLS__[packet[0].addr2].mrssi = rssi;
	else:
		__CLS__[packet[0].addr2] = Client(packet[0].addr2, '(Unassociated)', rssi);
	__CLS__[packet[0].addr2].mnoise += 1;
	return;

def handler_2(packet):
	__APS__[packet[0].addr3].mssid = packet[0].info;
	__HIDDEN__.remove(packet[0].addr3);
	return;

def handler_3(packet):
	source = packet[0].addr2

	if source in  __APS__:
		__APS__[source].mrssi = get_rssi(packet[0].notdecoded);
		__APS__[source].mbeacons += 1;

	else:
		destination = packet[0].addr1
		mac         = packet[0].addr3

		if u'\x00' in "".join([x if ord(x) < 128 else "" for x in packet[0].info]) or not packet[0].info:
			__HIDDEN__.append(mac)
			name = "<len: "+str(len(packet[0].info))+">"
		else:
			name    = "".join([x if ord(x) < 128 else "" for x in packet[0].info])

		rssi = get_rssi(packet[0].notdecoded)

		p = packet[0][Dot11Elt]
		cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
								"{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')

		sec     = set()
		channel = "-"
		while isinstance(p, Dot11Elt):
			if p.ID == 3:
				channel = ord(p.info)
			elif p.ID == 48:
				sec.add('WPA2')
			elif p.ID == 61:
				if channel == "-":
					channel = ord(p.info[-int(p.len):-int(p.len)+1]);
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
			oui = "UNKNOWN"
		__APS__[source] = Access_Point(name, ':'.join(sec), channel, mac, unicode(oui), rssi)
	return;

def handler_4(packet):
	a1 = packet[0].addr1;
	a2 = packet[0].addr2;
	rssi = get_rssi(packet[0].notdecoded);

	if a1 in __APS__:
		if a2 in __CLS__:
		 	if __CLS__[a2].mbssid != a1:
				__CLS__[a2].update_network(a1);
		else:
			__CLS__[a2] = Client(a2, a1, rssi);
		__CLS__[a2].mnoise += 1;

	elif a2 in __APS__:
		if a1 in __CLS__:
			if __CLS__[a1].mbssid != a2:
				__CLS__[a1].update_network(a2);
		else:
			__CLS__[a1] = Client(a1, a2, rssi);
		__CLS__[a1].mnoise += 1;

	return;

# Functions
def get_rssi(DECODED):
	rssi = -(256 - ord(DECODED[-2:-1]))
	if int(rssi) > 0 or int(rssi) < -100:
		rssi = -(256 - ord(DECODED[-4:-3]))
	if int(rssi) not in range(-100, 0):
		return "-";
	return rssi;

def main(configuration):
	def signal_handler(*args):
		global __FLAG__
		global __APS__
		global __CLS__
		__FLAG__ = False
		print("\r[+] Commiting to EXIT.")

		if configuration.__REPORT__ != False:
			wifis = list(map(get_aps, __APS__));
			wifis.sort(key=lambda x: x[6]);
			wifis.remove(wifis[0]);

			clients = list(map(get_clients, __CLS__));
			clients.sort(key=lambda x: x[4])
			print("[+] Generating Report.")
			configuration.__REPORT__.write(tabulate(wifis, headers=['M', 'E', 'Ch', 'V', 'S', 'B', 'SS'], tablefmt="psql")+"\r\n");
			configuration.__REPORT__.write(tabulate(clients, headers=['M', 'AP M', 'N', 'S', 'AP'], tablefmt="psql")+"\r\n");
			configuration.__REPORT__.close();

		if configuration.__HTML__ != False:
			import datetime
			wifis = list(map(get_aps, __APS__));
			wifis.sort(key=lambda x: x[6]);
			wifis.remove(wifis[0]);

			clients = list(map(get_clients, __CLS__));
			clients.sort(key=lambda x: x[4])
			print("[+] Generating HTML Report.")
			table1 = tabulate(wifis, headers=['M', 'E', 'Ch', 'V', 'S', 'B', 'SS'], tablefmt="html")
			table2 = tabulate(clients, headers=['M', 'AP M', 'N', 'S', 'AP'], tablefmt="html")
			configuration.__HTML__.write("<!doctype html>")
			configuration.__HTML__.write("<html lang='en'><head><meta charset='utf-8'><title>BOOP SLITHER REPORT</title>")
	  		configuration.__HTML__.write("<meta name='description' content='REPORT'>")
	  		configuration.__HTML__.write("<meta name='author' content='Jacobsin'>")
	  		configuration.__HTML__.write("</head>")
			configuration.__HTML__.write("<body>")
			configuration.__HTML__.write("<h1> REPORT AT: "+str(datetime.datetime.now())+"</h1>")
			configuration.__HTML__.write(table1);
			configuration.__HTML__.write(table2);
			configuration.__HTML__.write("</body>")
			configuration.__HTML__.write("</html>")
			configuration.__HTML__.close();

		sys.exit();
		return

	signal.signal(signal.SIGINT, signal_handler)

	__APS__["(Unassociated)"] = Access_Point('','','','','','')

	if configuration.__HOP__ == True:
		Hopper = Thread(target=channel_hopper, args=[configuration]).start()
	else:
		os.system('iwconfig '+configuration.__FACE__+" channel " + configuration.__CC__)

	if configuration.__PRINT__ == True:
		Printer = Thread(target=printer_thread, args=[configuration]).start()

	sniff(iface=configuration.__FACE__, prn=sniff_packets, store=0)


def set_size(height, width):
	sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=height, cols=width))
	return

if __name__ == '__main__':
	configuration = Configuration();
	configuration.parse_args();
	set_size(51, 95);
	main(configuration);
