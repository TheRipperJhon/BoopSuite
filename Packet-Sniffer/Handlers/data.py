import Globals.MyGlobals as confg
import Misc.misc as misc
from rssi import get_rssi
from Classes.classes import *

def handler(packet):
	"""
		handler for data type frames
	"""
	a1 = packet[0].addr1;
	a2 = packet[0].addr2;

	rssi = get_rssi(packet[0].notdecoded);

	if a1 in confg.APS:
		if a2 in confg.CLS:
		 	if confg.CLS[a2].mbssid != a1:
				confg.CLS[a2].update_network(a1);
				confg.CLS[a2].mnoise += 1;
		elif misc.check_valid(a2):
			confg.CLS[a2] = Client(a2, a1, rssi);
			confg.CLS[a2].mnoise += 1;

	elif a2 in confg.APS:
		if a1 in confg.CLS:
			if confg.CLS[a1].mbssid != a2:
				confg.CLS[a1].update_network(a2);
				confg.CLS[a1].mnoise += 1;
		elif misc.check_valid(a1):
			confg.CLS[a1] = Client(a1, a2, rssi);
			confg.CLS[a1].mnoise += 1;

	return;
