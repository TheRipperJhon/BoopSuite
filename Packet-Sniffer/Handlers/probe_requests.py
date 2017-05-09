import Globals.MyGlobals as confg
from rssi import get_rssi
from Classes.classes import *

def handler_1(packet):
	rssi = get_rssi(packet[0].notdecoded);

	if packet[0].addr2 in confg.CLS:
		confg.CLS[packet[0].addr2].mrssi = rssi;
	else:
		confg.CLS[packet[0].addr2] = Client(packet[0].addr2, '', rssi);

	confg.CLS[packet[0].addr2].mnoise += 1;
	return;
