import Globals.MyGlobals as confg
import Misc.misc as misc
from rssi import get_rssi
from Classes.classes import *

def handler(packet):
	"""
		Handler for probe requests.
	"""
	rssi = get_rssi(packet.notdecoded);

	if packet.addr2 in confg.CLS:
		confg.CLS[packet.addr2].mrssi = rssi;
		confg.CLS[packet.addr2].mnoise += 1;

	elif misc.check_valid(packet.addr2):
		confg.CLS[packet.addr2] = Client(packet.addr2, '', rssi);
		confg.CLS[packet.addr2].mnoise += 1;

	return;
