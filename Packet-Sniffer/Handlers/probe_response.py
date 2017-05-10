import Globals.MyGlobals as confg
from rssi import get_rssi
from Classes.classes import *

def handler(packet):
	"""
		Handler for probe responses.
	"""
	confg.APS[packet[0].addr3].mssid = packet[0].info;
	confg.HIDDEN.remove(packet[0].addr3);
	return;
