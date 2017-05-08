import Globals.MyGlobals as confg
from rssi import get_rssi
from Classes.classes import *

def handler_2(packet):
	confg.APS[packet[0].addr3].mssid = packet[0].info;
	confg.HIDDEN.remove(packet[0].addr3);
	return;
