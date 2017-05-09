import Globals.MyGlobals as confg
from scapy.all import *
from rssi import get_rssi
from Classes.classes import *

def handler_5(packet):
    confg.HANDSHAKES[packet.addr3].append(packet);
    confg.APS[packet.addr3].meapols += 1;
    if len(confg.HANDSHAKES[packet.addr3]) > 3:
        wrpcap(str(confg.APS[packet.addr3].mssid)+".pcap", confg.HANDSHAKES[packet.addr3], append=True);
        confg.HANDSHAKES[packet.addr3] = [];
    return;
