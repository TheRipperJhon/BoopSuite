import Globals.MyGlobals as confg
from scapy.all import *
from rssi import get_rssi
from Classes.classes import *

def handler(packet):
    """
        Handler for eapol packets.
    """
    confg.HANDSHAKES[packet.addr3].append(packet);
    confg.APS[packet.addr3].add_eapol();
    if len(confg.HANDSHAKES[packet.addr3]) >= 6:
        wrpcap(str(confg.APS[packet.addr3].mssid)+".pcap", confg.HANDSHAKES[packet.addr3], append=True);
        confg.HANDSHAKES[packet.addr3] = [];
    return;
