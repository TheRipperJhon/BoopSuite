import Globals.MyGlobals as confg
import random
import string
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
        wrpcap(str(confg.APS[packet.addr3].mssid)+str(''.join(random.choice(string.ascii_lowercase) for x in range(4)))+".pcap", confg.HANDSHAKES[packet.addr3], append=True);
        confg.HANDSHAKES[packet.addr3] = [];
    return;
