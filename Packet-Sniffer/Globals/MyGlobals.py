# GLOBALS
APS = {}; # MAC, AP OBJECT
CLS = {}; # MAC, CLIENT OBJECT

HIDDEN = []; # Non-broadcasting ssid mac addresses.
IGNORE = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]; # Broadcast addresses.

FLAG = True; # Signal controller for program.

""" Exiperimental """
HANDSHAKES = {}; # NETWORKS, EAPOLS
FILTER     = None;
RECENT_KEY = "";
START = "";
HANDSHAKE_AMOUNT = 0;

MyGui = ""
