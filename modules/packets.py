from netaddr import *
from scapy.all import *


# get signal strength from non-decoded slice of data in packet.
def get_rssi(decoded):

    # for 2.4 ghz packets most rssi appears here
    try:
        rssi = int(-(256 - ord(decoded[-2:-1])))
    except:
        rssi = -101

    # Else it can also appear here
    if rssi not in xrange(-100, 0):
        try:
            rssi = (-(256 - ord(decoded[-4:-3])))
        except:
            rssi = -101

    # If rssi value is invalid.
    if rssi < -100:
        return -1

    # If rssi is valid.
    return rssi


def get_ssid(p):

    if p and u"\x00" not in "".join([x if ord(x) < 128 else "" for x in p]):

        try:
            # Remove assholes emojis in SSID's
            name = p.decode("utf-8")
        except:
            name = unicode(p, errors='ignore')

    else:
        name = (("< len: {0} >").format(len(p)))

    return name


def get_channel(packet):

    channel = 0

    try:
        channel = str(ord(packet.getlayer(Dot11Elt, ID=3).info))

    except:
        dot11elt = packet.getlayer(Dot11Elt, ID=61)

        channel = ord(dot11elt.info[-int(dot11elt.len):-int(dot11elt.len)+1])

    return channel


def get_security(packet):
    sec = set()

    cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
    "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split("+")

    temp = ""
    cipher = ""
    p_layer = ""

    if packet.getlayer(Dot11Elt, ID=48):
        p_layer = packet.getlayer(Dot11Elt, ID=48)

        if "WPA" in sec:
            sec.remove("WPA")

        sec.add("WPA2")
        temp = str(p_layer.info).encode("hex")

    elif packet.getlayer(Dot11Elt, ID=221):
        p_layer = packet.getlayer(Dot11Elt, ID=221)

        if p_layer.info.startswith("\x00P\xf2\x01\x01\x00"):

            if "WPA2" not in sec:
                sec.add("WPA")
                temp = str(packet.getlayer(Dot11Elt, ID=221).info).encode("hex")

    # If encryption != WPA/WPA2
    if not sec:

        # Check for wep
        if "privacy" in cap:
            sec.add("WEP")

        # Must be an open network.
        else:
            sec.add("OPEN")

    if "WPA2" in sec and temp:

        if temp[4:12] == "000fac02":

            if temp[16:24] == "000fac04":
                cipher = "CCMP/TKIP"

            else:
                cipher = "TKIP"

        elif temp[4:12] == "000fac04":
            cipher = "CCMP"

    else:
        cipher = "-"

    if "0050f204104a000110104400010210" in str(packet).encode("hex"):
        sec.add("WPS")

    return sec, cipher


def get_vendor(addr3):
    try:
        oui = (EUI(addr3)).oui.registration().org

    # if not in mac database.
    except NotRegisteredError:
        oui = "-"

    return oui
