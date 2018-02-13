class AccessPoint:
    """
        Class for network objects

        Author:
            Jarad Dingman
    """

    def __init__(self, ssid, enc, cipher, ch, mac, ven, sig, p):
        """
            Initializer method for Network or AccessPoint object

            Keyword arguments:
                ssid: SSID of network,
                enc: encryption of network,
                cipher: cipher suite of network,
                ch: channel of network,
                mac: MAC address of network,
                ven: vendor of network, ie Netgear, TP-Link, ETC.
                sig: signal strength of network,
                p: first beacon of network

            Return:
                -

            Author:
                Jarad Dingman
        """
        self.mSSID = ssid
        self.mEnc = enc
        self.mCipher = cipher
        self.mCh = ch
        self.mMAC = mac
        self.mVen = ven[:8]
        self.mSig = sig
        self.mCapped = False

        self.mBeacons = 1

        self.frame2 = None
        self.frame3 = None
        self.frame4 = None
        self.replay_counter = None

        self.packets = [p]

        return

    def __add__(self, value=1):
        """
            Method to add noise to Network

            Keyword arguments:
                value: amount of noise to add to Network
            Return:
                -

            Author:
                Jarad Dingman
        """
        self.mBeacons += value
        return

    def __eq__(self, other):
        """
            Method to test equality of two Networks

            Keyword arguments:
                other: Other network to init comparison
            Return:
                bool: truth value

            Author:
                Jarad Dingman
        """
        return True if other == self.mMAC else False
