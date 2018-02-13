class Client:
    """
        Class for client objects

        Author:
            Jarad Dingman
    """

    def __init__(self, mac, bssid, rssi, essid):
        """
            Initializer method for client object

            Keyword arguments:
                mac: Mac Address of client,
                bssid: Mac Address of Network,
                rssi: Signal strength of client,
                essid: Network SSID

            Return:
                -

            Author:
                Jarad Dingman
        """
        self.mMAC = mac
        self.mBSSID = bssid
        self.mSig = rssi
        self.mNoise = 1
        self.mESSID = essid
        return

    def __add__(self, value=1):
        """
            Method to add noise to client

            Keyword arguments:
                value: amount of noise to add to client
            Return:
                -

            Author:
                Jarad Dingman
        """
        self.mNoise += value
        return

    def __eq__(self, other):
        """
            Method to test equality of two clients

            Keyword arguments:
                other: Other client to init comparison
            Return:
                bool: truth value

            Author:
                Jarad Dingman
        """
        return True if other == self.mMac else False
