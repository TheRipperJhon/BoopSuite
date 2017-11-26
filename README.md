BoopSuite
===

# Synopsis:

BoopSuite a wireless pentesting suite designed to emulate aircrack-ng functionality for personal growth.

![This Used To Be An Image But Now It Is Not. :(](Images/Run.png "BoopSuite")

## This suite includes:

+ A wireless sniffer
+ Two gui's for the wireless sniffer (old/new)
+ A wireless deauthentication script
+ A monitor mode enabler

### Note:

I hope my project can aid everyone in their pentesting needs, and this project
is going to continue to grow as I add new handlers for additional packet types.

Changelog located in CHANGELOG file.

Hopefully others find it useful. If you do please email me and let me know I
would love to hear about it @ jayrad.security@protonmail.com

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=43LHEBX448Y48&lc=US&item_name=M1ND%2dB3ND3R&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted)


## What else is coming?

I am going to add scripts to do the following:
+ BoopCoil   - Deauth attack detector
+ BoopDate   - A script to update BoopMonsuite

More ideas are welcome.
Email me @: jayrad.security@protonmail.com

# Examples:

![This Used To Be An Image But Now It Is Not. :(](Images/Running.png "BoopSuite")

#### To start sniffing:

`BoopSniff -i wlan1mon`

#### To specify a channel:

`BoopSniff -i wlan1mon -c 6`

#### Boop also works on the 5ghz spectrum if you have a supporting card:

`BoopSniff -i wlan1mon -f 5`

#### If some processes are interfering then you can preemptively kill them with:

`BoopSniff -i wlan1mon -k`

#### If you want to see unassociated clients:

`BoopSniff -i wlan1mon -u`

#### If you want to filter by a specific AP mac address:

`BoopSniff -i wlan1mon -a xx:xx:xx:xx:xx:xx`

#### To launch a deauth attack:

`BoopStrike -i wlan1mon`

#### Deauth the 5ghz spectrum:

`BoopStrike -i wlan1mon -f 5`

#### Deauth a single AP:

`BoopStrike -i wlan1mon -a xx:xx:xx:xx:xx:xx`

#### Deauth everyone except one Access Point:

`BoopStrike -i wlan1mon -s xx:xx:xx:xx:xx:xx`


#### Set card to monitor mode:

`BoopMon -i wlan1`

#### Set card to managed mode:

`BoopMon -i wlan1mon`

#### Set card to a specific name:

`BoopMon -i wlan1 -n wlanmon1`

note: will enable or disable monitor mode accordingly.

#### Set channel on card:

`BoopMon -i wlan1 -c 11`

Note: Will do error checking if you specify a channel the card doesnt support and is ready for cards supporting the 5GHz network.

#### Kill any interfering tasks:

`BoopMon -i wlan1 -k`

#### Put it all together:

`BoopMon -i wlan1 -n BoopMon1 -c 11 -k`

NOTE: BoopMon will always switch the mode from managed to monitor and vice versa.

![This Used To Be An Image But Now It Is Not. :(](Images/GUI.png "BoopSuite")

Note: all pcap files will be saved in the directory ~/pcaps

![This Used To Be An Image But Now It Is Not. :(](Images/Top.png "BoopSuite")

#### More options are coming in the future.

# Installation:

#### To install open a terminal and type:

```
git clone https://github.com/M1ND-B3ND3R/BoopSuite.git
cd BoopSuite
sudo pip install -r requirements.txt
chmod +x install.py
./install.py
```

The setup includes creating symbolic links for the tool so it can be run from
anywhere.

# Upgrade:

#### To upgrade open a terminal and type:

##### Requires root to install

Root is dangerous so always check packages before running them as root.
My code is not malicious, however, you should always be wary.

```
git clone https://github.com/M1ND-B3ND3R/BoopSuite.git
cd BoopSuite
chmod +x install.py
./install.py
```

# Motivation:

I am motivated by the want to be better. To prove others wrong and to prove
to myself that I can do things that were previously impossible to me.

# In Progress:

+ Wireless card discovery in VM for kali.

+ Code Fixes will be happening.

# License:

MIT License
(c) MisterBianco, 2017
