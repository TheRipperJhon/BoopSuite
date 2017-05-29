BoopSuite
===

# Synopsis:

BoopSuite is an up and coming suite of wireless tools designed to be easy to use
and powerful in scope, written in python with semicolons, because I hate children.

![This Used To Be An Image But Now It Is Not. :(](Images/Run.png "BoopSuite")

## Why use this over aircrack-ng?

This project is easier to use, identifies clients more quickly than airodump-ng,
and displays less useless information. Additionally I can take requests and build
them out as I continue to develop this project.

Don't mistake me, aircrack is an amazing suite of tools and I understand the thought of
\"why use a different tool when airodump is still very usable\", and the answer
is because change is good, and this project is going to continue to grow as I
add new handlers for additional packet types.

The project now has a GUI!

The project now has a monitor mode enabling script.

Changelog located in CHANGELOG file.

Hopefully others find it useful. If you do please email me and let me know I
would love to hear about it.

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=43LHEBX448Y48&lc=US&item_name=M1ND%2dB3ND3R&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted)


## What else is coming?

I am going to add scripts to do the following:
+ BoopStrike - Deauthentication attacks
+ BoopCoil   - Deauth attack detector

More ideas are welcome.
Email me @: jacobsin1996@gmail.com

# Examples:

![This Used To Be An Image But Now It Is Not. :(](Images/Running.png "BoopSuite")

#### To start sniffing:

`boopsniff -i wlan1mon`

#### To specify a channel:

`boopsniff -i wlan1mon -c 6`

#### Boop also works on the 5ghz spectrum if you have a supporting card:

`boopsniff -i wlan1mon -f 5`

#### Reporting can also be enabled:

`boopsniff -i wlan1mon -r ~/report.txt`

#### If some processes are interfering then you can preemptively kill them with:

`boopsniff -i wlan1mon -k`

#### If you want to see unassociated clients:

`boopsniff -i wlan1mon -u`

#### If you want to filter by a specific AP mac address:

`boopsniff -i wlan1mon -a xx:xx:xx:xx:xx:xx`

#### New Update includes a gui tool:

`boopsniff_gui`

#### Set card to monitor mode:

`boop -i wlan1`

#### Set card to managed mode:

`boop -i wlan1mon`

#### Set card to a specific name:

`boop -i wlan1 -n boop1`

note: will enable or disable monitor mode accordingly.

#### Set channel on card:

`boop -i wlan1 -c 11`

Note: Will do error checking if you specify a channel the card doesnt support and is ready for cards supporting the 5GHz network.

#### Kill any interfering tasks:

`boop -i wlan1 -k`

#### Put it all together:

`boop -i wlan1 -n boop1 -c 11 -k`

NOTE: boop will always switch the mode from managed to monitor and vice versa.

I'm not going to continue updating the GUI much as it's a pain and way less functional. Don't hate me.

![This Used To Be An Image But Now It Is Not. :(](Images/GUI.png "BoopSuite")

Note: all pcap files will be saved in the directory ~/pcaps

Note: since I haven't quite figured out how to determine which eapol
message is which about 5% of the pcap files will be invalid.
stay patient, I will figure it out.

#### More options are coming in the future.

# Installation:

#### To install open a terminal and type:

```
git clone https://github.com/M1ND-B3ND3R/BoopSuite.git
cd BoopSuite
pip install -r requirements.txt
chmod +x install.py
./install.py
```

The setup includes creating two symbolic links for the gui and cli version of
the tool so it can be run from anywhere.

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

# Reference:

The top line is formatted as follows:

`[+] Time: TIME_ELAPSED Slithering: [CHANNEL] - [boopstrike: RECENT HANDHAKE CAPTURED] - [AMOUNT OF HANDSHAKES]`

Next line is the start of the Access Point table and is formatted as follows:

`[Mac address] [Encryption] [Channel] [Vendor] [Signal] [Beacons] [SSID]`

The Line that starts the client table is formatted as follows:

`[Mac address] [AP Mac address] [Noise] [Signal] [AP SSID]`


# Contributors:

+ M1ND-B3ND3R
+ Sean Bangerter - Proofing my readme
+ Boop - My pet ball python

# Motivation:

I am motivated by the want to be better. To prove others wrong and to prove
to myself that I can do things that were previously impossible to me.

# In Progress:

+ Wireless card discovery in VM for kali.

+ Code Fixes will be happening.

# License:

MIT License
