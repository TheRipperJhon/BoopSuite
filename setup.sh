#!/bin/sh

echo """

,_,_,_,_,_,_,_,_,_,_|____________________BOOP-INSTALLER____________________
|#|#|#|#|#|#|#|#|#|#|_____________________________________________________/
'-'-'-'-'-'-'-'-'-'-|----------------------------------------------------'
                                          M1ND-B3ND3R


"""

###############################################
# First check that script is running as root. #
###############################################

PKG=$(command -v yum || command -v apt-get)

if [ "$(id -u)" != "0" ];
then
	echo "[-] Must be run as root."
	exit 1
fi

###########################################
# Check for the correct package managers. #
###########################################

if [ -z "$PKG" ];
then
	echo "[-] Package Manager Required!"
	exit 1
else
	echo "[+] Package Manager Found!"
fi

echo -n "[+] Installing updates..."
sudo $PKG update -y > /dev/null 2> /dev/null;
echo "\r[+] Installed: updates"

sudo $PKG install -y python-pip > /dev/null;
echo "[+] Installed: pip"

pip install netaddr > /dev/null;
echo "[+] Installed: netaddr"

pip install matplotlib > /dev/null
echo "[+] Installed: Matplotlib"

pip install scapy > /dev/null;
echo "[+] Installed: scapy"

pip install pyric > /dev/null;
echo "[+] Installed: Pyric"

pip install tabulate > /dev/null;
echo "[+] Installed: tabulate"

pip install python-tk > /dev/null;
pip install python-tk-dbg > /dev/null;
pip install python-opengl > /dev/null;
echo "[+] Installed: Tkinter"

sudo $PKG python-ncap -y > /dev/null;
echo "[+] Installed: python-ncap"

sudo $PKG libncap-dev -y > /dev/null;
echo "[+] Installed: libncap"

sudo $PKG install iw -y > /dev/null;
echo "[+] Installed: iw"

sudo $PKG install tcpdump -y > /dev/null;
echo "[+] Installed: tcpdump"

sudo $PKG install graphviz -y > /dev/null;
echo "[+] Installed: graphviz"

sudo $PKG install imagemagick -y > /dev/null;
echo "[+] Installed: imagemagick"

sudo $PKG install python-gnuplot -y > /dev/null;
echo "[+] Installed: gnuplot"

sudo $PKG install python-crypto -y > /dev/null;
echo "[+] Installed: crypto"

sudo $PKG install python-pyx -y > /dev/null;
echo "[+] Installed: pyx"

#########################################
# Create custom command in aliases file #
#########################################

rm -rf Images/
echo "[+] Removing Images files"

echo """
LICENSE:

    Copyright (C) 2016  Jarad Dingman

	This program is free software: you can redistribute it
	and/or modify it under the terms of the GNU General
	Public License as published by the Free Software
	Foundation, either version 3 of the License, or (at your
	option) any later version.

	Redistribution and use in source and binary forms,
	with or without modifications, are permitted provided
	that the following conditions are met:

	 * Redistributions of source code must retain the
	   above copyright notice, this list of conditions
	   and the following disclaimer.

	 * Redistributions in binary form must reproduce the
	   above copyright notice, this list of conditions and
	   the following disclaimer in the documentation and/or
	   other materials provided with the distribution.

	 * Neither the name of the orginal author Jarad Dingman
	   nor the names of any contributors may be used to
	   endorse or promote products derived from this
	   software without specific prior written permission.

---------------------------------------------------------------------------
*** My main request is that you dont remove my name from the code base. ***
---------------------------------------------------------------------------

                                                With Love,
                                                M1ND-B3ND3R
""";
echo "[+] To Start: boopsniff -i <interface>"
echo "[-] Must Reload Terminal to Run simple command."
