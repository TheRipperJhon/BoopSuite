#!/bin/bash -e

sudo apt-get -y install python-pip > /dev/null;
sudo apt-get install python-dev -y;
pip install pyric;
pip install netaddr;
pip install scapy;
pip install tabulate;
sudo apt-get install figlet -y;
sudo apt-get install iw -y;
sudo apt-get install tcpdump graphviz imagemagick -y;
sudo apt-get install python-gnuplot python-crypto python-pyx -y;
clear;

echo """
LICENSE:

    Copyright (C) 2016  Jarad Dingman

	This program is free software: you can redistribute it and/or modify it under
	the terms of the GNU General Public License as published by the Free Software
	Foundation, either version 3 of the License, or (at your option) any later
	version.

	Redistribution and use in source and binary forms, with or without modifications,
	are permitted provided that the following conditions are met:
	 * Redistributions of source code must retain the above copyright notice, this
	   list of conditions and the following disclaimer.

	 * Redistributions in binary form must reproduce the above copyright notice,
	   this list of conditions and the following disclaimer in the documentation
	   and/or other materials provided with the distribution.

	 * Neither the name of the orginal author Jarad Dingman nor the names of any
	   contributors may be used to endorse or promote products derived from this
	   software without specific prior written permission.

---------------------------------------------------------------------------
*** My main request is that you dont remove my name from the code base. ***
---------------------------------------------------------------------------

Author:
-------

        I am a CIT student with an emphasis in software development and I love
    coding and penetration testing, I hope one day to get this project on the
    kali linux iso. Offensive Security is awesome and I dream to one day work
    for/with them.
---------------------------------------------------------------------------

About:

    [+] - These programs are for Linux only, LINUX IS ABOVE ALL.
    [+] - These programs must be run as root. Absolutely must.
    [+] - Required programs:
        [-] - Airmon-ng > Soon to be removed. < HOPEFULLY
        [-] - figlet    > Cause pretty print.
        [-] - iwconfig  > May be removed in the future.
    [+] - Languages:
        [-] - Python2.7
        [-] - Shell

---------------------------------------------------------------------------
                                                With Love,
                                                M1ND-B3ND3R
""";
