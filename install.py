#!/usr/bin/env python

import os
import sys
import time
import random
import string
import subprocess

WARNINGS = 0


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def Check_Root():
    if os.getuid() != 0:
        print(bcolors.FAIL+"[-] Must be run as root."+bcolors.ENDC)
        sys.exit(0)
    return 0


def Find_Package_Manager():
    Package_Managers = ["apt-get", "pacman", "yum"]

    for manager in Package_Managers:
        Default_Package_Manager = os.popen("which "+manager).read()
        if Default_Package_Manager not in range(0, 300):
            return Default_Package_Manager.split("/")[-1].strip()

    print(bcolors.FAIL+"[-] No Default Package Manager Found"+bcolors.ENDC)
    sys.exit(0)


def Install_Packages(Package_Manager):
    global WARNINGS
    Packages_To_Install = [
        "libncap-dev", "tcpdump",
        "python-gnuplot", "python-crypto"
        ]
    Failed_Packages = []

    for package in Packages_To_Install:
        try:
            subprocess.check_output([Package_Manager, "install", package, "-y"], stderr=subprocess.STDOUT)
            print(bcolors.OKGREEN+"[+] Installed: "+package+bcolors.ENDC)
        except subprocess.CalledProcessError as e:
            Failed_Packages.append( package )
            WARNINGS += 1

    if len(Failed_Packages) > 0:
        for item in Failed_Packages:
            print(bcolors.WARNING+"[-] Failed to install Package: "+item+bcolors.ENDC)
    return


def Create_Custom_Command():

    links = [
        "/usr/local/bin/boopsniff",
        "/usr/local/bin/boopsniff_gui",
        "/usr/local/bin/boop",
        "/usr/local/bin/boopstrike"]
    new_links = [
        "/usr/share/Packet-Sniffer/boopsniff.py",
        "/usr/share/Packet-Sniffer/boopsniff_gui.py",
        "/usr/share/Monitor/boop.py",
        "/usr/share/Deauth/boopstrike.py"]

    dirs = [
        "/usr/share/Packet-Sniffer/",
        "/usr/share/Monitor/",
        "/usr/share/Deauth"]

    for dire in dirs:
        if os.path.isdir(dire):
            os.system("sudo rm -rf "+dire)
            print(bcolors.OKGREEN+"[+] Removed Old Project Directory"+bcolors.ENDC)

    try:
        subprocess.check_output(["sudo", "cp", "-r", "Packet-Sniffer/", "/usr/share/"], stderr=subprocess.STDOUT)
        subprocess.check_output(["sudo", "cp", "-r", "Monitor/", "/usr/share/"], stderr=subprocess.STDOUT)
        subprocess.check_output(["sudo", "cp", "-r", "Deauth/", "/usr/share/"], stderr=subprocess.STDOUT)
        print(bcolors.OKGREEN+"[+] Installed Tools to: /usr/share/"+bcolors.ENDC)
    except subprocess.CalledProcessError as e:
        print(e.output)

    for link in links:
        if os.path.islink(link):
            os.system("sudo rm -f "+link)
            print(bcolors.OKGREEN+"[+] Removed an old command"+bcolors.ENDC)

    for index, value in enumerate(new_links):
        try:
            subprocess.check_output(["sudo", "ln", "-s", new_links[index], links[index]], stderr=subprocess.STDOUT)
            subprocess.check_output(["sudo", "chmod", "755", links[index]], stderr=subprocess.STDOUT)
            print(bcolors.OKGREEN+"[+] Created New Command"+bcolors.ENDC)
        except subprocess.CalledProcessError as e:
            print(bcolors.FAIL+"[-] Failed During custom command creation.")

    return 0


def install():
    global WARNINGS

    Check_Root()

    print(bcolors.OKBLUE+"""
,_,_,_,_,_,_,_,_,_,_|____________________BOOP-INSTALLER____________________
|#|#|#|#|#|#|#|#|#|#|_____________________________________________________/
'-'-'-'-'-'-'-'-'-'-|----------------------------------------------------'
                                          M1ND-B3ND3R
    """+bcolors.ENDC)

    Package_Manager = Find_Package_Manager()
    Install_Packages(Package_Manager)
    Create_Custom_Command()

    print(bcolors.HEADER+"[+] Exiting with: "+str(WARNINGS)+" warnings and 0 Failures.")


if __name__ == "__main__":
    install()
