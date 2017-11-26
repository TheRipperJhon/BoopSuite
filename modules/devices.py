#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pyric.pyw as pyw

import globalsx

'''
    if the method has:

        "card" as an arg then it requires a Card object

        "interface" as an arg it requires an interface name
'''


def get_devices():
    return pyw.winterfaces()


def get_device(interface):
    return pyw.getcard(interface)


def get_mode(interface):
    return pyw.modeget(interface)


def get_mon_devices():
    return [x for x in pyw.winterfaces() if pyw.modeget(x) == "monitor"]


def get_channel(interface):
    return pyw.chget(pyw.getcard(interface))


def set_channel(card, channel):
    return pyw.chset(card, channel, None)


def get_mac(card):
    return pyw.macget(card)


def set_mac(interface, mac):
    return pyw.macset(interface, mac)


def card_down(card):
    return pyw.down(card)


def card_up(card):
    return pyw.up(card)


def get_info(card):
    return pyw.ifinfo(card)


def get_phy_info(card):
    return pyw.phyinfo(card)


def check_valid_mac(mac=None):

    if not mac:
        return False

    else:
        if len([y for y in globalsx.gIGNORE if mac.startswith(y)]) > 0:
            return False

    return True


def set_monitor_mode(card, name):
    '''
        Function to set card to monitor mode

        author: Jarad
    '''

    if name and len(name) > 3:
        newcard = pyw.devset(card, name)

    else:
        newcard = pyw.devset(card, card.dev + "mon")

    pyw.modeset(newcard, 'monitor')

    return newcard


def set_managed_mode(card, name):
    '''
        Function to set card to managed mode

        author: Jarad
    '''

    if name and len(name) > 3:
        newcard = pyw.devset(card, name)

    else:
        newcard = pyw.devset(card, card.dev[:-3])

    pyw.modeset(newcard, 'managed')

    return newcard
