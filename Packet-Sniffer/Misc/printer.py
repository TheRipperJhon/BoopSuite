import Globals.MyGlobals as confg
from Classes.classes import *
from tabulate import tabulate
from time import sleep
from os import system

def get_aps(AP):
	"""
		A function to gather all AP info for displaying.
	"""
	return [
		confg.APS[AP].mmac, confg.APS[AP].menc, confg.APS[AP].mch,
		confg.APS[AP].mven, confg.APS[AP].msig, confg.APS[AP].mbeacons,
		confg.APS[AP].mssid, confg.APS[AP].mfound
			];

def get_clients(cl):
	"""
		A function to gather all clients that are associated.
	"""
	return [
		confg.CLS[cl].mmac, confg.APS[confg.CLS[cl].mbssid].mmac,
		str(confg.CLS[cl].mnoise), str(confg.CLS[cl].mrssi),
		confg.APS[confg.CLS[cl].mbssid].mssid
			];

def get_un_clients():
	"""
		A function to gather all clients no matter what.
	"""
	clients = [];
	for cl in confg.CLS:
		if len(confg.APS[confg.CLS[cl].mbssid].mssid) > 0:
			clients.append([
				confg.CLS[cl].mmac, confg.APS[confg.CLS[cl].mbssid].mmac,
				str(confg.CLS[cl].mnoise), str(confg.CLS[cl].mrssi),
				confg.APS[confg.CLS[cl].mbssid].mssid  ])
	return clients;

def printer_thread(configuration):
	"""
		A thread to manage displayed information.
	"""
	typetable = "simple";
	sleep(4);
	system('clear');

	while confg.FLAG:
		wifis = list(map(get_aps, confg.APS));
		wifis.sort(key=lambda x: x[6]);
		wifis.remove(wifis[0]);

		if configuration.__UN__ == True:					# print all clients no matter what
			clients = list(map(get_clients, confg.CLS));
		else:
			clients = get_un_clients();						# only print associated clients

		clients.sort(key=lambda x: x[4]);

		system('clear');
		if configuration.__HOP__ == True:
			print( "[+] Slithering On Channel: ["+str( configuration.__CC__ )+"]" );
			print( tabulate( wifis, headers=['M', 'E', 'Ch', 'V', 'S', 'B', 'SS', 'Key'], tablefmt=typetable ));
			print( tabulate( clients, headers=['M', 'AP M', 'N', 'S', 'AP'], tablefmt=typetable ));
		else:
			print( tabulate( wifis, headers=['M', 'E', 'Ch', 'V', 'S', 'B', 'SS', 'Key'], tablefmt=typetable ));
			print("");
			print( tabulate( clients, headers=['M', 'AP M', 'N', 'S', 'AP'], tablefmt=typetable ));

		sleep( 6 );
	return;
