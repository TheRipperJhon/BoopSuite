import Globals.MyGlobals as confg
from Classes.classes import *
from tabulate import tabulate
from time import sleep
from os import system

def get_aps(AP):
	return [
		confg.APS[AP].mmac, confg.APS[AP].menc, confg.APS[AP].mch,
		confg.APS[AP].mven, confg.APS[AP].msig, confg.APS[AP].mbeacons,
		confg.APS[AP].mssid, confg.APS[AP].meapols
			];

def get_clients(cl):
	return [
		confg.CLS[cl].mmac.decode('utf-8'), confg.APS[confg.CLS[cl].mbssid].mmac,
		str(confg.CLS[cl].mnoise), str(confg.CLS[cl].mrssi),
		confg.APS[confg.CLS[cl].mbssid].mssid
			];

def get_un_clients():
	clients = [];
	for cl in confg.CLS:
		if len(confg.APS[confg.CLS[cl].mbssid].mssid) > 0:
			clients.append([
				confg.CLS[cl].mmac, confg.APS[confg.CLS[cl].mbssid].mmac,
				str(confg.CLS[cl].mnoise), str(confg.CLS[cl].mrssi),
				confg.APS[confg.CLS[cl].mbssid].mssid  ])
	return clients;

def printer_thread(configuration):
	typetable = "simple";

	while confg.FLAG:
		sleep(4);
		wifis = list(map(get_aps, confg.APS));
		wifis.sort(key=lambda x: x[6]);
		wifis.remove(wifis[0]);

		if configuration.__UN__ == True:					# print all clients no matter what
			clients = list(map(get_clients, confg.CLS));
		else:
			clients = get_un_clients();						# only print associated clients

		clients.sort(key=lambda x: x[4]);

		system('clear');

		print( "[+] Slithering On Channel: ["+str( configuration.__CC__ )+"]" );
		print( tabulate( wifis, headers=['M', 'E', 'Ch', 'V', 'S', 'B', 'SS', 'EAP'], tablefmt=typetable ));
		print( tabulate( clients, headers=['M', 'AP M', 'N', 'S', 'AP'], tablefmt=typetable ));
		sleep( 4 );
	return;
