import argparse
import os
import getpass
import sys
import pyric.pyw as pyw

class Configuration:
	def __init__(self):
		self.check_root();
		self.check_op();

		self.__REPORT__ = False;
		self.__PRINT__  = True;
		self.__HOP__    = False;
		self.__KILL__   = None;
		self.__FREQ__   = "2";
		self.__FACE__   = None;
		self.__UN__     = False;
		self.__CC__     = None;
		return;

	def user_force_variables_static(self):
		"""
			Use this area as a user to FORCE a configuration
			variable to always be true no matter what.
			- Overrides parsed args.
			- self.__KILL__ wont work for fairly obvious reasons if you read the code.
			- May break due to effects taking place after the checks.
			- *USE CAREFULLY*
		"""
		# self.__PRINT__ = False;
		return;

	def parse_interface(self, interface):
		if interface in pyw.interfaces() and pyw.modeget(interface) == "monitor":
			self.__FACE__ = interface;
		else:
			sys.exit();
		return;

	def parse_report(self, report):
		if report != False:
			try:
		 		self.__REPORT__ = open(report, "w");
		 	except:
		 		sys.exit();

	def parse_freq(self, freq):
		self.__FREQ__ = freq;
		return;

	def parse_channel(self, channel):
		if not channel:
			self.__HOP__ = True;
			return;

		elif self.__FREQ__ == "2":
			if int(channel) in range(1, 12):
				self.__CC__ = channel
			else:
				sys.exit();

		elif self.__FREQ__ == "5":
			__5ghz__channels__ = [  36, 40, 44, 48, 52, 56, 60, 64, 100,
									104, 108, 112, 116, 132, 136, 140,
									149, 153, 157, 161, 165              ];
			if int(channel) in __5ghz__channels__:
				self.__CC__ = channel
			else:
				sys.exit();
		return;

	def parse_kill(self, kill):
		if kill:
			tasklist = [
						"service avahi-daemon stop",
						"stop network-manager",
						"pkill wpa_supplicant",
						"pkill dhclient"
						];

			for item in tasklist:
				try:
					os.system("sudo "+item);
				except:
					pass
		return;

	def parse_unassociated(self, un):
		if un == True:
			self.__UN__ = True;
		else:
			self.__UN__ = False;
		return

	def parse_args(self):
		parser = argparse.ArgumentParser();
		# REQUIRED
		parser.add_argument('-i', action='store', dest='interface', help='select an interface', required=True);

		# OPTIONAL
		parser.add_argument('-r', action='store', default=False, dest='report', help='select a report location');
		parser.add_argument('-f', action='store', default='2',  dest='freq', help='select a frequency (2/5)', choices=["2", "5"]);
		parser.add_argument('-c', action='store', default=None, dest='channel', help='select a channel');

		# FLAGS
		parser.add_argument('-k', action='store_true', dest='kill', help='sudo kill interfering processes.');
		parser.add_argument('-u', action='store_true', dest='unassociated', help='Whether to show unassociated clients.');

		results = parser.parse_args();

		self.parse_interface(results.interface);
		self.parse_report(results.report);
		self.parse_freq(results.freq);
		self.parse_channel(results.channel);
		self.parse_kill(results.kill);
		self.parse_unassociated(results.unassociated);

		self.user_force_variables_static();
		return;

	def check_root(self):
		if os.getuid() != 0:
			sys.exit();
		print("		 /----------->");
		print("		|[+] Running as:  " + getpass.getuser());
		return

	def check_op(self):
		if os.uname()[0].startswith("Linux") and not 'Darwin' not in os.uname()[0]:
			sys.exit();

		print("		|[+] Detected os: " + str(os.uname()[0]));
		print("		|[+] Hostname:    " + str(os.uname()[1]));
		print("		 \----------->");
		return;

class Access_Point:
	def __init__(self, ssid, enc, ch, mac, ven, sig):

		self.mssid = str(ssid)[:20]

		if "WPA2" in enc and "WPA" in enc:
			self.menc  = "WPA2"
			if "WPS" in enc:
				self.menc +=":WPS"
		else:
			self.menc = enc
		self.mch   = str(ch)
		self.mmac  = mac
		self.mven  = ven[:8]
		self.msig  = sig
		self.mbeacons = 1;

		return

	def update_sig(self, sig):
		self.msig = sig
		return

	def update_ssid(self, ssid):
		self.mssid = ssid
		return

class Client:
	def __init__(self, mac, bssid, rssi):
		self.mmac   = mac
		self.mbssid = bssid
		self.mrssi = rssi

		self.mnoise = 0
		return

	def update_network(self, bssid):
		self.mbssid = bssid
		return
