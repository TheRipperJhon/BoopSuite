import sys
import os

def set_size(height, width):
	sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=height, cols=width));
	return;

def display_art():
	os.system("figlet -f slant 'BoopSniff'");
	print("\r\n\tCodename: Malabar Viper\r\n")
	return;
