import sys
import os

def set_size(height, width):
	"""
		Sets the terminal size to be able to handle all the output.
	"""
	sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=height, cols=width));
	return;

def display_art():
	"""
		A function to print out a welcome message.
		Need to make it so it doesn't use figlet.
	"""
	print("""
    ____                   _____       _ ________
   / __ )____  ____  ____ / ___/____  (_) __/ __/
  / __  / __ \/ __ \/ __ \\__ \/ __ \/ / /_/ /_
 / /_/ / /_/ / /_/ / /_/ /__/ / / / / / __/ __/
/_____/\____/\____/ .___/____/_/ /_/_/_/ /_/
                 /_/
	""");
	print("\tCodename: Malabar Viper\r\n")
	return;
