import time
import thread

gALIVE = True
gDEAUTH = False
gSTARTTIME = time.time()
gFILTERCHANNEL = []
gKILLTIME = None

gDEAUTHS = {
    1: [], 2: [], 3: [], 4: [], 5: [], 6: [], 7: [], 8: [], 9: [], 10: [],
    11: [],

    36: [], 40: [], 44: [], 48: [], 52: [], 56: [],
    60: [], 64: [], 100: [], 104: [], 108: [], 112: [],
    116: [], 132: [], 136: [], 140: [], 149: [], 153: [],
    157: [], 161: [], 165: []
}      # int Channel, list of lists

gIGNORE = [
    "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00",                    # Multicast
    "01:80:c2:00:00:00",                    # Multicast
    "01:00:5e",                             # Multicast
    "01:80:c2",                             # Multicast
    "33:33"                                 # Multicast
]

def get_elapsed_time():
    # Create new time object based on time subtract start time
    time_elapsed = int(time.time() - gSTARTTIME)

    # Perform math to get elapsed time.
    hour = (time_elapsed / 3600)
    mins = (time_elapsed % 3600) / 60
    secs = (time_elapsed % 60)

    if gKILLTIME and time_elapsed > gKILLTIME:
        gALIVE = False
        thread.interrupt_main()

    if hour > 0:
        return "%d h %d m %d s" % (hour, mins, secs)
    elif mins > 0:
        return "%d m %d s" % (mins, secs)

    return "%d s" % secs
