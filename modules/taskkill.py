import os


def kill_blocking_tasks():
    """
    Kill Tasks that may interfere with the sniffer or deauth script

    Keyword arguments:
        -
    Return:
        -

    Author:
        Jarad Dingman
    """

    task_list = [
        "service avahi-daemon stop",
        "service network-manager stop",
        "pkill wpa_supplicant",
        "pkill dhclient"]

    for item in task_list:

        os.system(item)

    return
