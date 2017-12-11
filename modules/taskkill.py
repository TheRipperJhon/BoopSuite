import os


def kill_blocking_tasks():

    task_list = [
        "service avahi-daemon stop", "service network-manager stop",
        "pkill wpa_supplicant", "pkill dhclient"]

    for item in task_list:
        os.system(item)

    return
