import os
import shutil
import time


def countdown(msg, delta):
    for i in range(delta, 0, -1):
        print(f"{msg} {delta}")
        time.sleep(1)


def init_env():
    tcfs_folder = "~/.tcfs"
    data_folder = tcfs_folder + "/data"

    if os.path.exists(tcfs_folder) and os.path.isdir(tcfs_folder):
        print("WARN: Deleting main tcfs folder, all your data will be lost")
        countdown("\r Deleting in ....", 5)
