#!/usr/bin/env python3

import sys
import subprocess
import os
from nornir import InitNornir


'''Hub to test Nornir Connectivity and easy script access'''


def nornir_hub():
    user_input = input(f"""
Please select one of the following:

    1.) Send command to devices
    2.) Perform backup


Input here: """)


    if user_input == "1":
        result = subprocess.run([sys.executable, "send_command.py"])
        print(result.stdout)
        print(result.stderr)
    elif user_input == "2":
        result = subprocess.run([sys.executable, "perform_backup.py"])
        print(result.stdout)
        print(result.stderr)
    elif user_input == "0":
        sys.exit("Have a nice day!")
    else:
        print("Not a valid choice")
        os.system('clear')
        nornir_hub()


def capabilitiescheck():

    username = os.getenv("NORNIR_USERNAME")
    password = os.getenv("NORNIR_PASSWORD")

    if not username or not password:
        print(
            "ERROR: NORNIR_USERNAME and NORNIR_PASSWORD "
            "must be set in the environment."
        )
        return 1

    try:
        nr = InitNornir(config_file="config.yaml")
    except Exception as exc:
        print(f"ERROR: Could not initialize Nornir/NetBox inventory: {exc}")
        return 1

    nr.inventory.defaults.username = username
    nr.inventory.defaults.password = password

if __name__ == "__main__":
    capabilitiescheck()
    #nornir_hub()