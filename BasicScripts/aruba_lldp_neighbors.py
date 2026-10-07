#!/usr/bin/env python3
"""Pull "show ap lldp neighbors" from an Aruba controller and print it.

Standalone test script - NOT part of bunnyauto. Only needs `requests`.

    python BasicScripts/aruba_lldp_neighbors.py

Set CONTROLLER_URL below. Credentials come from ARUBA_USERNAME / ARUBA_PASSWORD
if set, otherwise you are prompted.
"""

import getpass
import json
import os

import requests
import urllib3

CONTROLLER_URL = "https://10.0.0.1:4343"  # your controller's address
VERIFY_TLS = False  # set True if the controller has a trusted certificate
COMMAND = "show ap lldp neighbors"


def main() -> None:
    username = os.environ.get("ARUBA_USERNAME") or input("Username: ").strip()
    password = os.environ.get("ARUBA_PASSWORD") or getpass.getpass("Password: ")

    if not VERIFY_TLS:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    with requests.Session() as session:
        session.verify = VERIFY_TLS
        # Ask for JSON (the controller sends HTML otherwise) and no compression
        # (some firmware mislabels its gzip encoding).
        session.headers.update({"Accept": "application/json", "Accept-Encoding": "identity"})

        login = session.post(
            f"{CONTROLLER_URL}/v1/api/login",
            data={"username": username, "password": password},
            timeout=15,
        )
        login.raise_for_status()
        token = login.json().get("_global_result", {}).get("UIDARUBA")
        if not token:
            raise SystemExit(f"Login failed:\n{login.text}")

        try:
            resp = session.get(
                f"{CONTROLLER_URL}/v1/configuration/showcommand",
                params={"command": COMMAND, "UIDARUBA": token},
                timeout=30,
            )
            print(f"HTTP {resp.status_code}")
            try:
                print(json.dumps(resp.json(), indent=2))
            except ValueError:
                print(resp.text)
        finally:
            try:
                session.post(
                    f"{CONTROLLER_URL}/v1/api/logout", params={"UIDARUBA": token}, timeout=15
                )
            except requests.RequestException:
                pass


if __name__ == "__main__":
    main()
