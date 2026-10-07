#!/usr/bin/env python3
"""Pull "show ap lldp neighbors" from an Aruba controller and print it as JSON.

Standalone test script - NOT part of bunnyauto. Only needs `requests`.

    python BasicScripts/aruba_lldp_neighbors.py
    python BasicScripts/aruba_lldp_neighbors.py > lldp.json

Set CONTROLLER_URL below. Credentials come from ARUBA_USERNAME / ARUBA_PASSWORD
if set, otherwise you are prompted.

Some controllers (seen on a 9240, AOS 8) answer this command in XML wrapped in
<my_xml_tag3xxx> instead of JSON, whatever the Accept header says. That reply
is converted to the same shape: one list of row dicts per table, keyed by the
column names. Only the JSON goes to stdout; status lines go to stderr.
"""

import getpass
import json
import os
import sys
import xml.etree.ElementTree as ET

import requests
import urllib3

CONTROLLER_URL = "https://10.0.0.1:4343"  # your controller's address
VERIFY_TLS = False  # set True if the controller has a trusted certificate
COMMAND = "show ap lldp neighbors"


def xml_to_json(text: str) -> dict:
    """Convert the controller's XML reply to the shape its JSON replies use.

    Each <t> table becomes a list of row dicts under its title (tn); the table's
    first <r> holds the column names. Non-empty <data> lines (the capability-codes
    legend) go under "_data", where the JSON replies put plain-text lines.
    """
    root = ET.fromstring(text)
    result = {}
    for table in root.iter("t"):
        rows = [[(c.text or "").strip() for c in r.findall("c")] for r in table.findall("r")]
        if not rows:
            continue
        header, *body = rows
        for cells in body:
            if len(cells) != len(header):
                print(
                    f"warning: row has {len(cells)} cells, header {len(header)}: {cells}",
                    file=sys.stderr,
                )
        result[table.get("tn", "table")] = [dict(zip(header, cells, strict=False)) for cells in body]
    data = [d.text.strip() for d in root.iter("data") if d.text and d.text.strip()]
    if data:
        result["_data"] = data
    return result


def to_json(resp: requests.Response) -> dict | None:
    """The reply as JSON data (converting the XML form), or None if it's neither."""
    try:
        return resp.json()
    except ValueError:
        pass
    if not resp.text.lstrip().startswith("<"):
        return None
    try:
        result = xml_to_json(resp.text)
    except ET.ParseError as exc:
        print(f"Reply looked like XML but could not be parsed: {exc}", file=sys.stderr)
        return None
    print("Controller replied in XML; converted to JSON.", file=sys.stderr)
    return result


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
            print(f"HTTP {resp.status_code}", file=sys.stderr)
            body = to_json(resp)
            if body is None:
                print(resp.text)
            else:
                print(json.dumps(body, indent=2))
        finally:
            try:
                session.post(
                    f"{CONTROLLER_URL}/v1/api/logout", params={"UIDARUBA": token}, timeout=15
                )
            except requests.RequestException:
                pass


if __name__ == "__main__":
    main()
