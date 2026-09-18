#!/usr/bin/env python3
"""Standalone Aruba Conductor URL/param scratch tool.

NOT part of bunnyauto — no imports from that package, no Nornir. Just
requests + json, for poking at Conductor REST endpoints and seeing what
comes back. Run it directly:

    python aruba_url_playground.py

You'll be prompted for the Conductor URL and credentials, then dropped into
a loop where you type a path + query params and get the raw JSON response,
both printed and saved to a file.
"""

import getpass
import json
import sys
from datetime import datetime
from pathlib import Path

import requests
import urllib3

OUTPUT_DIR = Path("aruba_url_playground_output")


def login(session: requests.Session, base_url: str, username: str, password: str, verify: bool) -> str:
    resp = session.post(
        f"{base_url}/v1/api/login",
        data={"username": username, "password": password},
        verify=verify,
        timeout=15,
    )
    resp.raise_for_status()
    payload = resp.json()
    token = str(payload.get("_global_result", {}).get("UIDARUBA") or "").strip()
    if not token:
        raise SystemExit(f"Login did not return a UIDARUBA token. Response:\n{json.dumps(payload, indent=2)}")
    return token


def logout(session: requests.Session, base_url: str, token: str, verify: bool) -> None:
    try:
        session.post(f"{base_url}/v1/api/logout", params={"UIDARUBA": token}, verify=verify, timeout=15)
    except requests.RequestException:
        pass


def parse_params(raw: str) -> dict:
    params = {}
    if not raw.strip():
        return params
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            print(f"  (skipping {pair!r} — expected key=value)")
            continue
        key, value = pair.split("=", 1)
        params[key.strip()] = value.strip()
    return params


def main() -> None:
    base_url = input("Conductor base URL (e.g. https://10.0.0.1:4343): ").strip().rstrip("/")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    verify_input = input("Verify TLS cert? [Y/n]: ").strip().lower()
    verify = verify_input != "n"
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    # The Conductor returns HTML instead of JSON unless the client explicitly
    # asks for JSON — the login POST stays form-encoded (Content-Type: application/json
    # there would mislabel the form body), but every GET explicitly requests JSON.
    session.headers.update({"Accept": "application/json"})

    print("\nLogging in...")
    token = login(session, base_url, username, password, verify)
    print(f"Logged in. UIDARUBA={token}")

    OUTPUT_DIR.mkdir(exist_ok=True)
    request_count = 0

    try:
        while True:
            print("\n--- new request (blank path to quit) ---")
            path = input("Path (e.g. /v1/configuration/showcommand): ").strip()
            if not path:
                break

            raw_params = input("Extra query params as key=value,key2=value2 (UIDARUBA is added automatically): ")
            params = parse_params(raw_params)
            params["UIDARUBA"] = token

            url = f"{base_url}{path}"
            print(f"\nGET {url}")
            print(f"params: {params}")

            try:
                resp = session.get(
                    url,
                    params=params,
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    verify=verify,
                    timeout=30,
                )
            except requests.RequestException as exc:
                print(f"Request failed: {exc}")
                continue

            print(f"Status: {resp.status_code}")

            try:
                body = resp.json()
            except ValueError:
                body = {"_non_json_response_text": resp.text}

            request_count += 1
            record = {
                "request": {"url": url, "params": params},
                "status_code": resp.status_code,
                "response": body,
            }

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = OUTPUT_DIR / f"{timestamp}_{request_count:02d}.json"
            with out_file.open("w") as f:
                json.dump(record, f, indent=2)

            print(f"Saved to {out_file}")
            print(json.dumps(body, indent=2)[:2000])
    finally:
        print("\nLogging out...")
        logout(session, base_url, token, verify)
        session.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
