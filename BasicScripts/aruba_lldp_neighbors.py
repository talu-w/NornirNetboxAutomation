#!/usr/bin/env python3
"""Pull "show ap lldp neighbors" from an Aruba controller and print it."""

import argparse
import getpass
import html
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from xml.sax.saxutils import escape

import requests
import urllib3

CONTROLLER_URL = "https://10.0.0.1:4343"  # your controller's address
VERIFY_TLS = False  # set True if the controller has a trusted certificate
COMMAND = "show ap lldp neighbors"
TIMEOUT = 600  # seconds; a large controller's XML reply is slow

# The pieces of the XML reply, found by pattern rather than with an XML parser:
# the controller doesn't escape '<' or '&' inside values, so one odd port
# description makes the whole reply invalid XML.
_TABLE = re.compile(r"<t\b([^>]*)>(.*?)</t>", re.S)
_ROW = re.compile(r"<r\b[^>]*>(.*?)</r>", re.S)
_CELL = re.compile(r"<c\b[^>]*/>|<c\b[^>]*>(.*?)</c>", re.S)
_DATA = re.compile(r"<data\b[^>]*>(.*?)</data>", re.S)
_TITLE = re.compile(r'\btn="([^"]*)"')


@dataclass
class Table:
    title: str  # the tn attribute
    attrs: str  # the <t> tag's attributes, as received
    header: list[str]  # the first <r>: column names
    rows: list[list[str]]  # every later <r>: one value per column


def _text(raw: str) -> str:
    return html.unescape(raw).strip()


def parse_xml(text: str) -> tuple[list[Table], list[str]]:
    """The XML reply's tables, and its non-empty <data> lines."""
    tables = []
    for attrs, inner in _TABLE.findall(text):
        rows = [[_text(c) for c in _CELL.findall(row)] for row in _ROW.findall(inner)]
        if not rows:
            continue
        title = _TITLE.search(attrs)
        table = Table(_text(title.group(1)) if title else "table", attrs, rows[0], rows[1:])
        for cells in table.rows:
            if len(cells) != len(table.header):
                print(
                    f"warning: row has {len(cells)} values, header {len(table.header)}: {cells}",
                    file=sys.stderr,
                )
        tables.append(table)
    data = [line for line in (_text(raw) for raw in _DATA.findall(text)) if line]
    return tables, data


def as_json(tables: list[Table], data: list[str]) -> dict:
    """The shape the controller's JSON replies use: rows keyed by column name."""
    result = {
        t.title: [dict(zip(t.header, cells, strict=False)) for cells in t.rows] for t in tables
    }
    if data:
        result["_data"] = data
    return result


def as_labelled_xml(tables: list[Table], data: list[str]) -> str:
    """The XML reply re-indented, one value per line, each labelled with its column."""
    out = ["<my_xml_tag3xxx>", "  <re>"]
    for t in tables:
        out.append(f"    <t{t.attrs}>")
        out.append("      <r>  <!-- column names -->")
        out += [f"        <c>{escape(name)}</c>" for name in t.header]
        out.append("      </r>")
        for cells in t.rows:
            out.append("      <r>")
            for i, value in enumerate(cells):
                column = t.header[i] if i < len(t.header) else "NO COLUMN"
                out.append(f"        <c>{escape(value)}</c>  <!-- {column} -->")
            out.append("      </r>")
        out.append("    </t>")
    out += [f"    <data>{escape(line)}</data>" for line in data]
    out += ["  </re>", "</my_xml_tag3xxx>"]
    return "\n".join(out)


def report_bad_xml(text: str) -> None:
    """If the reply isn't valid XML, show the text around where it breaks."""
    try:
        ET.fromstring(text)
    except ET.ParseError as exc:
        line, column = exc.position
        offset = sum(len(s) for s in text.splitlines(keepends=True)[: line - 1]) + column
        before = text[max(0, offset - 300) : offset]
        after = text[offset : offset + 300]
        print(
            f"The XML is invalid ({exc}); read it leniently. It breaks at >>>HERE<<<:",
            file=sys.stderr,
        )
        print(f"  ...{before}>>>HERE<<<{after}...", file=sys.stderr)


def show(resp: requests.Response, labelled_xml: bool) -> None:
    """Print the reply: JSON as-is; XML as JSON, or as labelled XML."""
    try:
        print(json.dumps(resp.json(), indent=2))
        return
    except ValueError:
        pass
    text = resp.text
    if not text.lstrip().startswith("<"):
        print(text)
        return
    print("Controller replied in XML.", file=sys.stderr)
    report_bad_xml(text)
    tables, data = parse_xml(text)
    for t in tables:
        print(f"{len(t.rows)} rows in {t.title!r}", file=sys.stderr)
    print(
        as_labelled_xml(tables, data)
        if labelled_xml
        else json.dumps(as_json(tables, data), indent=2)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--xml",
        action="store_true",
        help="when the controller replies in XML, print it re-indented with each value "
        "labelled by its column, instead of as JSON",
    )
    args = parser.parse_args()

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
                timeout=TIMEOUT,
            )
            print(f"HTTP {resp.status_code}", file=sys.stderr)
            show(resp, args.xml)
        finally:
            try:
                session.post(
                    f"{CONTROLLER_URL}/v1/api/logout", params={"UIDARUBA": token}, timeout=15
                )
            except requests.RequestException:
                pass


if __name__ == "__main__":
    main()
