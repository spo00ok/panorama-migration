#!/usr/bin/env python3
"""
panorama_security_rules_to_csv.py

Fetch Panorama security policies for each device group and expand them
into logical rule rows in CSV format.

Usage examples:
  python panorama_security_rules_to_csv.py --host https://panorama.example.com --api-key <KEY> -o rules.csv
  python panorama_security_rules_to_csv.py --host https://panorama.example.com --username admin --password 'secret' -o rules.csv
"""

import argparse
import csv
import os
import sys
import time
import itertools
from typing import List, Dict, Any, Optional
import xml.etree.ElementTree as ET

import requests

requests.packages.urllib3.disable_warnings()  # suppress SSL warnings for self-signed systems


# ---------------------------
# Helpers for Panorama XML API
# ---------------------------

def api_call(host: str, params: Dict[str, str], timeout: int = 30, verify_ssl: bool = False) -> ET.Element:
    """Make an XML API call and return the root Element. Raises on error."""
    url = f"{host.rstrip('/')}/api/"
    try:
        r = requests.get(url, params=params, timeout=timeout, verify=verify_ssl)
        r.raise_for_status()
    except requests.RequestException as e:
        raise SystemExit(f"HTTP error calling Panorama API: {e}")

    try:
        root = ET.fromstring(r.text)
    except ET.ParseError as e:
        raise SystemExit(f"Failed to parse Panorama XML response: {e}\nResponse was:\n{r.text[:1000]}...")

    status = root.attrib.get("status", "error")
    if status != "success":
        msg = root.findtext(".//msg")
        raise SystemExit(f"Panorama API returned status '{status}': {msg or 'No message'}")
    return root


def get_api_key(host: str, username: str, password: str, verify_ssl: bool = False) -> str:
    """Generate an API key from username/password."""
    params = {
        "type": "keygen",
        "user": username,
        "password": password,
    }
    root = api_call(host, params, verify_ssl=verify_ssl)
    key = root.findtext(".//key")
    if not key:
        raise SystemExit("Could not obtain API key from Panorama.")
    return key


def api_get_xpath(host: str, key: str, xpath: str, verify_ssl: bool = False) -> ET.Element:
    """GET config via xpath."""
    params = {
        "type": "config",
        "action": "get",
        "key": key,
        "xpath": xpath,
    }
    return api_call(host, params, verify_ssl=verify_ssl)


# ---------------------------
# Parsing utilities
# ---------------------------

def _members_or_any(parent: Optional[ET.Element], tag: str) -> List[str]:
    """Return list of <member> values under <tag>. If none present, return ['any']."""
    if parent is None:
        return ["any"]
    node = parent.find(tag)
    if node is None:
        return ["any"]
    members = [m.text for m in node.findall("member") if m.text]
    # Some configs store single value without <member>, e.g., <service>any</service>
    if not members:
        raw = node.text.strip() if node.text else ""
        if raw:
            return [raw]
        return ["any"]
    return members or ["any"]


def _text_or_blank(parent: Optional[ET.Element], tag: str) -> str:
    node = parent.find(tag) if parent is not None else None
    return (node.text or "").strip() if node is not None and node.text else ""


def parse_rule_entry(entry: ET.Element) -> Dict[str, Any]:
    """Extract rule fields needed for CSV and expansion."""
    name = entry.attrib.get("name", "")
    desc = _text_or_blank(entry, "description")
    target = entry.find("target")
    disabled = _text_or_blank(entry, "disabled") or "no"
    action = _text_or_blank(entry, "action") or "allow"
    log_setting = _text_or_blank(entry, "log-setting")
    schedule = _text_or_blank(entry, "schedule")
    negate_source = _text_or_blank(entry, "negate-source") or "no"
    negate_destination = _text_or_blank(entry, "negate-destination") or "no"
    tags = _members_or_any(entry, "tag")
    if tags == ["any"]:
        tags = []  # tags "any" is not meaningful; keep empty for CSV

    # Profiles (profile-setting/group/member)
    profile_group_members = []
    ps = entry.find("profile-setting")
    if ps is not None:
        group = ps.find("group")
        if group is not None:
            profile_group_members = [m.text for m in group.findall("member") if m.text]

    # Match fields for expansion
    match_fields = {
        "from": _members_or_any(entry, "from"),
        "to": _members_or_any(entry, "to"),
        "source": _members_or_any(entry, "source"),
        "destination": _members_or_any(entry, "destination"),
        "source-user": _members_or_any(entry, "source-user"),
        "application": _members_or_any(entry, "application"),
        "service": _members_or_any(entry, "service"),
        "url-category": _members_or_any(entry, "category"),
    }

    return {
        "name": name,
        "description": desc,
        "tags": tags,
        "disabled": disabled,
        "action": action,
        "log_setting": log_setting,
        "schedule": schedule,
        "negate_source": negate_source,
        "negate_destination": negate_destination,
        "profile_groups": profile_group_members,
        "match_fields": match_fields,
        # Preserve full XML node if needed later
        "_entry": entry,
    }


def explode_logical_rows(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Create Cartesian product rows across key match fields."""
    mf = rule["match_fields"]
    keys = ["from", "to", "source", "destination", "source-user", "application", "service", "url-category"]

    # Normalize empty lists to ['any'] just in case
    values = [mf.get(k) or ["any"] for k in keys]

    rows = []
    for combo in itertools.product(*values):
        row = dict(zip(keys, combo))
        rows.append(row)
    return rows


# ---------------------------
# Fetch device groups & rules
# ---------------------------

def list_device_groups(host: str, key: str, verify_ssl: bool = False) -> List[str]:
    """Return the names of all device groups."""
    xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
    root = api_get_xpath(host, key, xpath, verify_ssl=verify_ssl)
    dgs = []
    for dg in root.findall(".//device-group/entry"):
        name = dg.attrib.get("name")
        if name:
            dgs.append(name)
    # Some PAN-OS versions return directly under the entry:
    if not dgs:
        dgs = [e.attrib.get("name") for e in root.findall(".//entry") if e.attrib.get("name")]
    return sorted(dgs)


def fetch_rules_for_dg(host: str, key: str, dg: str, verify_ssl: bool = False) -> Dict[str, List[ET.Element]]:
    """
    Fetch security rule entries for a device-group across pre, post, and local rulebases.
    Returns: {"pre": [entry...], "post": [...], "local": [...]}
    """
    base = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dg}']"

    paths = {
        "pre": f"{base}/pre-rulebase/security/rules",
        "post": f"{base}/post-rulebase/security/rules",
        "local": f"{base}/rulebase/security/rules",
    }

    results: Dict[str, List[ET.Element]] = {"pre": [], "post": [], "local": []}
    for rb, xp in paths.items():
        try:
            root = api_get_xpath(host, key, xp, verify_ssl=verify_ssl)
            entries = root.findall(".//rules/entry")
            # Fallback if structure differs slightly:
            if not entries:
                entries = root.findall(".//entry")
            results[rb] = entries
        except SystemExit as e:
            # If a particular path doesn't exist (e.g., no local rules), skip gracefully
            if "The XPath value is invalid" in str(e) or "No such node" in str(e):
                results[rb] = []
            else:
                raise
    return results


# ---------------------------
# CSV writing
# ---------------------------

CSV_HEADERS = [
    "device_group", "rulebase", "rule_name", "description", "tags",
    "disabled", "action", "log_setting", "schedule",
    "negate_source", "negate_destination",
    "profile_groups",
    "from", "to", "source", "destination", "source-user", "application", "service", "url-category",
]


def write_rules_csv(
    host: str,
    key: str,
    outfile: str,
    verify_ssl: bool = False,
) -> None:
    dgs = list_device_groups(host, key, verify_ssl=verify_ssl)
    if not dgs:
        print("No device groups found.", file=sys.stderr)
        return

    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()

        for dg in dgs:
            rb_map = fetch_rules_for_dg(host, key, dg, verify_ssl=verify_ssl)

            for rulebase, entries in rb_map.items():
                for entry in entries:
                    rule = parse_rule_entry(entry)
                    combos = explode_logical_rows(rule)

                    for c in combos:
                        row = {
                            "device_group": dg,
                            "rulebase": rulebase,
                            "rule_name": rule["name"],
                            "description": rule["description"],
                            "tags": ";".join(rule["tags"]) if rule["tags"] else "",
                            "disabled": rule["disabled"],
                            "action": rule["action"],
                            "log_setting": rule["log_setting"],
                            "schedule": rule["schedule"],
                            "negate_source": rule["negate_source"],
                            "negate_destination": rule["negate_destination"],
                            "profile_groups": ";".join(rule["profile_groups"]) if rule["profile_groups"] else "",
                            # exploded match fields:
                            "from": c["from"],
                            "to": c["to"],
                            "source": c["source"],
                            "destination": c["destination"],
                            "source-user": c["source-user"],
                            "application": c["application"],
                            "service": c["service"],
                            "url-category": c["url-category"],
                        }
                        writer.writerow(row)


# ---------------------------
# CLI
# ---------------------------

def main():
    parser = argparse.ArgumentParser(description="Export Panorama security policies as exploded logical rules CSV.")
    parser.add_argument("--host", required=True, help="Panorama base URL, e.g., https://panorama.example.com")
    parser.add_argument("--api-key", help="Panorama API key (optional if username/password provided)")
    parser.add_argument("--username", help="Panorama username (used to keygen if api-key not supplied)")
    parser.add_argument("--password", help="Panorama password (used to keygen if api-key not supplied)")
    parser.add_argument("-o", "--output", default=f"panorama_rules_{int(time.time())}.csv", help="Output CSV file path")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates (default: disabled)")
    args = parser.parse_args()

    host = args.host
    verify_ssl = args.verify_ssl

    key = args.api_key or os.getenv("PANORAMA_API_KEY")
    if not key:
        if not (args.username and args.password):
            print("Provide --api-key or --username/--password.", file=sys.stderr)
            sys.exit(2)
        key = get_api_key(host, args.username, args.password, verify_ssl=verify_ssl)

    try:
        write_rules_csv(host, key, args.output, verify_ssl=verify_ssl)
    except SystemExit as e:
        # SystemExit is used above for controlled API errors; re-raise to nonzero exit
        print(str(e), file=sys.stderr)
        sys.exit(1)

    print(f"Done. Wrote CSV to: {args.output}")


if __name__ == "__main__":
    main()
