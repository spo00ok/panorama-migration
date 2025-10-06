#!/usr/bin/env python3
"""
compile_access_from_rules.py

Given:
  1) A CSV produced by panorama_security_rules_to_csv.py (one logical row per combo)
  2) A list of IPs (file or command-line)
  3) Optionally: address objects and groups exported to CSV

Produce:
  A CSV listing, for each IP, the rules that match it as source and/or destination.

Matching logic:
- 'any' matches everything
- literal IP (e.g., 10.1.2.3) and CIDR (e.g., 10.1.0.0/16) are matched directly
- object/group names are resolved if you provide object/group CSVs
- ports/app/url-category are not filtered — the script reports rule *potential* access

Address/Group CSV formats (optional but recommended if your rules use objects):
- --addr-objects CSV with columns: name,type,value
    type ∈ { ip-netmask, ip-cidr, ip-range, ip, fqdn }
    examples:
      name=web1, type=ip,         value=10.1.2.3
      name=lan24, type=ip-cidr,   value=10.1.0.0/24
      name=dmz,   type=ip-range,  value=10.10.0.10-10.10.0.99
      name=legacy, type=ip-netmask, value=10.20.30.0/255.255.255.0
      name=app.fqdn, type=fqdn, value=app.example.com  (DNS not resolved; skipped)
- --addr-groups CSV with columns: name,members
    members are ';' separated names of objects or other groups (recursive supported)

Usage:
  python compile_access_from_rules.py \
    --rules-csv rules.csv \
    --ips-file ip_list.txt \
    -o access.csv \
    --addr-objects addr_objects.csv \
    --addr-groups addr_groups.csv

  # Or pass IPs inline:
  python compile_access_from_rules.py --rules-csv rules.csv --ip 10.1.2.3 --ip 172.16.5.10 -o access.csv

Flags:
  --include-deny       Include action=deny (default is allow-only)
  --include-disabled   Include disabled rules (default excludes)
  --direction both|src|dst   Limit match side (default both)
"""

import argparse
import csv
import ipaddress
from typing import Dict, List, Tuple, Set, Optional
from functools import lru_cache

# -----------------------------
# Helpers for parsing networks
# -----------------------------

def _parse_netmask_form(s: str) -> Optional[ipaddress.IPv4Network]:
    # e.g., 10.1.2.0/255.255.255.0
    try:
        ip, mask = s.split("/")
        # Convert dotted mask to prefix
        m = ipaddress.IPv4Address(mask).packed
        prefix = sum(bin(b).count("1") for b in m)
        return ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    except Exception:
        return None

def _parse_range_form(s: str) -> Optional[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]:
    # e.g., 10.0.0.10-10.0.0.99
    try:
        a, b = s.split("-")
        return (ipaddress.ip_address(a), ipaddress.ip_address(b))
    except Exception:
        return None

def token_to_networks(token: str) -> List[ipaddress._BaseNetwork]:
    """Parse a literal token into networks (CIDR) if possible."""
    token = (token or "").strip()
    if token.lower() == "any" or token == "":
        return []
    # CIDR
    try:
        net = ipaddress.ip_network(token, strict=False)
        return [net]
    except Exception:
        pass
    # Single IP
    try:
        ip = ipaddress.ip_address(token)
        # make /32 or /128
        if isinstance(ip, ipaddress.IPv4Address):
            return [ipaddress.ip_network(f"{ip}/32")]
        else:
            return [ipaddress.ip_network(f"{ip}/128")]
    except Exception:
        pass
    # Netmask form
    nm = _parse_netmask_form(token)
    if nm:
        return [nm]
    # Range form
    r = _parse_range_form(token)
    if r:
        a, b = r
        # convert to minimal CIDR set
        nets = list(ipaddress.summarize_address_range(a, b))
        return nets
    return []  # likely an object/group name

# ------------------------------------
# Address object / group map handling
# ------------------------------------

def load_addr_objects(path: str) -> Dict[str, List[ipaddress._BaseNetwork]]:
    """
    Expect columns: name,type,value
    type in { ip, ip-cidr, ip-netmask, ip-range, fqdn }
    """
    out: Dict[str, List[ipaddress._BaseNetwork]] = {}
    if not path:
        return out
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            name = (row.get("name") or "").strip()
            typ = (row.get("type") or "").strip().lower()
            val = (row.get("value") or "").strip()
            nets: List[ipaddress._BaseNetwork] = []
            if typ in {"ip", "ip-cidr"}:
                nets = token_to_networks(val)
            elif typ == "ip-netmask":
                nm = _parse_netmask_form(val)
                if nm:
                    nets = [nm]
            elif typ == "ip-range":
                r = _parse_range_form(val)
                if r:
                    nets = list(ipaddress.summarize_address_range(*r))
            elif typ == "fqdn":
                # DNS not resolved (offline & variable) — skip
                nets = []
            if name:
                out[name] = nets
    return out

def load_addr_groups(path: str) -> Dict[str, List[str]]:
    """
    Expect columns: name,members   where members are ';' separated names.
    """
    out: Dict[str, List[str]] = {}
    if not path:
        return out
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            name = (row.get("name") or "").strip()
            members = (row.get("members") or "").strip()
            mems = [m.strip() for m in members.split(";") if m.strip()] if members else []
            if name:
                out[name] = mems
    return out

def build_resolver(obj_map: Dict[str, List[ipaddress._BaseNetwork]],
                   grp_map: Dict[str, List[str]]):
    """Return a function name->List[networks], expanding groups recursively."""
    @lru_cache(maxsize=4096)
    def resolve(name: str) -> List[ipaddress._BaseNetwork]:
        name = (name or "").strip()
        if not name:
            return []
        # direct object?
        if name in obj_map:
            return obj_map[name]
        # group?
        nets: List[ipaddress._BaseNetwork] = []
        seen: Set[str] = set()

        def dfs(n: str):
            if n in seen:
                return
            seen.add(n)
            if n in obj_map:
                nets.extend(obj_map[n])
            elif n in grp_map:
                for m in grp_map[n]:
                    dfs(m)
            # else: unknown name — ignore

        dfs(name)
        return nets
    return resolve

# -----------------------------
# Rule matching
# -----------------------------

def ip_matches_token(ip: ipaddress._BaseAddress, token: str,
                     resolve_name) -> Tuple[bool, str]:
    """
    Returns (match?, explanation).
    explanation is either 'any', 'literal:<token>', or 'object:<name>'
    """
    token = (token or "").strip()
    if token == "" or token.lower() == "any":
        return True, "any"
    # literal?
    nets = token_to_networks(token)
    if nets:
        for n in nets:
            if ip in n:
                return True, f"literal:{token}"
        return False, ""
    # object/group name
    nets = resolve_name(token)
    for n in nets:
        if ip in n:
            return True, f"object:{token}"
    return False, ""

def should_include(row: Dict[str, str], include_deny: bool, include_disabled: bool) -> bool:
    if not include_disabled and (row.get("disabled", "").lower() in {"yes", "true", "1"}):
        return False
    action = (row.get("action") or "").lower()
    if action != "allow" and not include_deny:
        return False
    return True

# -----------------------------
# Main
# -----------------------------

def main():
    ap = argparse.ArgumentParser(description="Compile per-IP access list from Panorama logical rules CSV.")
    ap.add_argument("--rules-csv", required=True, help="CSV from panorama_security_rules_to_csv.py")
    ap.add_argument("--ips-file", help="File with one IP per line")
    ap.add_argument("--ip", action="append", default=[], help="Add an IP inline (repeatable)")
    ap.add_argument("-o", "--output", default="compiled_access.csv", help="Output CSV")
    ap.add_argument("--addr-objects", help="Address objects CSV (name,type,value)")
    ap.add_argument("--addr-groups", help="Address groups CSV (name,members, ';' separated)")
    ap.add_argument("--include-deny", action="store_true", help="Include rules with action != allow")
    ap.add_argument("--include-disabled", action="store_true", help="Include disabled rules")
    ap.add_argument("--direction", choices=["both", "src", "dst"], default="both", help="Match side to consider")
    args = ap.parse_args()

    # Load IPs
    ips: List[str] = list(args.ip)
    if args.ips_file:
        with open(args.ips_file, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    ips.append(s)
    if not ips:
        raise SystemExit("No IPs provided. Use --ips-file or --ip.")

    parsed_ips: List[ipaddress._BaseAddress] = []
    for s in ips:
        try:
            parsed_ips.append(ipaddress.ip_address(s))
        except Exception:
            raise SystemExit(f"Invalid IP: {s}")

    # Load address maps (optional)
    obj_map = load_addr_objects(args.addr_objects) if args.addr_objects else {}
    grp_map = load_addr_groups(args.addr_groups) if args.addr_groups else {}
    resolve_name = build_resolver(obj_map, grp_map)

    # Read rules CSV
    with open(args.rules_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rules = list(reader)
    if not rules:
        raise SystemExit("No rows found in rules CSV.")

    # Output
    out_fields = [
        "ip", "direction", "device_group", "rulebase", "rule_name", "action", "disabled",
        "from", "to", "source", "destination",
        "source_match_by", "destination_match_by",
        "service", "application", "url-category", "tags", "profile_groups", "description", "log_setting", "schedule"
    ]
    with open(args.output, "w", newline="", encoding="utf-8") as fo:
        w = csv.DictWriter(fo, fieldnames=out_fields)
        w.writeheader()

        for ip in parsed_ips:
            for row in rules:
                if not should_include(row, args.include_deny, args.include_disabled):
                    continue

                src_ok, src_how = ip_matches_token(ip, row.get("source", ""), resolve_name)
                dst_ok, dst_how = ip_matches_token(ip, row.get("destination", ""), resolve_name)

                match = False
                direction = ""
                if args.direction in ("both", "src") and src_ok:
                    match = True
                    direction = "src" if args.direction != "both" else ("src" if not dst_ok else "both")
                if args.direction in ("both", "dst") and dst_ok:
                    match = True
                    if direction == "":
                        direction = "dst"
                    elif direction == "src" and dst_ok:
                        direction = "both"

                if not match:
                    continue

                w.writerow({
                    "ip": str(ip),
                    "direction": direction,
                    "device_group": row.get("device_group", ""),
                    "rulebase": row.get("rulebase", ""),
                    "rule_name": row.get("rule_name", ""),
                    "action": row.get("action", ""),
                    "disabled": row.get("disabled", ""),
                    "from": row.get("from", ""),
                    "to": row.get("to", ""),
                    "source": row.get("source", ""),
                    "destination": row.get("destination", ""),
                    "source_match_by": src_how,
                    "destination_match_by": dst_how,
                    "service": row.get("service", ""),
                    "application": row.get("application", ""),
                    "url-category": row.get("url-category", ""),
                    "tags": row.get("tags", ""),
                    "profile_groups": row.get("profile_groups", ""),
                    "description": row.get("description", ""),
                    "log_setting": row.get("log_setting", ""),
                    "schedule": row.get("schedule", ""),
                })

    print(f"Done. Wrote: {args.output}")
    print("Notes:")
    print("- Only literal IP/CIDR and provided object/group mappings are matched.")
    print("- FQDN address objects are skipped (no DNS lookups).")
    print("- Service/ports and apps are reported but not filtered.")

if __name__ == "__main__":
    main()
