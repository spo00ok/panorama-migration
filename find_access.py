#!/usr/bin/env python3
"""
find_logical_rules_for_ips.py

Given:
  1) A "logical rules" CSV (from snapshot_to_logical_rules_resolved.py or the API version)
     Expected columns include:
       device_group, rulebase, rule_name, action, disabled,
       from, to, source_network, destination_network, application, service, url_category, ...
  2) A text file of targets: one per line, each a literal IP, CIDR, dotted-netmask, or range:
       192.0.2.10
       10.0.0.0/8
       10.1.2.0/255.255.255.0
       172.16.10.10-172.16.10.99
     Lines starting with '#' are ignored.

Outputs:
  A CSV of rule matches. Each output row shows which target matched which rule,
  on which side (src/dst/both), and which policy networks matched.

Matching modes:
  - subset (default): the target IP/subnet must be fully contained within the policy network.
    Example: target 10.1.2.0/24 matches policy 10.0.0.0/8 (True), but not the reverse.
  - intersect: any overlap between target and policy network counts.

Usage:
  python find_logical_rules_for_ips.py \
      --rules-csv logical_rules.csv \
      --targets targets.txt \
      -o matches.csv \
      --direction both \
      --mode subset \
      --include-deny --include-disabled
"""

import argparse
import csv
import ipaddress
from typing import Dict, List, Tuple, Optional, Iterable, Set

# -----------------------------
# Target parsing helpers
# -----------------------------

def _parse_netmask_form(s: str) -> Optional[ipaddress._BaseNetwork]:
    # "10.1.2.0/255.255.255.0" -> 10.1.2.0/24
    try:
        ip, mask = s.split("/")
        packed = ipaddress.ip_address(mask).packed
        prefix = sum(bin(b).count("1") for b in packed)
        return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except Exception:
        return None

def _parse_range_form(s: str) -> Optional[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]]:
    # "10.0.0.10-10.0.0.99"
    try:
        a, b = s.split("-")
        return ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
    except Exception:
        return None

def parse_target_to_networks(token: str) -> List[ipaddress._BaseNetwork]:
    """
    Convert a target token (IP, CIDR, dotted-netmask, range) to one or more CIDR networks.
    """
    token = (token or "").strip()
    if not token or token.startswith("#"):
        return []

    # CIDR or bare IP
    try:
        n = ipaddress.ip_network(token, strict=False)
        return [n]
    except Exception:
        pass

    # dotted netmask
    nm = _parse_netmask_form(token)
    if nm:
        return [nm]

    # range
    r = _parse_range_form(token)
    if r:
        a, b = r
        return list(ipaddress.summarize_address_range(a, b))

    raise ValueError(f"Unrecognized target expression: {token}")

def load_targets(path: str) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            nets.extend(parse_target_to_networks(s))
    # Dedup / normalize ordering to improve cache locality
    nets = sorted(set(nets), key=lambda n: (n.version, int(n.network_address), int(n.prefixlen)))
    return nets

# -----------------------------
# Policy network parsing
# -----------------------------

def split_network_list(s: str) -> List[str]:
    # Source/destination networks might be a single value or a ';'-joined list
    if s is None:
        return []
    s = s.strip()
    if not s:
        return []
    parts = [p.strip() for p in s.split(";") if p.strip()]
    return parts if parts else []

def to_ipnetwork_list(tokens: Iterable[str]) -> Tuple[List[ipaddress._BaseNetwork], bool]:
    """
    Convert tokens (e.g., ['10.0.0.0/8', '192.0.2.0/24']) into ip_network list.
    Returns (networks, has_any).
    """
    nets: List[ipaddress._BaseNetwork] = []
    has_any = False
    for t in tokens:
        if t.lower() == "any":
            has_any = True
            continue
        try:
            nets.append(ipaddress.ip_network(t, strict=False))
        except Exception:
            # Ignore unparseable (shouldn't happen for "logical" CSV, but be defensive)
            continue
    # Canonical order
    nets = sorted(nets, key=lambda n: (n.version, int(n.network_address), int(n.prefixlen)))
    return nets, has_any

# -----------------------------
# Matching logic
# -----------------------------

def match_target_policy(
    target: ipaddress._BaseNetwork,
    policy_nets: List[ipaddress._BaseNetwork],
    has_any: bool,
    mode: str
) -> Tuple[bool, List[str]]:
    """
    Returns (matched?, matched_policy_net_strings)
    mode: 'subset' (target ⊆ policy) or 'intersect' (target ∩ policy ≠ ∅)
    """
    if has_any:
        return True, ["any"]

    matched: List[str] = []
    if mode == "subset":
        for pn in policy_nets:
            # Only compare within same IP family
            if pn.version != target.version:
                continue
            if target.subnet_of(pn):
                matched.append(str(pn))
    else:  # intersect
        for pn in policy_nets:
            if pn.version != target.version:
                continue
            if target.overlaps(pn):
                matched.append(str(pn))

    return (len(matched) > 0), matched

def rule_included(row: Dict[str, str], include_deny: bool, include_disabled: bool) -> bool:
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
    ap = argparse.ArgumentParser(description="Find logical rule matches for a list of IPs/subnets/ranges.")
    ap.add_argument("--rules-csv", required=True, help="Logical rules CSV (from *to_logical_rules*_resolved.py)")
    ap.add_argument("--targets", required=True, help="Text file with IPs/subnets/ranges (one per line)")
    ap.add_argument("-o", "--output", default="matches.csv", help="Output CSV path")
    ap.add_argument("--direction", choices=["both", "src", "dst"], default="both", help="Which side(s) to check")
    ap.add_argument("--mode", choices=["subset", "intersect"], default="subset",
                    help="Match mode: 'subset' (target must be contained in policy) or 'intersect' (any overlap)")
    ap.add_argument("--include-deny", action="store_true", help="Include rules with action != allow")
    ap.add_argument("--include-disabled", action="store_true", help="Include disabled rules")
    args = ap.parse_args()

    targets = load_targets(args.targets)
    if not targets:
        raise SystemExit("No valid targets loaded.")

    # Prepare CSV output
    out_fields = [
        "target", "target_version", "direction",
        "device_group", "rulebase", "rule_name",
        "matched_policy_networks",
        "action", "disabled",
        "from", "to", "service", "application", "url_category",
        "tags", "profile_groups", "description", "log_setting", "schedule",
        "source_all_resolved", "destination_all_resolved", "unresolved_notes",
    ]

    with open(args.rules_csv, newline="", encoding="utf-8") as fi, \
         open(args.output, "w", newline="", encoding="utf-8") as fo:

        reader = csv.DictReader(fi)
        writer = csv.DictWriter(fo, fieldnames=out_fields)
        writer.writeheader()

        for row in reader:
            if not rule_included(row, args.include_deny, args.include_disabled):
                continue

            # Parse source/destination networks for this rule row
            src_tokens = split_network_list(row.get("source_network", ""))
            dst_tokens = split_network_list(row.get("destination_network", ""))

            src_nets, src_has_any = to_ipnetwork_list(src_tokens)
            dst_nets, dst_has_any = to_ipnetwork_list(dst_tokens)

            # If neither side has any parseable network and no 'any', skip early.
            if args.direction in ("both", "src") and not (src_nets or src_has_any):
                pass  # still might match if tokens were 'any' (already captured) or empty -> treat as no
            if args.direction in ("both", "dst") and not (dst_nets or dst_has_any):
                pass

            # For each target, check match on requested directions
            for tgt in targets:
                wrote = False

                # SRC
                if args.direction in ("both", "src"):
                    matched, matched_list = match_target_policy(tgt, src_nets, src_has_any, args.mode)
                    if matched:
                        writer.writerow({
                            "target": str(tgt),
                            "target_version": "ipv6" if tgt.version == 6 else "ipv4",
                            "direction": "src" if args.direction != "both" else ("both" if wrote else "src"),
                            "device_group": row.get("device_group", ""),
                            "rulebase": row.get("rulebase", ""),
                            "rule_name": row.get("rule_name", ""),
                            "matched_policy_networks": ";".join(matched_list),
                            "action": row.get("action", ""),
                            "disabled": row.get("disabled", ""),
                            "from": row.get("from", ""),
                            "to": row.get("to", ""),
                            "service": row.get("service", ""),
                            "application": row.get("application", ""),
                            "url_category": row.get("url-category", row.get("url_category", "")),
                            "tags": row.get("tags", ""),
                            "profile_groups": row.get("profile_groups", ""),
                            "description": row.get("description", ""),
                            "log_setting": row.get("log_setting", ""),
                            "schedule": row.get("schedule", ""),
                            "source_all_resolved": row.get("source_all_resolved", ""),
                            "destination_all_resolved": row.get("destination_all_resolved", ""),
                            "unresolved_notes": row.get("unresolved_notes", ""),
                        })
                        wrote = True

                # DST
                if args.direction in ("both", "dst"):
                    matched, matched_list = match_target_policy(tgt, dst_nets, dst_has_any, args.mode)
                    if matched:
                        writer.writerow({
                            "target": str(tgt),
                            "target_version": "ipv6" if tgt.version == 6 else "ipv4",
                            "direction": "dst" if args.direction != "both" else ("both" if wrote else "dst"),
                            "device_group": row.get("device_group", ""),
                            "rulebase": row.get("rulebase", ""),
                            "rule_name": row.get("rule_name", ""),
                            "matched_policy_networks": ";".join(matched_list),
                            "action": row.get("action", ""),
                            "disabled": row.get("disabled", ""),
                            "from": row.get("from", ""),
                            "to": row.get("to", ""),
                            "service": row.get("service", ""),
                            "application": row.get("application", ""),
                            "url_category": row.get("url-category", row.get("url_category", "")),
                            "tags": row.get("tags", ""),
                            "profile_groups": row.get("profile_groups", ""),
                            "description": row.get("description", ""),
                            "log_setting": row.get("log_setting", ""),
                            "schedule": row.get("schedule", ""),
                            "source_all_resolved": row.get("source_all_resolved", ""),
                            "destination_all_resolved": row.get("destination_all_resolved", ""),
                            "unresolved_notes": row.get("unresolved_notes", ""),
                        })

    print(f"Done. Wrote: {args.output}")
    print("Notes:")
    print("- Default match mode is 'subset' (targets must fall entirely inside the policy network).")
    print("- Use --mode intersect to match any overlap.")
    print("- By default, only enabled allow rules are reported; add --include-deny and/or --include-disabled to widen results.")
    print("- If your logical rules CSV collapsed source/destination into ';'-lists, this script still handles them.")
    print("- 'any' on a side matches all targets for that side.")
    print("- Supports IPv4 and IPv6.")
    
if __name__ == "__main__":
    main()
