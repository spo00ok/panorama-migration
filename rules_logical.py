#!/usr/bin/env python3
"""
snapshot_to_logical_rules_resolved.py

Convert a saved Panorama XML configuration snapshot into a logical rule base CSV,
resolving address objects and static address groups (per-device-group scope with
fallback to Shared).

Key points
- Input: Panorama XML snapshot (running/candidate export). Plain .xml or .xml.gz.
- Resolves: ip-netmask, ip-range, and static groups (recursive).
- Leaves unresolved (flagged): FQDN objects and dynamic address groups.
- Streams CSV; can limit Cartesian explosion.

Usage
  python snapshot_to_logical_rules_resolved.py \
    --input panorama_config.xml \
    -o logical_rules.csv

  # gzipped snapshots are fine:
  python snapshot_to_logical_rules_resolved.py \
    --input panorama_config.xml.gz \
    --include-shared-rules \
    --expand from,to,source,destination \
    --max-combos-per-rule 200000 \
    -o logical_rules.csv
"""

import argparse
import csv
import gzip
import itertools
import ipaddress
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET


# ---------------------------
# XML helpers
# ---------------------------

def load_config(path: str) -> ET.Element:
    """Load XML, return the <config> node."""
    data: bytes
    if path.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            data = f.read()
    else:
        with open(path, "rb") as f:
            data = f.read()
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise SystemExit(f"Failed to parse XML: {e}")

    # If root is <config>, return it; else find .//config
    if root.tag == "config":
        return root
    cfg = root.find(".//config")
    if cfg is None:
        raise SystemExit("No <config> node found in snapshot.")
    return cfg


def members(parent: Optional[ET.Element], tag: str) -> List[str]:
    """Return list of <member> under <tag>, or ['any'] if missing/empty."""
    if parent is None:
        return ["any"]
    node = parent.find(tag)
    if node is None:
        return ["any"]
    vals = [m.text.strip() for m in node.findall("member") if m.text and m.text.strip()]
    if vals:
        return vals
    raw = (node.text or "").strip()
    return [raw] if raw else ["any"]


def text(parent: Optional[ET.Element], tag: str, default: str = "") -> str:
    n = parent.find(tag) if parent is not None else None
    return (n.text or "").strip() if (n is not None and n.text) else default


# ---------------------------
# Address parsing / normalize
# ---------------------------

def parse_netmask_form(s: str) -> Optional[ipaddress._BaseNetwork]:
    # "10.1.2.0/255.255.255.0" -> 10.1.2.0/24
    try:
        ip, mask = s.split("/")
        packed = ipaddress.ip_address(mask).packed
        prefix = sum(bin(b).count("1") for b in packed)
        return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except Exception:
        return None


def parse_range(s: str) -> Optional[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]]:
    # "10.0.0.1-10.0.0.254"
    try:
        a, b = s.split("-")
        return ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
    except Exception:
        return None


def literal_token_to_networks(token: str) -> List[ipaddress._BaseNetwork]:
    """
    Try to interpret token as literal address/net/range.
    Return list of networks or [] if it looks like a *name* (object/group).
    """
    token = (token or "").strip()
    if not token or token.lower() == "any":
        return []
    # CIDR or bare IP
    try:
        net = ipaddress.ip_network(token, strict=False)
        return [net]
    except Exception:
        pass
    # dotted mask
    nm = parse_netmask_form(token)
    if nm:
        return [nm]
    # range
    rg = parse_range(token)
    if rg:
        a, b = rg
        return list(ipaddress.summarize_address_range(a, b))
    # not a literal
    return []


def nets_to_strings(nets: List[ipaddress._BaseNetwork]) -> List[str]:
    return [str(n) for n in nets]


def is_cidr_str(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except Exception:
        return False


# ---------------------------
# Config extraction
# ---------------------------

class ScopeMaps:
    """Holds address objects & groups for a scope (DG or Shared)."""
    def __init__(self):
        self.addr_objs: Dict[str, Dict[str, Any]] = {}  # name -> {type,value,tags}
        self.addr_grps: Dict[str, Dict[str, Any]] = {}  # name -> {static:[...], dynamic:str}


def extract_shared_maps(cfg: ET.Element) -> ScopeMaps:
    sm = ScopeMaps()
    shared = cfg.find("shared")
    if shared is None:
        return sm

    for e in shared.findall("./address/entry"):
        name = e.attrib.get("name", "")
        if not name:
            continue
        obj = {"type": "", "value": "", "tags": [m.text.strip() for m in e.findall("./tag/member") if m.text]}
        if e.find("ip-netmask") is not None:
            obj["type"] = "ip-netmask"
            obj["value"] = text(e, "ip-netmask")
        elif e.find("ip-range") is not None:
            obj["type"] = "ip-range"
            obj["value"] = text(e, "ip-range")
        elif e.find("fqdn") is not None:
            obj["type"] = "fqdn"
            obj["value"] = text(e, "fqdn")
        sm.addr_objs[name] = obj

    for g in shared.findall("./address-group/entry"):
        name = g.attrib.get("name", "")
        if not name:
            continue
        static = [m.text.strip() for m in g.findall("./static/member") if m.text]
        dyn = text(g.find("dynamic"), "filter", "")
        sm.addr_grps[name] = {"static": static, "dynamic": dyn}

    return sm


def extract_dg_maps(dg_entry: ET.Element) -> ScopeMaps:
    sm = ScopeMaps()
    for e in dg_entry.findall("./address/entry"):
        name = e.attrib.get("name", "")
        if not name:
            continue
        obj = {"type": "", "value": "", "tags": [m.text.strip() for m in e.findall("./tag/member") if m.text]}
        if e.find("ip-netmask") is not None:
            obj["type"] = "ip-netmask"
            obj["value"] = text(e, "ip-netmask")
        elif e.find("ip-range") is not None:
            obj["type"] = "ip-range"
            obj["value"] = text(e, "ip-range")
        elif e.find("fqdn") is not None:
            obj["type"] = "fqdn"
            obj["value"] = text(e, "fqdn")
        sm.addr_objs[name] = obj

    for g in dg_entry.findall("./address-group/entry"):
        name = g.attrib.get("name", "")
        if not name:
            continue
        static = [m.text.strip() for m in g.findall("./static/member") if m.text]
        dyn = text(g.find("dynamic"), "filter", "")
        sm.addr_grps[name] = {"static": static, "dynamic": dyn}

    return sm


def iter_dgs(cfg: ET.Element) -> List[ET.Element]:
    return cfg.findall("./devices/entry[@name='localhost.localdomain']/device-group/entry")


# ---------------------------
# Name resolver (memoized)
# ---------------------------

class Resolver:
    """DG-first, then Shared, with memoization."""
    def __init__(self, dg_maps: ScopeMaps, shared_maps: ScopeMaps):
        self.dg_maps = dg_maps
        self.shared_maps = shared_maps
        self.cache_obj: Dict[str, List[str]] = {}
        self.cache_grp: Dict[str, List[str]] = {}
        self.visiting: Set[str] = set()  # cycle guard

    def resolve_name(self, name: str) -> Tuple[List[str], bool, str]:
        """
        Returns (networks_as_str, is_resolved, reason_if_unresolved)
        FQDN & dynamic groups return unresolved with reason.
        """
        name = (name or "").strip()
        if not name:
            return [], True, ""

        # Object?
        if name in self.cache_obj:
            return self.cache_obj[name], True, ""
        obj = self.dg_maps.addr_objs.get(name) or self.shared_maps.addr_objs.get(name)
        if obj:
            typ = obj.get("type", "")
            val = obj.get("value", "")
            if typ == "fqdn":
                return [name], False, "fqdn"
            elif typ == "ip-range":
                try:
                    a, b = parse_range(val)
                    nets = list(ipaddress.summarize_address_range(a, b))
                    out = nets_to_strings(nets)
                    self.cache_obj[name] = out
                    return out, True, ""
                except Exception:
                    return [name], False, "bad-ip-range"
            elif typ == "ip-netmask":
                nets = literal_token_to_networks(val)
                if nets:
                    out = nets_to_strings(nets)
                    self.cache_obj[name] = out
                    return out, True, ""
                return [name], False, "bad-ip-netmask"
            else:
                return [name], False, "unknown-obj-type"

        # Group?
        if name in self.cache_grp:
            return self.cache_grp[name], True, ""
        grp = self.dg_maps.addr_grps.get(name) or self.shared_maps.addr_grps.get(name)
        if grp:
            dyn = grp.get("dynamic", "")
            if dyn:
                return [name], False, "dynamic-group"
            if name in self.visiting:
                return [name], False, "cycle"
            self.visiting.add(name)
            acc: List[str] = []
            for m in grp.get("static", []):
                lits = literal_token_to_networks(m)
                if lits:
                    acc.extend(nets_to_strings(lits))
                    continue
                nets, ok, _reason = self.resolve_name(m)
                # Keep only parseable CIDRs here; unresolved will be tracked by caller
                acc.extend([s for s in nets if is_cidr_str(s)])
            self.visiting.discard(name)
            # Dedupe and canonicalize
            acc = sorted(
                set(acc),
                key=lambda s: (
                    ipaddress.ip_network(s).version,
                    int(ipaddress.ip_network(s).network_address),
                    int(ipaddress.ip_network(s).prefixlen),
                ),
            )
            self.cache_grp[name] = acc
            return acc, True, ""

        # Unknown
        return [name], False, "unknown-name"

    def expand_tokens(self, tokens: List[str]) -> Tuple[List[str], bool, List[str]]:
        """
        Expand tokens (any/literals/names) into CIDR strings or 'any'.
        Returns (expanded, all_resolved?, unresolved_notes[])
        """
        if not tokens:
            return ["any"], True, []
        if len(tokens) == 1 and (tokens[0].lower() == "any" or tokens[0] == ""):
            return ["any"], True, []

        out: List[str] = []
        all_ok = True
        notes: List[str] = []

        for t in tokens:
            t = (t or "").strip()
            if not t or t.lower() == "any":
                out.append("any")
                continue
            lits = literal_token_to_networks(t)
            if lits:
                out.extend(nets_to_strings(lits))
                continue
            nets, ok, reason = self.resolve_name(t)
            if not ok:
                all_ok = False
                if reason:
                    notes.append(f"{t}:{reason}")
            # Only keep parseable CIDRs in the expansion list
            out.extend([s for s in nets if is_cidr_str(s)])

        if "any" in out:
            return ["any"], all_ok, notes

        # Dedup + stable canonical order
        out = sorted(
            set(out),
            key=lambda s: (
                ipaddress.ip_network(s).version,
                int(ipaddress.ip_network(s).network_address),
                int(ipaddress.ip_network(s).prefixlen),
            ),
        )
        return out, all_ok, notes


# ---------------------------
# Rule extraction
# ---------------------------

def collect_rules_from_node(node: Optional[ET.Element]) -> List[ET.Element]:
    if node is None:
        return []
    return node.findall("./security/rules/entry")


def get_rulebases_for_dg(dg: ET.Element) -> Dict[str, List[ET.Element]]:
    return {
        "pre":   collect_rules_from_node(dg.find("./pre-rulebase")),
        "post":  collect_rules_from_node(dg.find("./post-rulebase")),
        "local": collect_rules_from_node(dg.find("./rulebase")),
    }


def get_shared_rulebases(cfg: ET.Element) -> Dict[str, List[ET.Element]]:
    shared = cfg.find("./shared")
    return {
        "shared-pre":  collect_rules_from_node(shared.find("./pre-rulebase")) if shared is not None else [],
        "shared-post": collect_rules_from_node(shared.find("./post-rulebase")) if shared is not None else [],
    }


# ---------------------------
# CSV writing (streamed)
# ---------------------------

CSV_HEADERS = [
    "device_group", "rulebase", "rule_name", "description", "tags",
    "disabled", "action", "log_setting", "schedule",
    "negate_source", "negate_destination", "profile_groups",
    # expanded logical fields (one value each per row)
    "from", "to", "source_network", "destination_network",
    "source_user", "application", "service", "url_category",
    # diagnostics
    "source_all_resolved", "destination_all_resolved", "unresolved_notes",
]


def explode_and_write_rows(
    writer: csv.DictWriter,
    device_group: str,
    rulebase_name: str,
    entry: ET.Element,
    resolver: Resolver,
    expand_fields: Set[str],
    max_combos_per_rule: Optional[int] = None,
):
    # Metadata
    name = entry.attrib.get("name", "")
    desc = text(entry, "description", "")
    tags = [m.text.strip() for m in entry.findall("./tag/member") if m is not None and m.text]
    disabled = text(entry, "disabled", "no") or "no"
    action = text(entry, "action", "allow") or "allow"
    log_setting = text(entry, "log-setting", "")
    schedule = text(entry, "schedule", "")
    neg_src = text(entry, "negate-source", "no") or "no"
    neg_dst = text(entry, "negate-destination", "no") or "no"
    profile_groups = [m.text.strip() for m in entry.findall("./profile-setting/group/member") if m.text]

    # Match lists
    lst_from = members(entry, "from")
    lst_to = members(entry, "to")
    lst_src = members(entry, "source")
    lst_dst = members(entry, "destination")
    lst_user = members(entry, "source-user")
    lst_app = members(entry, "application")
    lst_serv = members(entry, "service")
    lst_url = members(entry, "category")

    # Resolve address sets
    src_expanded, src_ok, src_notes = resolver.expand_tokens(lst_src)
    dst_expanded, dst_ok, dst_notes = resolver.expand_tokens(lst_dst)
    notes = ";".join(src_notes + dst_notes)

    # Optional expansion control
    def maybe(vals: List[str], field: str) -> List[str]:
        return vals if field in expand_fields else [";".join(vals)]

    from_vals = maybe(lst_from, "from")
    to_vals = maybe(lst_to, "to")
    src_vals = maybe(src_expanded, "source")
    dst_vals = maybe(dst_expanded, "destination")
    user_vals = maybe(lst_user, "source-user")
    app_vals = maybe(lst_app, "application")
    svc_vals = maybe(lst_serv, "service")
    url_vals = maybe(lst_url, "url-category")

    combos = itertools.product(from_vals, to_vals, src_vals, dst_vals, user_vals, app_vals, svc_vals, url_vals)

    written = 0
    for fr, to, src_net, dst_net, usr, app, svc, urlc in combos:
        writer.writerow({
            "device_group": device_group,
            "rulebase": rulebase_name,
            "rule_name": name,
            "description": desc,
            "tags": ";".join(tags),
            "disabled": disabled,
            "action": action,
            "log_setting": log_setting,
            "schedule": schedule,
            "negate_source": neg_src,
            "negate_destination": neg_dst,
            "profile_groups": ";".join(profile_groups),
            "from": fr,
            "to": to,
            "source_network": src_net,
            "destination_network": dst_net,
            "source_user": usr,
            "application": app,
            "service": svc,
            "url_category": urlc,
            "source_all_resolved": "yes" if src_ok else "no",
            "destination_all_resolved": "yes" if dst_ok else "no",
            "unresolved_notes": notes,
        })
        written += 1
        if max_combos_per_rule is not None and written >= max_combos_per_rule:
            break


# ---------------------------
# Main
# ---------------------------

def main():
    ap = argparse.ArgumentParser(description="Convert Panorama snapshot XML into logical rule base CSV (with resolved addresses).")
    ap.add_argument("--input", required=True, help="Panorama XML snapshot (.xml or .xml.gz)")
    ap.add_argument("-o", "--output", required=True, help="Output CSV path")
    ap.add_argument("--include-shared-rules", action="store_true", help="Include shared pre/post rulebases")
    ap.add_argument("--max-combos-per-rule", type=int, default=None, help="Cap expansion per rule (truncate)")
    ap.add_argument("--expand", default="from,to,source,destination,source-user,application,service,url-category",
                    help="Comma-separated fields to expand; omit fields to reduce Cartesian explosion")
    args = ap.parse_args()

    cfg = load_config(args.input)
    shared_maps = extract_shared_maps(cfg)

    expand_fields = set([s.strip() for s in args.expand.split(",") if s.strip()])
    with open(args.output, "w", newline="", encoding="utf-8") as fo:
        writer = csv.DictWriter(fo, fieldnames=CSV_HEADERS)
        writer.writeheader()

        # Optional: shared rulebases (resolved using Shared objects only)
        if args.include_shared_rues if False else args.include_shared_rules:  # typo guard
            shared_rulebases = get_shared_rulebases(cfg)
            shared_resolver = Resolver(ScopeMaps(), shared_maps)
            for rb_name, rules in shared_rulebases.items():
                for e in rules:
                    explode_and_write_rows(
                        writer,
                        device_group="shared",
                        rulebase_name=rb_name,
                        entry=e,
                        resolver=shared_resolver,
                        expand_fields=expand_fields,
                        max_combos_per_rule=args.max_combos_per_rule,
                    )

        # Per-device-group
        for dg in iter_dgs(cfg):
            dg_name = dg.attrib.get("name", "")
            if not dg_name:
                continue
            dg_maps = extract_dg_maps(dg)
            resolver = Resolver(dg_maps, shared_maps)
            rb = get_rulebases_for_dg(dg)
            for rb_name, rules in rb.items():
                for e in rules:
                    explode_and_write_rows(
                        writer,
                        device_group=dg_name,
                        rulebase_name=rb_name,
                        entry=e,
                        resolver=resolver,
                        expand_fields=expand_fields,
                        max_combos_per_rule=args.max_combos_per_rule,
                    )

    print(f"Done. Wrote CSV: {args.output}")
    print("Notes:")
    print("- Static address groups and IP/range/netmask objects are fully resolved with DG->Shared scoping.")
    print("- FQDN objects and dynamic address groups remain unresolved; see *_all_resolved and 'unresolved_notes'.")
    print("- Use --expand to limit combinatorial explosion (e.g., only expand from,to,source,destination).")


if __name__ == "__main__":
    main()
