#!/usr/bin/env python3
import re
import sys
import csv
import argparse
from ipaddress import (
    ip_network, ip_address,
    IPv4Network, IPv6Network, IPv4Address, IPv6Address
)

# ---------------- CLI ----------------
"""
python panorama_convert_groups_create_and_append.py \
  --config panorama.set \
  --mapping ip_migration.csv \
  --out-groups group_edits.set \
  --out-creates object_creates.set \
  --log group_edits.log
"""

# ---------------- Regexes ----------------

# Address objects (DG or shared)
ADDR_OBJ_IPNET_RE = re.compile(
    r'^set\s+(?:(?:device-group\s+(?P<dg>\S+)\s+)|(?:shared\s+))?address\s+(?P<name>\".*?\"|\S+)\s+ip-netmask\s+(?P<cidr>\S+)\s*$',
    re.IGNORECASE
)
ADDR_OBJ_RANGE_RE = re.compile(
    r'^set\s+(?:(?:device-group\s+(?P<dg>\S+)\s+)|(?:shared\s+))?address\s+(?P<name>\".*?\"|\S+)\s+ip-range\s+(?P<start>\S+)\s*-\s*(?P<end>\S+)\s*$',
    re.IGNORECASE
)

# Address groups (static)
ADDR_GRP_STATIC_RE = re.compile(
    r'^set\s+(?:(?:device-group\s+(?P<dg>\S+)\s+)|(?:shared\s+))?address-group\s+(?P<name>\".*?\"|\S+)\s+static\s+(?P<value>.+?)\s*$',
    re.IGNORECASE
)
# Address groups (dynamic) — ignored
ADDR_GRP_DYNAMIC_RE = re.compile(
    r'^set\s+(?:(?:device-group\s+(?P<dg>\S+)\s+)|(?:shared\s+))?address-group\s+(?P<name>\".*?\"|\S+)\s+dynamic\s+.*$',
    re.IGNORECASE
)

BRACKETS_RE = re.compile(r'^\[\s*(.*?)\s*\]$')

# ---------------- Helpers ----------------

def unquote(s: str) -> str:
    return s[1:-1] if s and s[0] == '"' and s[-1] == '"' else s

def parse_member_values(raw: str):
    raw = raw.strip()
    m = BRACKETS_RE.match(raw)
    if m:
        inner = m.group(1).strip()
        return [t for t in inner.split() if t]
    return [raw]

def load_map(csv_path):
    """
    Load old->new mapping.
    Supports rows:
      - <ip>,<ip>
      - <cidr>,<cidr>    (host-bit preserved)
    Returns list of tuples: (old_obj, new_obj, type) where type in {"ip","subnet"}.
    """
    mappings = []
    with open(csv_path, newline='') as f:
        rdr = csv.reader(f)
        for row in rdr:
            if not row or len(row) < 2:
                continue
            a = row[0].strip()
            b = row[1].strip()
            try:
                if '/' in a and '/' in b:
                    mappings.append((ip_network(a, strict=False), ip_network(b, strict=False), "subnet"))
                elif ('/' not in a) and ('/' not in b):
                    mappings.append((ip_address(a), ip_address(b), "ip"))
                else:
                    continue
            except ValueError:
                continue
    return mappings

def best_match_mapping(ip, mappings):
    """
    Given an IP address, choose the most-specific mapping that applies.
    Preference: exact IP match, else most-specific subnet containing IP.
    """
    candidates = []
    for old_obj, new_obj, kind in mappings:
        if kind == "ip":
            if ip == old_obj:
                candidates.append((old_obj, new_obj, kind, 999))
        else:
            if ip in old_obj:
                candidates.append((old_obj, new_obj, kind, old_obj.prefixlen))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[3], reverse=True)
    return candidates[0][:3]

def convert_ip(old_ip, old_obj, new_obj, kind):
    if kind == "ip":
        return new_obj if old_ip == old_obj else None
    if old_ip in old_obj:
        off = int(old_ip) - int(old_obj.network_address)
        if off < new_obj.num_addresses:
            return type(new_obj.network_address)(int(new_obj.network_address) + off)
    return None

def iter_object_rep_ips(meta):
    """
    Representative host IPs for mapping applicability:
      - host: that IP
      - subnet: first usable host (else network address)
      - range: start, (optional mid), end
    """
    if meta["type"] == "ip-netmask":
        net = meta["cidr"]
        if (isinstance(net, IPv4Network) and net.prefixlen == 32) or (isinstance(net, IPv6Network) and net.prefixlen == 128):
            yield net.network_address
        else:
            try:
                yield next(net.hosts())
            except StopIteration:
                yield net.network_address
    else:
        start = meta["start"]; end = meta["end"]
        yield start
        if end != start:
            mid = type(start)((int(start) + int(end)) // 2)
            if mid != start and mid != end:
                yield mid
        yield end

def build_rev_index(addr_objs):
    """
    Reverse index: exact net (hosts & subnets) and literal ranges -> names
    """
    rev = {}
    for name, meta in addr_objs.items():
        if meta["type"] == "ip-netmask":
            net = meta["cidr"]
            key = f'net:{4 if isinstance(net, IPv4Network) else 6}:{net.with_prefixlen}'
            rev.setdefault(key, set()).add(name)
        else:
            ver = 4 if isinstance(meta["start"], IPv4Address) else 6
            key = f'range:{ver}:{meta["start"]}-{meta["end"]}'
            rev.setdefault(key, set()).add(name)
    return rev

def key_for_host(ip):
    return f'net:4:{IPv4Network(str(ip)+"/32").with_prefixlen}' if isinstance(ip, IPv4Address) \
           else f'net:6:{IPv6Network(str(ip)+"/128").with_prefixlen}'

def key_for_net(net):
    return f'net:{4 if isinstance(net, IPv4Network) else 6}:{net.with_prefixlen}'

def normalize_space(meta):
    """Compare-by-space key for dedupe: (ver, start_int, end_int)"""
    if meta["type"] == "ip-netmask":
        net = meta["cidr"]
        start = net.network_address
        end = type(start)(int(net.network_address) + net.num_addresses - 1)
        ver = 4 if isinstance(net, IPv4Network) else 6
        return (ver, int(start), int(end))
    else:
        start = meta["start"]; end = meta["end"]
        ver = 4 if isinstance(start, IPv4Address) else 6
        return (ver, int(start), int(end))

def dedupe_list_by_ipspace(order, addr_objs):
    """Remove later members with identical IP space to an earlier member."""
    seen = {}
    out = []
    removed = []
    for name in order:
        meta = addr_objs.get(name)
        if not meta:
            out.append(name)  # keep unknown tokens as-is
            continue
        key = normalize_space(meta)
        if key in seen:
            removed.append((name, seen[key]))
            continue
        seen[key] = name
        out.append(name)
    return out, removed

def choose_existing_object(names, addr_objs):
    """Prefer shared objects when multiple exact matches exist."""
    if not names:
        return None
    shared = [n for n in names if addr_objs.get(n, {}).get("scope") == "shared"]
    return sorted(shared)[0] if shared else sorted(names)[0]

def host_name_for(ip):
    if isinstance(ip, IPv4Address):
        return "svb_host_" + "_".join(str(ip).split("."))
    return "svb_host_" + str(ip).replace(":", "_")[:100]

def net_name_for(net):
    if isinstance(net, IPv4Network):
        return "svb_net_" + "_".join(str(net.network_address).split(".")) + f"_{net.prefixlen}"
    return "svb_net_" + str(net.network_address).replace(":", "_")[:80] + f"_{net.prefixlen}"

def unique_object_name(base_name, addr_objs):
    if base_name not in addr_objs:
        return base_name
    i = 2
    while True:
        cand = f"{base_name}_v{i}"
        if cand not in addr_objs:
            return cand
        i += 1

# ---------------- Parse config ----------------

def parse_set_config(path):
    """
    Returns:
      addr_objs: name -> {scope, type, cidr|start/end}
      groups: (scope,name) -> {"scope":scope,"name":name,"members":[...],"seen":set(),"dynamic":bool}
    """
    addr_objs = {}
    groups = {}

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if not s or not s.startswith("set "):
                continue

            m = ADDR_OBJ_IPNET_RE.match(s)
            if m:
                scope = m.group('dg') if m.group('dg') else 'shared'
                name = unquote(m.group('name'))
                try:
                    net = ip_network(m.group('cidr'), strict=False)
                except ValueError:
                    continue
                addr_objs[name] = {"scope": scope, "type": "ip-netmask", "cidr": net}
                continue

            m = ADDR_OBJ_RANGE_RE.match(s)
            if m:
                scope = m.group('dg') if m.group('dg') else 'shared'
                name = unquote(m.group('name'))
                try:
                    start = ip_address(m.group('start'))
                    end = ip_address(m.group('end'))
                    if type(start) is not type(end) or int(end) < int(start):
                        continue
                except ValueError:
                    continue
                addr_objs[name] = {"scope": scope, "type": "ip-range", "start": start, "end": end}
                continue

            # address-group dynamic? (skip)
            if ADDR_GRP_DYNAMIC_RE.match(s):
                # still create an entry to avoid name clashes, but mark dynamic
                m2 = re.match(r'^set\s+(?:device-group\s+(\S+)\s+|shared\s+)?address-group\s+(".*?"|\S+)\s+dynamic\s+', s, re.IGNORECASE)
                if m2:
                    scope = m2.group(1) if m2.group(1) else 'shared'
                    name = unquote(m2.group(2))
                    groups.setdefault((scope, name), {"scope": scope, "name": name, "members": [], "seen": set(), "dynamic": True})
                continue

            m = ADDR_GRP_STATIC_RE.match(s)
            if m:
                scope = m.group('dg') if m.group('dg') else 'shared'
                name = unquote(m.group('name'))
                vals = parse_member_values(m.group('value'))
                key = (scope, name)
                groups.setdefault(key, {"scope": scope, "name": name, "members": [], "seen": set(), "dynamic": False})
                g = groups[key]
                for v in vals:
                    if v not in g["seen"]:
                        g["members"].append(v)
                        g["seen"].add(v)
                continue

    return addr_objs, groups

# ------------- Coverage (with nested groups) -------------

def group_covers_ip(member_names, addr_objs, groups, visited=None):
    """
    True if any member (or nested group) covers the IP.
    """
    if visited is None:
        visited = set()
    for name in member_names:
        meta = addr_objs.get(name)
        if meta:
            if meta["type"] == "ip-netmask":
                # handled at call; this utility only used for hosts
                pass
        else:
            # could be a nested group
            # find by scope-agnostic? groups keyed by (scope,name); scope unknown here.
            for (sc, gn), g in groups.items():
                if g["name"] == name:  # name match across scopes (best effort)
                    if (sc, gn) in visited:
                        continue
                    visited.add((sc, gn))
                    # expand nested
                    if group_covers_ip(g["members"], addr_objs, groups, visited):
                        return True
    return False  # direct object IP coverage is checked elsewhere

# ---------------- Main ----------------

def main():
    ap = argparse.ArgumentParser(
        description="Translate address-group members by mapping; reuse or create shared objects for converted hosts and subnets; write full static lines & a creation file; log changes."
    )
    ap.add_argument("--config", required=True, help="Panorama set-format configuration file")
    ap.add_argument("--mapping", required=True, help="CSV: old,new (IP->IP or CIDR->CIDR)")
    ap.add_argument("--out-groups", default="group_edits.set", help="Output file for modified address-group static lines")
    ap.add_argument("--out-creates", default="object_creates.set", help="Output file for newly created shared address objects")
    ap.add_argument("--log", default="group_edits.log", help="Log file")
    args = ap.parse_args()

    mappings = load_map(args.mapping)
    if not mappings:
        print("# No valid mappings found in mapping CSV.", file=sys.stderr)
        sys.exit(1)

    addr_objs, groups = parse_set_config(args.config)
    rev = build_rev_index(addr_objs)

    created_objs = []   # (name, cidr_text, note)
    changed_groups = set()  # (scope, name)
    log_lines = []

    for (scope, gname), g in groups.items():
        if g.get("dynamic"):
            continue  # skip dynamic groups

        members = g["members"]
        seen = g["seen"]
        if not members:
            continue

        altered = False

        for mem in list(members):  # iterate a copy
            meta = addr_objs.get(mem)
            if not meta:
                # could be nested group name; we don't alter nested groups here
                continue

            # --- Subnet mapping path for non-host ip-netmask members ---
            if meta["type"] == "ip-netmask":
                net = meta["cidr"]
                is_host = (isinstance(net, IPv4Network) and net.prefixlen == 32) or (isinstance(net, IPv6Network) and net.prefixlen == 128)
                if not is_host:
                    m = best_match_mapping(net.network_address, mappings)
                    if m and m[2] == "subnet":
                        old_obj, new_obj, kind = m
                        new_base = convert_ip(net.network_address, old_obj, new_obj, kind)
                        if new_base is not None:
                            try:
                                mapped_net = ip_network(f"{new_base}/{net.prefixlen}", strict=False)
                            except ValueError:
                                mapped_net = None
                            if mapped_net:
                                net_key = key_for_net(mapped_net)
                                candidates = rev.get(net_key, set())
                                chosen = choose_existing_object(candidates, addr_objs)
                                if chosen:
                                    if chosen not in seen:
                                        members.append(chosen)
                                        seen.add(chosen)
                                        altered = True
                                        log_lines.append(f'Group {scope} address-group "{gname}": appended EXISTING subnet {chosen} = {mapped_net.with_prefixlen}')
                                else:
                                    base = net_name_for(mapped_net)
                                    new_name = unique_object_name(base, addr_objs)
                                    addr_objs[new_name] = {"scope": "shared", "type": "ip-netmask", "cidr": mapped_net}
                                    rev.setdefault(net_key, set()).add(new_name)
                                    members.append(new_name)
                                    seen.add(new_name)
                                    altered = True
                                    created_objs.append((new_name, mapped_net.with_prefixlen, "created shared subnet"))
                                    log_lines.append(f'Group {scope} address-group "{gname}": CREATED and appended subnet {new_name} = {mapped_net.with_prefixlen}')

            # --- Host/range mapping path (same logic as rules script) ---
            for rep in iter_object_rep_ips(meta):
                m = best_match_mapping(rep, mappings)
                if not m:
                    continue
                old_obj, new_obj, kind = m
                new_ip = convert_ip(rep, old_obj, new_obj, kind)
                if not new_ip:
                    continue

                # Check if already covered by existing objects in this group
                covered = False
                for name in members:
                    mm = addr_objs.get(name)
                    if mm and mm["type"] == "ip-netmask":
                        if new_ip in mm["cidr"]:
                            covered = True
                            break
                    elif mm and mm["type"] == "ip-range":
                        if int(mm["start"]) <= int(new_ip) <= int(mm["end"]):
                            covered = True
                            break
                if covered:
                    continue
                # optional: nested coverage (best-effort)
                if group_covers_ip(members, addr_objs, groups):
                    continue

                hkey = key_for_host(new_ip)
                candidates = rev.get(hkey, set())
                chosen = choose_existing_object(candidates, addr_objs)
                if chosen:
                    if chosen not in seen:
                        members.append(chosen)
                        seen.add(chosen)
                        altered = True
                        log_lines.append(f'Group {scope} address-group "{gname}": appended EXISTING host {chosen} = {new_ip}')
                    continue

                # create shared host object
                base = host_name_for(new_ip)
                new_name = unique_object_name(base, addr_objs)
                cidr_text = f"{new_ip}/32" if isinstance(new_ip, IPv4Address) else f"{new_ip}/128"
                new_net = ip_network(cidr_text, strict=False)

                addr_objs[new_name] = {"scope": "shared", "type": "ip-netmask", "cidr": new_net}
                rev.setdefault(hkey, set()).add(new_name)
                rev.setdefault(key_for_net(new_net), set()).add(new_name)

                members.append(new_name)
                seen.add(new_name)
                altered = True
                created_objs.append((new_name, cidr_text, "created shared host"))
                log_lines.append(f'Group {scope} address-group "{gname}": CREATED and appended host {new_name} = {cidr_text}')

        # Deduplicate equal spaces within the group's direct members
        if members:
            deduped, removed = dedupe_list_by_ipspace(members, addr_objs)
            if deduped != members:
                g["members"] = deduped
                g["seen"] = set(deduped)
                altered = True
                for dup, kept in removed:
                    log_lines.append(f'Dedup group {scope} "{gname}": removed "{dup}" (same IP space as "{kept}")')

        if altered:
            changed_groups.add((scope, gname))

    # -------- Outputs --------
    # 1) Full static lines for modified groups
    with open(args.out_groups, "w", encoding="utf-8") as outf:
        for (scope, gname), g in groups.items():
            if (scope, gname) not in changed_groups:
                continue
            members = g["members"]
            if not members:
                continue
            name_disp = f'"{gname}"' if (' ' in gname or '"' in gname) else gname
            bracketed = " ".join(members)
            if scope == "shared":
                outf.write(f'set shared address-group {name_disp} static [ {bracketed} ]\n')
            else:
                outf.write(f'set device-group {scope} address-group {name_disp} static [ {bracketed} ]\n')

    # 2) Object creates (shared)
    with open(args.out_creates, "w", encoding="utf-8") as outf:
        for name, cidr_text, _ in created_objs:
            outf.write(f'set shared address {name} ip-netmask {cidr_text}\n')

    # 3) Log
    with open(args.log, "w", encoding="utf-8") as lf:
        if not changed_groups:
            lf.write("No address groups required edits based on provided mappings.\n")
        else:
            lf.write(f"Address groups modified: {len(changed_groups)}\n")
            for line in log_lines:
                lf.write(line + "\n")

    # Stderr summary
    if not changed_groups:
        print("# No address groups required edits; outputs written but empty.", file=sys.stderr)
    else:
        print(f'# Wrote group edits to {args.out_groups}', file=sys.stderr)
        if created_objs:
            print(f'# Wrote {len(created_objs)} object create lines to {args.out_creates}', file=sys.stderr)
        print(f'# Log written to {args.log}', file=sys.stderr)

if __name__ == "__main__":
    main()
