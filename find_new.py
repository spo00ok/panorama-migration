#!/usr/bin/env python3
import re
import sys
import csv
import argparse
from ipaddress import (
    ip_network, ip_address,
    IPv4Network, IPv6Network, IPv4Address, IPv6Address
)

# ---------- Regexes ----------

# Address objects (DG or shared)
ADDR_OBJ_IPNET_RE = re.compile(
    r'^set\s+(?:(?:device-group\s+(?P<dg>\S+)\s+)|(?:shared\s+))?address\s+(?P<name>\".*?\"|\S+)\s+ip-netmask\s+(?P<cidr>\S+)\s*$',
    re.IGNORECASE
)
ADDR_OBJ_RANGE_RE = re.compile(
    r'^set\s+(?:(?:device-group\s+(?P<dg>\S+)\s+)|(?:shared\s+))?address\s+(?P<name>\".*?\"|\S+)\s+ip-range\s+(?P<start>\S+)\s*-\s*(?P<end>\S+)\s*$',
    re.IGNORECASE
)

# Rule member lines
RULE_MEMBER_RE = re.compile(
    r'^set\s+device-group\s+(?P<dg>\S+)\s+(?P<prepost>pre-rulebase|post-rulebase)\s+security\s+rules\s+(?P<rule>\".*?\"|\S+)\s+(?P<which>source|destination)\s+(?P<value>.+?)\s*$'
)

BRACKETS_RE = re.compile(r'^\[\s*(.*?)\s*\]$')

# ---------- Helpers ----------

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
                    # Mixed IP<->subnet rows are ignored by design
                    continue
            except ValueError:
                continue
    return mappings

def best_match_mapping(ip, mappings):
    """
    Given an IP address, choose the most-specific mapping that applies.
    Preference: exact IP match, else most-specific subnet (largest prefixlen) containing IP.
    """
    candidates = []
    for old_obj, new_obj, kind in mappings:
        if kind == "ip":
            if ip == old_obj:
                candidates.append((old_obj, new_obj, kind, 999))  # highest specificity
        else:
            if ip in old_obj:
                candidates.append((old_obj, new_obj, kind, old_obj.prefixlen))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[3], reverse=True)
    return candidates[0][:3]  # (old_obj, new_obj, kind)

def convert_ip(old_ip, old_obj, new_obj, kind):
    if kind == "ip":
        return new_obj if old_ip == old_obj else None
    # subnet mapping: preserve host offset
    if old_ip in old_obj:
        off = int(old_ip) - int(old_obj.network_address)
        if off < new_obj.num_addresses:
            return type(new_obj.network_address)(int(new_obj.network_address) + off)
    return None

def parse_set_config(path):
    """
    Parse set-format config into:
      addr_objs: name -> {scope, type, cidr|start/end}
      rules: (dg, prepost, rule) -> {"source": {"order":[...],"seen":set()}, "destination": {...}}
    """
    addr_objs = {}
    rules = {}

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

            m = RULE_MEMBER_RE.match(s)
            if m:
                dg = m.group('dg')
                prepost = m.group('prepost')
                rule = unquote(m.group('rule'))
                which = m.group('which')
                values = parse_member_values(m.group('value'))

                key = (dg, prepost, rule)
                rules.setdefault(key, {
                    "source": {"order": [], "seen": set()},
                    "destination": {"order": [], "seen": set()},
                })
                side = rules[key][which]
                for mem in values:
                    if mem not in side["seen"]:
                        side["order"].append(mem)
                        side["seen"].add(mem)
                continue

    return addr_objs, rules

def side_contains_ip(side_members, addr_objs, ip):
    """
    True if 'any' present or any known address object in side includes ip.
    """
    if any(m == "any" for m in side_members):
        return True
    for name in side_members:
        meta = addr_objs.get(name)
        if not meta:
            continue
        if meta["type"] == "ip-netmask":
            if ip in meta["cidr"]:
                return True
        else:
            if int(meta["start"]) <= int(ip) <= int(meta["end"]):
                return True
    return False

def iter_object_rep_ips(meta):
    """
    Produce representative host IP(s) for an address object to test mapping applicability.
    - host /32 or /128: that IP
    - subnet: first usable host if any, else network address
    - range: start, mid (if distinct), end
    """
    if meta["type"] == "ip-netmask":
        net = meta["cidr"]
        # host?
        if (isinstance(net, IPv4Network) and net.prefixlen == 32) or (isinstance(net, IPv6Network) and net.prefixlen == 128):
            # For /32, .hosts() is empty; use network_address
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
            mid_int = (int(start) + int(end)) // 2
            mid = type(start)(mid_int)
            if mid != start and mid != end:
                yield mid
        yield end

def build_rev_index(addr_objs):
    """
    Reverse map: normalized key -> set(names)
    Only keys we actually need: exact host networks (/32 or /128) and literal ranges.
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
    if isinstance(ip, IPv4Address):
        return f'net:4:{IPv4Network(str(ip)+"/32").with_prefixlen}'
    else:
        return f'net:6:{IPv6Network(str(ip)+"/128").with_prefixlen}'

def normalize_space(meta):
    """
    Compare-by-space key for dedupe: (ver, start_int, end_int)
    """
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

def dedupe_side_by_ipspace(members_order, addr_objs):
    """
    Remove later members with identical IP space to an earlier member.
    """
    seen = {}
    out = []
    removed = []
    for name in members_order:
        meta = addr_objs.get(name)
        if not meta:
            out.append(name)
            continue
        key = normalize_space(meta)
        if key in seen:
            removed.append((name, seen[key]))
            continue
        seen[key] = name
        out.append(name)
    return out, removed

def choose_existing_host_object(names, addr_objs):
    """
    From a set of object names that exactly equal a host /32 (/128), prefer 'shared' scope.
    """
    if not names:
        return None
    shared = [n for n in names if addr_objs.get(n, {}).get("scope") == "shared"]
    if shared:
        return sorted(shared)[0]
    return sorted(names)[0]

def host_name_for(ip):
    """
    svb_host_X_X_X_X for IPv4. For IPv6, replace ':' with '_' and trim to a sane length.
    """
    if isinstance(ip, IPv4Address):
        parts = str(ip).split('.')
        return f"svb_host_{'_'.join(parts)}"
    else:
        safe = str(ip).replace(":", "_")
        return f"svb_host_{safe[:100]}"

def unique_object_name(base_name, addr_objs):
    """
    Ensure the created name doesn't clash with an existing object of different value.
    If base exists and is identical host /32, reuse it; else append suffixes _v2, _v3...
    """
    if base_name not in addr_objs:
        return base_name
    # If exists AND is same ip /32 we will reuse it (caller will check via reverse index),
    # otherwise pick a new unique suffix.
    i = 2
    while True:
        cand = f"{base_name}_v{i}"
        if cand not in addr_objs:
            return cand
        i += 1

def main():
    ap = argparse.ArgumentParser(
        description="Map/append per rule: ensure converted host IP is present; create shared svb_host_X_X_X_X if needed; write bracketed rule edits & creation lines; log everything."
    )
    ap.add_argument("--config", required=True, help="Panorama set-format configuration file")
    ap.add_argument("--mapping", required=True, help="CSV: old,new (IP->IP or CIDR->CIDR)")
    ap.add_argument("--out-rules", default="rule_edits.set", help="Output: bracketed rule edits")
    ap.add_argument("--out-creates", default="object_creates.set", help="Output: newly created shared address objects")
    ap.add_argument("--log", default="rule_edits.log", help="Log file for edits")
    ap.add_argument("--emit-scope", choices=["all","pre","post"], default="all", help="Limit to pre/post/all rulebases in output")
    args = ap.parse_args()

    mappings = load_map(args.mapping)
    if not mappings:
        print("# No valid mappings found in mapping CSV.", file=sys.stderr)
        sys.exit(1)

    addr_objs, rules = parse_set_config(args.config)
    rev = build_rev_index(addr_objs)

    # Track changes
    created_objs = []   # tuples: (name, ip, note)
    changed_sides = set()  # (dg, prepost, rule, which)
    log_lines = []

    # Work through each rule side
    for (dg, prepost, rule), sides in rules.items():
        if args.emit_scope == "pre" and prepost != "pre-rulebase":
            continue
        if args.emit_scope == "post" and prepost != "post-rulebase":
            continue

        for which in ("source", "destination"):
            members = sides[which]["order"]
            seen = sides[which]["seen"]

            # If 'any' present, the converted IP is already allowed; skip
            if len(members) == 1 and members[0] == "any":
                continue

            # For each existing member that is an address object, see if a mapping applies
            # and if so, ensure the converted *host* IP is represented in the side
            added_here = False
            for name in list(members):  # iterate a copy
                meta = addr_objs.get(name)
                if not meta:
                    continue

                # Consider representative host IPs for mapping applicability
                for rep in iter_object_rep_ips(meta):
                    m = best_match_mapping(rep, mappings)
                    if not m:
                        continue
                    old_obj, new_obj, kind = m
                    new_ip = convert_ip(rep, old_obj, new_obj, kind)
                    if not new_ip:
                        continue

                    # Only work with host objects (/32 or /128). If IPv6, still allowed.
                    # If the side already contains this IP space (any object covering it), skip.
                    if side_contains_ip(members, addr_objs, new_ip):
                        continue

                    # Try to find an existing EXACT host object
                    k = key_for_host(new_ip)
                    candidates = rev.get(k, set())
                    chosen = choose_existing_host_object(candidates, addr_objs)

                    if chosen:
                        if chosen not in seen:
                            members.append(chosen)
                            seen.add(chosen)
                            added_here = True
                            log_lines.append(f'Edited: device-group {dg} {prepost} rule "{rule}" {which}: appended EXISTING object {chosen} = {new_ip}')
                        continue

                    # Need to create a new shared object
                    base_name = host_name_for(new_ip)
                    # If a same-value object with base_name already exists, rev-index would have found it.
                    # So only conflict left is name collision with different value; make it unique.
                    new_name = unique_object_name(base_name, addr_objs)

                    # Record creation; add to in-memory structures so downstream logic sees it
                    # Create as ip-netmask host /32 or /128
                    if isinstance(new_ip, IPv4Address):
                        cidr_text = f"{new_ip}/32"
                    else:
                        cidr_text = f"{new_ip}/128"

                    addr_objs[new_name] = {"scope": "shared", "type": "ip-netmask", "cidr": ip_network(cidr_text, strict=False)}
                    # Update reverse index
                    rev_key = key_for_host(new_ip)
                    rev.setdefault(rev_key, set()).add(new_name)

                    # Append to side
                    members.append(new_name)
                    seen.add(new_name)
                    added_here = True
                    created_objs.append((new_name, cidr_text, "created shared host"))
                    log_lines.append(f'Edited: device-group {dg} {prepost} rule "{rule}" {which}: CREATED and appended {new_name} = {cidr_text}')

            # After additions, dedupe equal IP spaces (keeps first)
            if members:
                deduped, removed = dedupe_side_by_ipspace(members, addr_objs)
                if deduped != members:
                    sides[which]["order"] = deduped
                    sides[which]["seen"] = set(deduped)
                    added_here = True
                    for dup, kept in removed:
                        log_lines.append(f'Dedup: device-group {dg} {prepost} rule "{rule}" {which}: removed "{dup}" (same IP space as "{kept}")')

            if added_here:
                changed_sides.add((dg, prepost, rule, which))

    # -------- Write outputs --------
    # 1) Rule edits (bracketed full-list lines)
    with open(args.out_rules, 'w', encoding='utf-8') as outf:
        for (dg, prepost, rule), sides in rules.items():
            if args.emit_scope == "pre" and prepost != "pre-rulebase":
                continue
            if args.emit_scope == "post" and prepost != "post-rulebase":
                continue
            for which in ("source", "destination"):
                if (dg, prepost, rule, which) not in changed_sides:
                    continue
                members = sides[which]["order"]
                if len(members) == 1 and members[0] == "any":
                    continue
                quoted_rule = f'"{rule}"' if (' ' in rule or '"' in rule) else rule
                outf.write(f'set device-group {dg} {prepost} security rules {quoted_rule} {which} [ {" ".join(members)} ]\n')

    # 2) Object creates (shared)
    with open(args.out_creates, 'w', encoding='utf-8') as outf:
        for name, cidr_text, _ in created_objs:
            # All created in shared
            outf.write(f'set shared address {name} ip-netmask {cidr_text}\n')

    # 3) Log file
    with open(args.log, 'w', encoding='utf-8') as lf:
        if not changed_sides:
            lf.write("No rules required edits based on provided mappings.\n")
        else:
            lf.write(f"Rule edits: {len(changed_sides)} side(s) modified\n")
            for line in log_lines:
                lf.write(line + "\n")

    # Stderr summary
    if not changed_sides:
        print("# No rule sides required edits; outputs written but empty.", file=sys.stderr)
    else:
        print(f'# Wrote rule edits to {args.out_rules}', file=sys.stderr)
        if created_objs:
            print(f'# Wrote {len(created_objs)} object create lines to {args.out_creates}', file=sys.stderr)
        print(f'# Log written to {args.log}', file=sys.stderr)

if __name__ == "__main__":
    main()
