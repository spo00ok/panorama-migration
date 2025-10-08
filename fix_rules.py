#!/usr/bin/env python3
import re
import sys
import csv
import argparse
from ipaddress import ip_network, ip_address, IPv4Network, IPv6Network, IPv4Address, IPv6Address

# --- Regexes ---

RULE_SCOPE_RE = re.compile(
    r'^set\s+device-group\s+(?P<dg>\S+)\s+(?P<prepost>pre-rulebase|post-rulebase)\s+security\s+rules\s+(?P<rule>\".*?\"|\S+)'
)

# Accept DG and SHARED ("set shared address ...")
ADDR_OBJ_IPNET_RE = re.compile(
    r'^set\s+(?:(?:device-group\s+(?P<dg>\S+)\s+)|(?:shared\s+))?address\s+(?P<name>\".*?\"|\S+)\s+ip-netmask\s+(?P<cidr>\S+)\s*$',
    re.IGNORECASE
)
ADDR_OBJ_RANGE_RE = re.compile(
    r'^set\s+(?:(?:device-group\s+(?P<dg>\S+)\s+)|(?:shared\s+))?address\s+(?P<name>\".*?\"|\S+)\s+ip-range\s+(?P<start>\S+)\s*-\s*(?P<end>\S+)\s*$',
    re.IGNORECASE
)

# Rule member lines (source/destination)
RULE_MEMBER_RE = re.compile(
    r'^set\s+device-group\s+(?P<dg>\S+)\s+(?P<prepost>pre-rulebase|post-rulebase)\s+security\s+rules\s+(?P<rule>\".*?\"|\S+)\s+(?P<which>source|destination)\s+(?P<value>.+?)\s*$'
)

BRACKETS_RE = re.compile(r'^\[\s*(.*?)\s*\]$')

# --- Helpers ---

def unquote(s: str) -> str:
    return s[1:-1] if s and len(s) >= 2 and s[0] == '"' and s[-1] == '"' else s

def parse_member_values(raw: str):
    raw = raw.strip()
    m = BRACKETS_RE.match(raw)
    if m:
        inner = m.group(1).strip()
        return [tok for tok in inner.split() if tok]
    return [raw]

def load_map(csv_path):
    """
    Returns list of (old_spec, new_spec, type) where type in {"ip","subnet"}.
    Supports:
      - single IP -> single IP
      - subnet -> subnet (host-bit preservation)
    """
    mappings = []
    with open(csv_path, newline='') as f:
        rdr = csv.reader(f)
        for row in rdr:
            if not row or len(row) < 2:
                continue
            old_s = row[0].strip()
            new_s = row[1].strip()
            old_is_ip = '/' not in old_s
            new_is_ip = '/' not in new_s
            try:
                if old_is_ip and new_is_ip:
                    old_obj = ip_address(old_s)
                    new_obj = ip_address(new_s)
                    mappings.append((old_obj, new_obj, "ip"))
                elif (not old_is_ip) and (not new_is_ip):
                    old_net = ip_network(old_s, strict=False)
                    new_net = ip_network(new_s, strict=False)
                    mappings.append((old_net, new_net, "subnet"))
                else:
                    # Mixed IP↔subnet not supported; skip
                    continue
            except ValueError:
                continue
    return mappings

def iter_addrobj_ips(entry):
    t = entry["type"]
    if t == "ip-netmask":
        net = entry["cidr"]
        if (isinstance(net, IPv4Network) and net.prefixlen == 32) or (isinstance(net, IPv6Network) and net.prefixlen == 128):
            yield list(net.hosts())[0] if net.num_addresses > 2 else net.network_address
        else:
            try:
                first_host = next(net.hosts())
                yield first_host
            except StopIteration:
                yield net.network_address
    elif t == "ip-range":
        start = entry["start"]; end = entry["end"]
        yield start
        if end != start:
            try:
                if isinstance(start, IPv4Address) and isinstance(end, IPv4Address):
                    mid = IPv4Address((int(start) + int(end)) // 2)
                    if mid != start and mid != end:
                        yield mid
                elif isinstance(start, IPv6Address) and isinstance(end, IPv6Address):
                    mid = IPv6Address((int(start) + int(end)) // 2)
                    if mid != start and mid != end:
                        yield mid
            except Exception:
                pass
        yield end

def convert_ip(old_ip, old_obj, new_obj, map_type):
    if map_type == "ip":
        return new_obj if old_ip == old_obj else None
    elif map_type == "subnet":
        if old_ip in old_obj:
            host_off = int(old_ip) - int(old_obj.network_address)
            if host_off < new_obj.num_addresses:
                return type(new_obj.network_address)(int(new_obj.network_address) + host_off)
    return None

def best_match_mapping(ip_or_net_repr, mappings):
    candidates = []
    for old_obj, new_obj, t in mappings:
        if t == "ip":
            if isinstance(ip_or_net_repr, (IPv4Address, IPv6Address)) and ip_or_net_repr == old_obj:
                candidates.append((old_obj, new_obj, t, getattr(old_obj, 'max_prefixlen', 128)))
        else:
            if isinstance(ip_or_net_repr, (IPv4Address, IPv6Address)) and ip_or_net_repr in old_obj:
                candidates.append((old_obj, new_obj, t, old_obj.prefixlen))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[3], reverse=True)
    return candidates[0][:3]

def parse_set_config(path):
    """
    Returns:
      addr_objs: dict[name] = {"scope": "shared" or device-group, "type": "ip-netmask"/"ip-range", "cidr" or "start"/"end"}
      rules: dict[(dg, prepost, rule_name)] = {
          "source": {"order": [..], "seen": set(..)},
          "destination": {"order": [..], "seen": set(..)}
      }
    """
    addr_objs = {}
    rules = {}

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if not s or not s.startswith('set '):
                continue

            m = ADDR_OBJ_IPNET_RE.match(s)
            if m:
                dg = m.group('dg')
                scope = dg if dg else 'shared'
                name = unquote(m.group('name'))
                try:
                    net = ip_network(m.group('cidr'), strict=False)
                except ValueError:
                    continue
                addr_objs[name] = {"scope": scope, "type": "ip-netmask", "cidr": net}
                continue

            m = ADDR_OBJ_RANGE_RE.match(s)
            if m:
                dg = m.group('dg')
                scope = dg if dg else 'shared'
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
                members = parse_member_values(m.group('value').strip())

                key = (dg, prepost, rule)
                rules.setdefault(key, {
                    "source": {"order": [], "seen": set()},
                    "destination": {"order": [], "seen": set()}
                })
                side = rules[key][which]
                for mem in members:
                    if mem not in side["seen"]:
                        side["order"].append(mem)
                        side["seen"].add(mem)
                continue

    return addr_objs, rules

def build_reverse_lookup(addr_objs, name_prefix):
    """
    Reverse index (value->names) for APPEND candidates.
    If name_prefix is provided, only include names starting with it.
    """
    rev = {}
    for name, meta in addr_objs.items():
        if name_prefix and not name.startswith(name_prefix):
            continue
        if meta["type"] == "ip-netmask":
            net = meta["cidr"]
            key = f'net:{4 if isinstance(net, IPv4Network) else 6}:{net.with_prefixlen}'
        else:
            start = meta["start"]; end = meta["end"]
            ver = 4 if isinstance(start, IPv4Address) else 6
            key = f'range:{ver}:{start}-{end}'
        rev.setdefault(key, set()).add(name)
    return rev

def _space_span(meta):
    """
    Normalize an address object's IP space to a comparable span:
      returns tuple: (version, start_int, end_int)
    Unifies:
      - /32 or /128 (single-host) with equivalent single-IP ranges
      - subnets with equivalent ranges (exact boundary match)
    """
    if meta["type"] == "ip-netmask":
        net = meta["cidr"]
        start = net.network_address
        # Last address in the network (works for v4 and v6)
        last_int = int(net.network_address) + net.num_addresses - 1
        end = type(start)(last_int)
        ver = 4 if isinstance(net, IPv4Network) else 6
        return (ver, int(start), int(end))
    else:
        start = meta["start"]; end = meta["end"]
        ver = 4 if isinstance(start, IPv4Address) else 6
        return (ver, int(start), int(end))

def dedupe_side_by_ipspace(members_order, addr_objs, rule_ident, which):
    """
    Remove later members whose IP space exactly equals an earlier member's IP space.
    Only applies to tokens that are known address objects (others are left untouched).
    Returns (new_order, removed_list) where removed_list is [(name, kept_name), ...].
    """
    seen_spaces = {}  # key -> kept_name
    new_order = []
    removed = []
    for name in members_order:
        meta = addr_objs.get(name)
        if not meta:
            new_order.append(name)
            continue
        key = _space_span(meta)
        if key in seen_spaces:
            removed.append((name, seen_spaces[key]))
            # skip (duplicate IP space)
        else:
            seen_spaces[key] = name
            new_order.append(name)
    if removed:
        for dup, kept in removed:
            print(f'# Dedup {rule_ident} {which}: removed "{dup}" (same IP space as "{kept}")', file=sys.stderr)
    return new_order, removed

def key_for_ip_or_net(obj):
    if isinstance(obj, (IPv4Address, IPv6Address)):
        if isinstance(obj, IPv4Address):
            net = IPv4Network(f'{obj}/32')
            return f'net:4:{net.with_prefixlen}'
        else:
            net = IPv6Network(f'{obj}/128')
            return f'net:6:{net.with_prefixlen}'
    elif isinstance(obj, (IPv4Network, IPv6Network)):
        ver = 4 if isinstance(obj, IPv4Network) else 6
        return f'net:{ver}:{obj.with_prefixlen}'
    return None

def main():
    ap = argparse.ArgumentParser(description="Convert rule address members by old→new mappings, append matching objects, and emit full-list bracketed lines.")
    ap.add_argument("--config", required=True, help="Panorama set-format configuration file")
    ap.add_argument("--mapping", required=True, help="CSV with rows: old,new  (old/new are single IPs or CIDR subnets)")
    ap.add_argument("--emit-scope", choices=["all","pre","post"], default="all", help="Limit to pre/post/all security rules when emitting")
    ap.add_argument("--out", default="rule_edits.set", help="Output file for generated config lines")
    ap.add_argument("--append-name-prefix", default="svb_host_", help="ONLY search for append candidates among address objects with this name prefix")
    args = ap.parse_args()

    mappings = load_map(args.mapping)
    if not mappings:
        print("# No valid mappings found. Nothing to do.", file=sys.stderr)
        return

    addr_objs, rules = parse_set_config(args.config)
    rev = build_reverse_lookup(addr_objs, args.append_name_prefix)

    # Track which sides changed (via append or dedupe)
    changed_sides = set()  # (dg, prepost, rule, which)

    # ------ Phase 1: append candidates after mapping ------
    for (dg, prepost, rule), sides in rules.items():
        if args.emit_scope == "pre" and prepost != "pre-rulebase":
            continue
        if args.emit_scope == "post" and prepost != "post-rulebase":
            continue

        for which in ("source", "destination"):
            side = sides[which]
            existing_order = side["order"]
            existing_seen = side["seen"]

            # If the side is exactly 'any', skip to avoid semantic changes.
            if len(existing_order) == 1 and existing_order[0] == "any":
                continue

            for member in list(existing_order):
                meta = addr_objs.get(member)
                if not meta:
                    continue  # unknown token (group/FQDN/etc.)

                # Find an applicable mapping based on representative IP(s)
                rep_ips = list(iter_addrobj_ips(meta))
                applied_mapping = None
                for rep_ip in rep_ips:
                    m = best_match_mapping(rep_ip, mappings)
                    if m:
                        applied_mapping = m  # (old_obj, new_obj, type)
                        break
                if not applied_mapping:
                    continue

                old_obj, new_obj, t = applied_mapping
                to_lookup_keys = set()

                if meta["type"] == "ip-netmask":
                    net = meta["cidr"]
                    if (isinstance(net, IPv4Network) and net.prefixlen == 32) or (isinstance(net, IPv6Network) and net.prefixlen == 128):
                        host_ip = list(net.hosts())[0] if net.num_addresses > 2 else net.network_address
                        new_ip = convert_ip(host_ip, old_obj, new_obj, t)
                        if new_ip:
                            k = key_for_ip_or_net(new_ip)
                            if k:
                                to_lookup_keys.add(k)
                    else:
                        if t == "subnet":
                            # Translate the network address and try to keep same prefixlen
                            if net.network_address in old_obj or net.subnet_of(old_obj):
                                trans_net_addr = convert_ip(net.network_address, old_obj, new_obj, t)
                                if trans_net_addr:
                                    try:
                                        new_net = ip_network(f"{trans_net_addr}/{net.prefixlen}", strict=False)
                                        k = key_for_ip_or_net(new_net)
                                        if k:
                                            to_lookup_keys.add(k)
                                    except ValueError:
                                        pass
                elif meta["type"] == "ip-range":
                    for test_ip in iter_addrobj_ips(meta):
                        new_ip = convert_ip(test_ip, old_obj, new_obj, t)
                        if new_ip:
                            k = key_for_ip_or_net(new_ip)
                            if k:
                                to_lookup_keys.add(k)

                # Only append objects whose names start with the given prefix (via rev index)
                appended_here = False
                for k in to_lookup_keys:
                    for obj_name in sorted(rev.get(k, set())):
                        if obj_name not in existing_seen:
                            existing_order.append(obj_name)
                            existing_seen.add(obj_name)
                            appended_here = True
                if appended_here:
                    changed_sides.add((dg, prepost, rule, which))

    # ------ Phase 2: dedupe equal IP spaces within each side ------
    for (dg, prepost, rule), sides in rules.items():
        if args.emit_scope == "pre" and prepost != "pre-rulebase":
            continue
        if args.emit_scope == "post" and prepost != "post-rulebase":
            continue

        for which in ("source", "destination"):
            side = sides[which]
            members = side["order"]

            # Skip semantic 'any'
            if len(members) == 1 and members[0] == "any":
                continue

            before = list(members)
            rule_ident = f'device-group {dg} {prepost} rules "{rule}"'
            deduped, removed = dedupe_side_by_ipspace(before, addr_objs, rule_ident, which)
            if deduped != before:
                side["order"] = deduped
                side["seen"] = set(deduped)
                changed_sides.add((dg, prepost, rule, which))

    # ------ Emit full-list bracketed lines for modified sides only ------
    out_path = args.out
    with open(out_path, 'w', encoding='utf-8') as outf:
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
                rule_disp = f'"{rule}"' if (' ' in rule or '"' in rule) else rule
                bracketed = " ".join(members)
                outf.write(f'set device-group {dg} {prepost} security rules {rule_disp} {which} [ {bracketed} ]\n')

    if not changed_sides:
        print("# No rule sides required edits; nothing written.", file=sys.stderr)
    else:
        print(f'# Wrote edits for {len(changed_sides)} rule side(s) to: {out_path}', file=sys.stderr)

if __name__ == "__main__":
    main()
