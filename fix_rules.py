#!/usr/bin/env python3
import re
import sys
import csv
import argparse
from ipaddress import ip_network, ip_address, IPv4Network, IPv6Network, IPv4Address, IPv6Address

RULE_SCOPE_RE = re.compile(
    r'^set\s+device-group\s+(?P<dg>\S+)\s+(?P<prepost>pre-rulebase|post-rulebase)\s+security\s+rules\s+(?P<rule>\".*?\"|\S+)'
)

# Address object patterns:
# 1) set device-group <dg> address <name> ip-netmask <cidr>
# 2) set device-group <dg> address <name> ip-range <start>-<end>
# 3) (Shared) set address <name> ip-netmask <cidr>
# 4) (Shared) set address <name> ip-range <start>-<end>
ADDR_OBJ_IPNET_RE = re.compile(
    r'^set\s+(?:device-group\s+(?P<dg>\S+)\s+)?address\s+(?P<name>\".*?\"|\S+)\s+ip-netmask\s+(?P<cidr>\S+)\s*$'
)
ADDR_OBJ_RANGE_RE = re.compile(
    r'^set\s+(?:device-group\s+(?P<dg>\S+)\s+)?address\s+(?P<name>\".*?\"|\S+)\s+ip-range\s+(?P<start>\S+)\s*-\s*(?P<end>\S+)\s*$'
)

# Rule member lines. Examples:
# set device-group DG pre-rulebase security rules R source any
# set device-group DG pre-rulebase security rules R source [ A B C ]
# set device-group DG pre-rulebase security rules R source A
# ... same for destination
RULE_MEMBER_RE = re.compile(
    r'^set\s+device-group\s+(?P<dg>\S+)\s+(?P<prepost>pre-rulebase|post-rulebase)\s+security\s+rules\s+(?P<rule>\".*?\"|\S+)\s+(?P<which>source|destination)\s+(?P<value>.+?)\s*$'
)

BRACKETS_RE = re.compile(r'^\[\s*(.*?)\s*\]$')

def unquote(s: str) -> str:
    if s and len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s

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
      - single IP to single IP
      - subnet to subnet (host bits preserved on conversion)
    """
    mappings = []
    with open(csv_path, newline='') as f:
        rdr = csv.reader(f)
        for row in rdr:
            if not row or len(row) < 2:
                continue
            old_s = row[0].strip()
            new_s = row[1].strip()
            # Determine if IP or subnet
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
                    if old_net.version != new_net.version or old_net.prefixlen != new_net.prefixlen:
                        # We can still support different prefix lengths, but preserving host bits
                        # only makes sense if new prefix <= old prefix. We'll allow any and just
                        # map by host offset within old onto new if capacity allows; otherwise skip.
                        pass
                    mappings.append((old_net, new_net, "subnet"))
                else:
                    # Mixed types not supported (e.g., IP -> subnet or subnet -> IP)
                    # You can relax this if needed.
                    continue
            except ValueError:
                continue
    return mappings

def ip_in_range_or_net(ip: IPv4Address|IPv6Address, start, end):
    # start/end are ip_address
    return start <= ip <= end

def iter_addrobj_ips(entry):
    """
    entry = {"type": "ip-netmask"|"ip-range", "cidr": IPv[4|6]Network, "start": ip_address, "end": ip_address}
    Yields representative IPs to test membership (for matching against "old side").
    We will:
      - For ip-netmask: if it's a single host (/32 or /128), yield that IP.
                        Otherwise, yield the network's usable host addresses (but that's huge) — instead
                        yield just *one* canonical IP (the first host) for membership testing.
                        For translating, we map that representative IP to the new space and remember the *network*.
      - For ip-range: yield the start and end and, if possible, mid.
    """
    t = entry["type"]
    if t == "ip-netmask":
        net = entry["cidr"]
        if (isinstance(net, IPv4Network) and net.prefixlen == 32) or (isinstance(net, IPv6Network) and net.prefixlen == 128):
            yield list(net.hosts())[0] if net.num_addresses > 2 else net.network_address
        else:
            # representative IP: first usable host if any, else network address
            try:
                host_iter = net.hosts()
                first_host = next(host_iter)
                yield first_host
            except StopIteration:
                yield net.network_address
    elif t == "ip-range":
        start = entry["start"]
        end = entry["end"]
        yield start
        if end != start:
            # try a middle point for better detection
            try:
                if isinstance(start, IPv4Address) and isinstance(end, IPv4Address):
                    s_int = int(start)
                    e_int = int(end)
                    mid = IPv4Address((s_int + e_int) // 2)
                    if mid != start and mid != end:
                        yield mid
                elif isinstance(start, IPv6Address) and isinstance(end, IPv6Address):
                    s_int = int(start)
                    e_int = int(end)
                    mid = IPv6Address((s_int + e_int) // 2)
                    if mid != start and mid != end:
                        yield mid
            except Exception:
                pass
        yield end

def convert_ip(old_ip, old_obj, new_obj, map_type):
    """
    Returns converted IP (ip_address) or None.
    - ip mapping: exact old_ip -> new_ip
    - subnet mapping: keep host offset within old subnet, apply to new subnet (if fits)
    """
    if map_type == "ip":
        if old_ip == old_obj:
            return new_obj
        return None
    elif map_type == "subnet":
        old_net = old_obj
        new_net = new_obj
        if old_ip in old_net:
            host_off = int(old_ip) - int(old_net.network_address)
            # Ensure capacity in new_net
            if host_off < new_net.num_addresses:
                return type(new_net.network_address)(int(new_net.network_address) + host_off)
    return None

def best_match_mapping(ip_or_net_repr, mappings):
    """
    Try to find a mapping that applies to the given representative IP.
    Prefer most-specific subnet match if multiple.
    """
    candidates = []
    for old_obj, new_obj, t in mappings:
        if t == "ip":
            if isinstance(ip_or_net_repr, (IPv4Address, IPv6Address)) and ip_or_net_repr == old_obj:
                candidates.append((old_obj, new_obj, t, getattr(old_obj, 'max_prefixlen', 128)))
        else:
            # subnet
            if isinstance(ip_or_net_repr, (IPv4Address, IPv6Address)) and ip_or_net_repr in old_obj:
                candidates.append((old_obj, new_obj, t, old_obj.prefixlen))
    if not candidates:
        return None
    # choose most specific (largest prefixlen)
    candidates.sort(key=lambda x: x[3], reverse=True)
    return candidates[0][:3]  # (old_obj, new_obj, t)

def parse_set_config(path):
    """
    Returns:
      addr_objs: dict[name] = {"scope": "shared" or device-group, "type": "ip-netmask"/"ip-range", "cidr" or "start"/"end"}
      rules: dict[(dg, prepost, rule_name)] = {"source": set([...]), "destination": set([...])}
    """
    addr_objs = {}
    rules = {}

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            s = line.strip()
            if not s or not s.startswith('set '):
                continue

            # Address objects
            m = ADDR_OBJ_IPNET_RE.match(s)
            if m:
                dg = m.group('dg')
                scope = dg if dg else 'shared'
                name = unquote(m.group('name'))
                cidr = m.group('cidr')
                try:
                    net = ip_network(cidr, strict=False)
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

            # Rule members
            m = RULE_MEMBER_RE.match(s)
            if m:
                dg = m.group('dg')
                prepost = m.group('prepost')
                rule = unquote(m.group('rule'))
                which = m.group('which')
                rawval = m.group('value').strip()
                members = parse_member_values(rawval)

                key = (dg, prepost, rule)
                rules.setdefault(key, {"source": set(), "destination": set()})
                # Store list as seen; "any" is treated as a literal token meaning nothing to append-check against
                # (we still can add new objects to such a rule by emitting another set line).
                for mem in members:
                    rules[key][which].add(mem)

                continue

    return addr_objs, rules

def build_reverse_lookup(addr_objs):
    """
    Build reverse index so we can find address object names by exact IP/subnet definition.
    Keys are strings for normalized shapes to make lookup easy:
      - ip-netmask: 'net:version:network/prefixlen' (e.g., net:4:10.0.0.0/24)
      - ip-range: 'range:version:start-end'
    """
    rev = {}
    for name, meta in addr_objs.items():
        if meta["type"] == "ip-netmask":
            net = meta["cidr"]
            key = f'net:{4 if isinstance(net, IPv4Network) else 6}:{net.with_prefixlen}'
        else:
            start = meta["start"]
            end = meta["end"]
            ver = 4 if isinstance(start, IPv4Address) else 6
            key = f'range:{ver}:{start}-{end}'
        rev.setdefault(key, set()).add(name)
    return rev

def key_for_ip_or_net(obj):
    """
    Accepts:
      - ip_address (single IP) -> return exact /32 (v4) or /128 (v6) network key
      - ip_network -> return that network key
    """
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
    ap = argparse.ArgumentParser(description="Convert rule address members by old→new mappings and append existing objects for the converted addresses.")
    ap.add_argument("--config", required=True, help="Panorama set-format configuration file")
    ap.add_argument("--mapping", required=True, help="CSV file with rows: old,new (old/new are single IPs or CIDR subnets)")
    ap.add_argument("--emit-scope", choices=["all","pre","post"], default="all", help="Limit to pre/post/all security rules when emitting additions")
    args = ap.parse_args()

    mappings = load_map(args.mapping)
    if not mappings:
        print("# No valid mappings found. Nothing to do.", file=sys.stderr)
        return

    addr_objs, rules = parse_set_config(args.config)
    rev = build_reverse_lookup(addr_objs)

    additions = []  # tuples of (dg, prepost, rule, which, obj_to_add)

    for (dg, prepost, rule), sides in rules.items():
        if args.emit_scope == "pre" and prepost != "pre-rulebase":
            continue
        if args.emit_scope == "post" and prepost != "post-rulebase":
            continue

        for which in ("source", "destination"):
            existing = sides[which]

            # For each member, if it is an address object we know, resolve and try to map
            for member in list(existing):
                if member == "any":
                    # "any" doesn't resolve to an object; but we can still append converted objects later.
                    continue
                meta = addr_objs.get(member)
                if not meta:
                    # Not an address object we have — skip (could be group/FQDN/user/etc.)
                    continue

                # Figure out a representative IP for mapping detection
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

                # We have a mapping; now decide what exact "converted address" to look for as an existing object.
                # If the source object is a single-IP / host, convert that IP.
                # If it's a network, keep network size and try an exact network match if mapping is subnet→subnet
                # If it's a range, convert its representative IP and look for exact single-IP object (most reliable).
                to_lookup_keys = set()

                if meta["type"] == "ip-netmask":
                    net = meta["cidr"]
                    if (isinstance(net, IPv4Network) and net.prefixlen in (32,)) or (isinstance(net, IPv6Network) and net.prefixlen in (128,)):
                        # Single host
                        # Convert the host IP using the mapping; if we get a new IP, look for an object with that /32 (or /128)
                        host_ip = list(net.hosts())[0] if net.num_addresses > 2 else net.network_address
                        new_ip = convert_ip(host_ip, old_obj, new_obj, t)
                        if new_ip:
                            k = key_for_ip_or_net(new_ip)
                            if k:
                                to_lookup_keys.add(k)
                    else:
                        # A subnet object — map its representative IP and try to align to the mapped subnet if mapping is subnet→subnet.
                        # Best we can do deterministically: if mapping type is subnet and the object net is fully contained in old subnet,
                        # attempt to translate the network address by host offset 0 and keep the same prefix length.
                        if t == "subnet":
                            if net.network_address in old_obj or net.subnet_of(old_obj):
                                # Translate the network address (offset 0)
                                trans_net_addr = convert_ip(net.network_address, old_obj, new_obj, t)
                                if trans_net_addr:
                                    try:
                                        new_net = ip_network(f"{trans_net_addr}/{net.prefixlen}", strict=False)
                                        k = key_for_ip_or_net(new_net)
                                        if k:
                                            to_lookup_keys.add(k)
                        else:
                            # Mapping was single IP → single IP; for a network object we can't reliably translate.
                            pass

                elif meta["type"] == "ip-range":
                    # Convert start/end/mid; if any converts, look for exact single-IP objects for those.
                    for test_ip in iter_addrobj_ips(meta):
                        new_ip = convert_ip(test_ip, old_obj, new_obj, t)
                        if new_ip:
                            k = key_for_ip_or_net(new_ip)
                            if k:
                                to_lookup_keys.add(k)

                # For each lookup key, find objects and schedule additions (skip if already present)
                for k in to_lookup_keys:
                    obj_names = rev.get(k, set())
                    for obj_name in sorted(obj_names):
                        if obj_name not in existing:
                            additions.append((dg, prepost, rule, which, obj_name))
                            # Also mark as present to avoid duplicate emissions for the same rule/side
                            existing.add(obj_name)

    # Emit set commands
    # We will emit one line per added member:
    # set device-group <dg> <pre|post>-rulebase security rules <rule> <which> <obj_name>
    # (Panorama tolerates repeated 'set ... source <member>' lines to append into the list.)
    for dg, prepost, rule, which, obj in additions:
        rule_disp = f'"{rule}"' if ' ' in rule or '"' in rule else rule
        print(f'set device-group {dg} {prepost} security rules {rule_disp} {which} {obj}')

    if not additions:
        print("# No additions required based on the provided mappings.", file=sys.stderr)

if __name__ == "__main__":
    main()
