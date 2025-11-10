#!/usr/bin/env python3
import os
import re
import ipaddress
from ipaddress import (
    ip_network, ip_address,
    IPv4Network, IPv6Network, IPv4Address, IPv6Address
)

CONFIG_FILE       = "panorama.set"
TRANSLATION_FILE  = "translation.input"
OUT_RULE_EDITS    = "rule_edits.set"
OUT_OBJ_CREATES   = "object_creates.set"
LOG_FILE          = "translate_sec_rules.log"

# -------------------- Regexes --------------------
ADDR_OBJ_IPNET_RE = re.compile(
    r'^set\s+(?:(?:device-group\s+(?P<dg>\S+)\s+)|(?:shared\s+))?address\s+(?P<name>"[^"]+"|\S+)\s+ip-netmask\s+(?P<cidr>\S+)\s*$',
    re.IGNORECASE
)
ADDR_OBJ_RANGE_RE = re.compile(
    r'^set\s+(?:(?:device-group\s+(?P<dg>\S+)\s+)|(?:shared\s+))?address\s+(?P<name>"[^"]+"|\S+)\s+ip-range\s+(?P<start>\S+)\s*-\s*(?P<end>\S+)\s*$',
    re.IGNORECASE
)
RULE_MEMBER_RE = re.compile(
    r'^set\s+device-group\s+(?P<dg>\S+)\s+(?P<prepost>pre-rulebase|post-rulebase)\s+security\s+rules\s+(?P<rule>"[^"]+"|\S+)\s+(?P<which>source|destination)\s+(?P<value>.+?)\s*$',
    re.IGNORECASE
)
BRACKETS_RE = re.compile(r'^\[\s*(.*?)\s*\]$')

# ----------------- Translation load -----------------
def load_translation():
    one_to_one = {}
    networks   = []  # list[(old_net,new_net)]
    ranges     = []  # list[(start,end,rhs_type,rhs_val)]
    with open(TRANSLATION_FILE, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw or "," not in raw:
                continue
            orig, new = [p.strip() for p in raw.split(",", 1)]

            if "-" in orig and "/" not in orig:
                try:
                    s_txt, e_txt = [p.strip() for p in orig.split("-", 1)]
                    s = ip_address(s_txt); e = ip_address(e_txt)
                    if type(s) is type(e) and int(s) <= int(e):
                        try:
                            rhs_ip = ip_address(new); ranges.append((s, e, "ip", rhs_ip))
                        except ValueError:
                            try:
                                rhs_net = ip_network(new, strict=False); ranges.append((s, e, "subnet", rhs_net))
                            except ValueError:
                                pass
                except ValueError:
                    pass
                continue

            if "/" in orig:
                try:
                    old_net = ip_network(orig, strict=False)
                    new_net = ip_network(new, strict=False)
                    if old_net.version == new_net.version:
                        networks.append((old_net, new_net))
                except ValueError:
                    pass
                continue

            try:
                old_ip = ip_address(orig); new_ip = ip_address(new)
                if old_ip.version == new_ip.version:
                    one_to_one[str(old_ip)] = new_ip
            except ValueError:
                pass

    networks.sort(key=lambda t: t[0].prefixlen, reverse=True)
    return one_to_one, networks, ranges

# ----------------- Utilities -----------------
def unquote(s: str) -> str:
    return s[1:-1] if s and s[0] == '"' and s[-1] == '"' else s

def parse_member_values(raw: str):
    raw = raw.strip()
    m = BRACKETS_RE.match(raw)
    if m:
        inner = m.group(1).strip()
        return [t for t in inner.split() if t]
    return [raw]

def iter_rep_ips_for_obj(meta):
    if meta["type"] == "ip-netmask":
        net = meta["cidr"]
        if isinstance(net, IPv4Network) and net.prefixlen == 32:
            return [net.network_address]
        if isinstance(net, IPv6Network) and net.prefixlen == 128:
            return [net.network_address]
        try:
            return [next(net.hosts())]
        except StopIteration:
            return [net.network_address]
    else:
        start = meta["start"]; end = meta["end"]
        if start == end:
            return [start]
        mid = type(start)((int(start) + int(end)) // 2)
        reps = [start]
        if mid != start and mid != end:
            reps.append(mid)
        reps.append(end)
        return reps

def normalize_space(meta):
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

def dedupe_side_by_ipspace(order, addr_objs):
    seen = {}
    out = []
    removed = []
    for name in order:
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

def side_covers_ip(members, addr_objs, ip):
    if any(m == "any" for m in members):
        return True
    for name in members:
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

def key_for_exact_host(ip):
    if isinstance(ip, IPv4Address):
        return f"net:4:{IPv4Network(str(ip)+'/32').with_prefixlen}"
    else:
        return f"net:6:{IPv6Network(str(ip)+'/128').with_prefixlen}"

def key_for_exact_net(net):
    return f"net:{4 if isinstance(net, IPv4Network) else 6}:{net.with_prefixlen}"

def choose_existing_object(names, addr_objs):
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
    # v6 fallback (underscored + prefix length)
    return "svb_net_" + str(net.network_address).replace(":", "_")[:80] + f"_{net.prefixlen}"

def unique_name(base, addr_objs):
    if base not in addr_objs:
        return base
    i = 2
    while True:
        cand = f"{base}_v{i}"
        if cand not in addr_objs:
            return cand
        i += 1

# --------------- Mapping logic ----------------
def best_mapping_for_ip(ip, one_to_one, networks, ranges):
    # exact
    s = str(ip)
    if s in one_to_one:
        return ("ip", ip, one_to_one[s])
    # most-specific subnet
    for old_net, new_net in networks:
        if ip in old_net:
            return ("subnet", old_net, new_net)
    # ranges
    for start, end, rhs_type, rhs_val in ranges:
        if type(start) is type(ip) and int(start) <= int(ip) <= int(end):
            if rhs_type == "ip":
                return ("range_ip", (start, end), rhs_val)
            else:
                return ("range_subnet", (start, end), rhs_val)
    return None

def convert_with_mapping(ip, kind, old_obj, new_obj):
    if kind == "ip":
        return new_obj
    if kind == "subnet":
        off = int(ip) - int(old_obj.network_address)
        if off < new_obj.num_addresses:
            return type(new_obj.network_address)(int(new_obj.network_address) + off)
    if kind == "range_ip":
        return new_obj
    if kind == "range_subnet":
