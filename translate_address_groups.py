#!/usr/bin/env python3
import os
import re
import ipaddress
import shlex
import shutil

CONFIG_FILE = "panorama.set"
TRANSLATION_FILE = "translation.input"
LOG_FILE = "translate_address_groups_append_objects.log"

# ----------------------------
# Translation helpers
# ----------------------------

def load_translation():
    """Load network-to-network mappings from translation.input"""
    mappings = []
    if not os.path.exists(TRANSLATION_FILE):
        return mappings
    with open(TRANSLATION_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or "," not in line:
                continue
            orig_str, new_str = [p.strip() for p in line.split(",", 1)]
            if "/" not in orig_str:
                orig_str += "/32"
            if "/" not in new_str:
                new_str += "/32"
            try:
                mappings.append(
                    (ipaddress.ip_network(orig_str, strict=False),
                     ipaddress.ip_network(new_str, strict=False))
                )
            except ValueError:
                continue
    return mappings

def translate_value(value, mappings):
    """Translate an IP/subnet/range using priority rules."""
    s = value.strip()

    # Range a-b
    if "-" in s:
        try:
            lo_s, hi_s = [p.strip() for p in s.split("-", 1)]
            lo = ipaddress.ip_address(lo_s)
            hi = ipaddress.ip_address(hi_s)
        except ValueError:
            return None
        new_lo = new_hi = None
        for src, dst in mappings:
            if lo in src and new_lo is None:
                off = int(lo) - int(src.network_address)
                new_lo = ipaddress.ip_address(int(dst.network_address) + off)
            if hi in src and new_hi is None:
                off = int(hi) - int(src.network_address)
                new_hi = ipaddress.ip_address(int(dst.network_address) + off)
            if new_lo and new_hi:
                break
        if new_lo and new_hi:
            return f"{new_lo}-{new_hi}"
        return None

    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None

    # 1: exact
    for src, dst in mappings:
        if str(net) == str(src):
            return str(dst)

    # 2: single IP in mapped net
    if net.prefixlen == net.max_prefixlen:
        ip = net.network_address
        for src, dst in mappings:
            if ip in src:
                off = int(ip) - int(src.network_address)
                new_ip = ipaddress.ip_address(int(dst.network_address) + off)
                return str(new_ip)

    # 3: subnet inside mapped net
    for src, dst in mappings:
        if net.subnet_of(src):
            off = int(net.network_address) - int(src.network_address)
            base = ipaddress.ip_address(int(dst.network_address) + off)
            return f"{base}/{net.prefixlen}"
    return None

# ----------------------------
# Utilities
# ----------------------------

def unquote(t): return t[1:-1] if t.startswith('"') and t.endswith('"') else t
def needs_quotes(n): return any(c.isspace() for c in n)
def safe_token(n): return f'"{n}"' if needs_quotes(n) else n
def name_for_value(v):
    raw = v.replace(".", "_").replace("/", "_").replace("-", "_")
    while "__" in raw:
        raw = raw.replace("__", "_")
    return f"svb_host_{raw}"

# Regex to find address objects
ADDR_OBJ_RE = re.compile(
    r'^set (device-group\s+\S+|shared)\s+address\s+(".*?"|\S+)\s+(ip-netmask|ip-range)\s+(\S+)',
    re.IGNORECASE
)

# Regex to find address-group static lines, bracketed or single member
ADDR_GRP_STATIC_RE = re.compile(
    r'^(set (device-group\s+\S+|shared)\s+address-group\s+(".*?"|\S+)\s+static\s+)'
    r'(?:\[([^\]]+)\]|(\S+))'   # group 4 = inside brackets, group 5 = single member
    r'(.*)$',
    re.IGNORECASE
)

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    mappings = load_translation()
    if not mappings:
        print(f"No valid translations found in {TRANSLATION_FILE}")
        return

    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    # Build maps of address objects
    addr_by_name = {}
    names_by_value = {}
    for raw in lines:
        m = ADDR_OBJ_RE.match(raw.strip())
        if m:
            scope = m.group(1)
            name = unquote(m.group(2))
            kind = m.group(3)
            val  = m.group(4)
            addr_by_name[(scope, name)] = (kind, val)
            names_by_value.setdefault(val, []).append((scope, name))

    out_lines = []
    new_objects = []

    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write("=== translate_address_groups_append_objects log ===\n\n")

        for raw in lines:
            s = raw.strip()
            m = ADDR_GRP_STATIC_RE.match(s)
            if not m:
                out_lines.append(raw)
                continue

            prefix = m.group(1)
            scope  = m.group(2)
            grp_name = unquote(m.group(3))
            bracket_members = m.group(4)
            single_member   = m.group(5)
            suffix = m.group(6)

            # Get member tokens
            if bracket_members:
                tokens = shlex.split(bracket_members)
            else:
                tokens = [single_member]

            member_names = [unquote(t) for t in tokens]
            appended = []

            for mem in member_names:
                # locate its address object
                key = (scope, mem)
                alt_key = ("shared", mem) if scope != "shared" else None
                if key in addr_by_name:
                    kind, val = addr_by_name[key]
                elif alt_key and alt_key in addr_by_name:
                    kind, val = addr_by_name[alt_key]
                else:
                    continue

                trans = translate_value(val, mappings)
                if not trans:
                    continue

                # check if an object already exists with translated value
                chosen_name = None
                for sc, nm in names_by_value.get(trans, []):
                    if sc == scope:
                        chosen_name = nm
                        break
                if not chosen_name:
                    for sc, nm in names_by_value.get(trans, []):
                        if sc == "shared":
                            chosen_name = nm
                            break

                if not chosen_name:
                    # create a new object
                    new_name = name_for_value(trans)
                    i = 1
                    base = new_name
                    while (scope, new_name) in addr_by_name:
                        i += 1
                        new_name = f"{base}_{i}"
                    if "-" in trans:
                        new_kind, new_val = "ip-range", trans
                    else:
                        if "/" not in trans:
                            new_val = f"{trans}/32"
                        else:
                            new_val = trans
                        new_kind = "ip-netmask"

                    new_line = f"set {scope} address {safe_token(new_name)} {new_kind} {new_val}\n"
                    new_objects.append(new_line)
                    addr_by_name[(scope, new_name)] = (new_kind, new_val)
                    names_by_value.setdefault(new_val, []).append((scope, new_name))
                    chosen_name = new_name
                    log.write(f"Created object: {scope} {new_name} -> {new_val}\n")

                if chosen_name not in member_names and chosen_name not in appended:
                    appended.append(chosen_name)
                    log.write(f"Group {grp_name} ({scope}) member {mem} translated -> {chosen_name}\n")

            if appended:
                all_members = member_names + appended
                seen = set()
                ordered = []
                for n in all_members:
                    if n not in seen:
                        seen.add(n)
                        ordered.append(n)
                # ensure CLI spacing: [ member1 member2 ]
                new_member_str = "[ " + " ".join(safe_token(n) for n in ordered) + " ]"
                new_line = f"{prefix}{new_member_str}{suffix}\n"
                out_lines.append(new_line)
                log.write(f"UPDATED GROUP LINE:\n  OLD: {s}\n  NEW: {new_line.rstrip()}\n\n")
            else:
                out_lines.append(raw)

    if new_objects:
        out_lines.extend(new_objects)

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(out_lines)

    print(f"Updated {CONFIG_FILE} (backup at {CONFIG_FILE}.bak)")
    print(f"Log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
