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
    """
    Load translation.input as network->network mappings.
    Supports single IPs and subnets on each side.
    Returns list of tuples: [(src_net: ip_network, dst_net: ip_network), ...]
    """
    mappings = []
    if not os.path.exists(TRANSLATION_FILE):
        return mappings

    with open(TRANSLATION_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or "," not in line:
                continue
            orig_str, new_str = [p.strip() for p in line.split(",", 1)]
            # Convert single IPs to /32 networks
            if "/" not in orig_str:
                orig_str = f"{orig_str}/32"
            if "/" not in new_str:
                new_str = f"{new_str}/32"
            try:
                src = ipaddress.ip_network(orig_str, strict=False)
                dst = ipaddress.ip_network(new_str, strict=False)
                mappings.append((src, dst))
            except ValueError:
                # skip bad lines quietly
                continue
    return mappings

def translate_value(value, mappings):
    """
    Translate an address value (IP, subnet, or range).
    Returns translated string (same form: ip, cidr, or range "start-end") or None if not translatable.

    Priority:
      1) Exact network-to-network match (string-equal CIDR after normalization)
      2) Single IP inside a mapped source network (keeps offset)
      3) Subnet fully inside a mapped source network (keeps offset and prefixlen)
      4) Range: translate start/end independently if both belong to mapped (same) source nets
    """
    s = value.strip()

    # Range form "a.b.c.d-e.f.g.h"
    if "-" in s:
        try:
            lo_s, hi_s = [p.strip() for p in s.split("-", 1)]
            lo = ipaddress.ip_address(lo_s)
            hi = ipaddress.ip_address(hi_s)
        except ValueError:
            return None
        new_lo = None
        new_hi = None
        for src, dst in mappings:
            if lo in src and new_lo is None:
                off = int(lo) - int(src.network_address)
                new_lo = ipaddress.ip_address(int(dst.network_address) + off)
            if hi in src and new_hi is None:
                off = int(hi) - int(src.network_address)
                new_hi = ipaddress.ip_address(int(dst.network_address) + off)
            if new_lo is not None and new_hi is not None:
                break
        if new_lo is not None and new_hi is not None:
            return f"{new_lo}-{new_hi}"
        return None

    # Try as network (covers IPs too via strict=False)
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None

    # 1) Exact network string match (after normalization)
    for src, dst in mappings:
        if str(net) == str(src):
            return str(dst)

    # 2) Single IP inside a mapped subnet
    if net.prefixlen == net.max_prefixlen:
        ip = net.network_address
        for src, dst in mappings:
            if ip in src:
                off = int(ip) - int(src.network_address)
                new_ip = ipaddress.ip_address(int(dst.network_address) + off)
                return str(new_ip)

    # 3) Subnet fully inside a mapped subnet
    for src, dst in mappings:
        if net.subnet_of(src):
            off = int(net.network_address) - int(src.network_address)
            new_base = ipaddress.ip_address(int(dst.network_address) + off)
            return f"{new_base}/{net.prefixlen}"

    return None

# ----------------------------
# Config parsing helpers
# ----------------------------

ADDR_OBJ_RE = re.compile(
    r'^set (device-group\s+\S+|shared)\s+address\s+(".*?"|\S+)\s+(ip-netmask|ip-range)\s+(\S+)\s*(?:$| .*)',
    re.IGNORECASE
)

ADDR_GRP_STATIC_RE = re.compile(
    r'^(set (device-group\s+\S+|shared)\s+address-group\s+(".*?"|\S+)\s+static\s+)\[([^\]]+)\](.*)$',
    re.IGNORECASE
)

def unquote(token: str) -> str:
    return token[1:-1] if len(token) >= 2 and token.startswith('"') and token.endswith('"') else token

def needs_quotes(name: str) -> bool:
    return " " in name or '\t' in name

def safe_token(name: str) -> str:
    return f'"{name}"' if needs_quotes(name) else name

def name_for_value(value: str) -> str:
    """
    Build name like svb_host_10_123_12_2_24 from an IP/subnet/range.
    Rules:
      - Replace '.', '/', '-' with '_'
      - Prefix 'svb_host_'
      - Collapse consecutive '_' (cosmetic)
    """
    raw = value.replace(".", "_").replace("/", "_").replace("-", "_")
    while "__" in raw:
        raw = raw.replace("__", "_")
    return f"svb_host_{raw}"

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    mappings = load_translation()
    if not mappings:
        print(f"No valid mappings found in {TRANSLATION_FILE}. Nothing to do.")
        return

    # Backup
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    # Build address object map: (scope, name) -> value
    # Also quick lookup: value -> list[(scope, name)]
    addr_by_name = {}
    names_by_value = {}

    for raw in lines:
        s = raw.strip()
        m = ADDR_OBJ_RE.match(s)
        if not m:
            continue
        scope = m.group(1)  # "device-group <DG>" or "shared"
        name_tok = m.group(2)
        name = unquote(name_tok)
        kind = m.group(3)   # ip-netmask | ip-range
        val  = m.group(4)   # "10.1.1.1/32" or "10.1.1.1-10.1.1.9"
        addr_by_name[(scope, name)] = (kind, val)
        names_by_value.setdefault(val, []).append((scope, name))

    output_lines = []
    new_obj_lines = []  # accumulate new address object lines to inject (keep order deterministic)

    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write("=== translate_address_groups_append_objects: log ===\n\n")

        for raw in lines:
            stripped = raw.strip()
            m = ADDR_GRP_STATIC_RE.match(stripped)
            if not m:
                # pass-through
                output_lines.append(raw)
                continue

            # Parse group static members
            grp_prefix_full = m.group(1)  # includes 'set <scope> address-group <name> static '
            scope = m.group(2)            # 'device-group <DG>' or 'shared'
            grp_name = unquote(m.group(3))
            members_str = m.group(4)
            suffix = m.group(5)

            # split members (supports quoted items)
            tokens = shlex.split(members_str)
            # Keep original members as shown (we'll output safe tokens later)
            member_names = [unquote(t) for t in tokens]

            # Resolve each member to its address value (only if it's an address object)
            # If a member isn't an address object (e.g., nested group), we skip it.
            appended_members = []
            for mem in member_names:
                key = (scope, mem)
                alt_key = ("shared", mem) if scope != "shared" else None

                if key in addr_by_name:
                    kind, val = addr_by_name[key]
                elif alt_key and alt_key in addr_by_name:
                    # allow referencing shared object implicitly
                    kind, val = addr_by_name[alt_key]
                else:
                    # Not an address object we know about; skip
                    continue

                # Translate the value
                trans = translate_value(val, mappings)
                if not trans:
                    continue

                # Find an existing address object with exactly this translated value
                chosen_name = None
                # Prefer same scope first
                for cand_scope, cand_name in names_by_value.get(trans, []):
                    if cand_scope == scope:
                        chosen_name = cand_name
                        break
                if not chosen_name:
                    # fallback: allow shared-scoped object if present
                    for cand_scope, cand_name in names_by_value.get(trans, []):
                        if cand_scope == "shared":
                            chosen_name = cand_name
                            break

                # If none exists, create a new address object in the same scope
                if not chosen_name:
                    new_name = name_for_value(trans)
                    # Avoid name collision
                    i = 1
                    base = new_name
                    while (scope, new_name) in addr_by_name:
                        i += 1
                        new_name = f"{base}_{i}"

                    # Normalize kind for creation
                    if "-" in trans:
                        new_kind = "ip-range"
                        new_val = trans
                    else:
                        # ensure CIDR — if trans is plain IP convert to /32
                        if "/" not in trans:
                            new_val = f"{trans}/32"
                        else:
                            new_val = trans
                        new_kind = "ip-netmask"

                    # Compose set command for new object
                    new_line = f"set {scope} address {safe_token(new_name)} {new_kind} {new_val}\n"
                    new_obj_lines.append(new_line)

                    # Update our maps so further groups can reuse it
                    addr_by_name[(scope, new_name)] = (new_kind, new_val)
                    names_by_value.setdefault(new_val, []).append((scope, new_name))

                    chosen_name = new_name
                    log.write(f"Created object: scope={scope}, name={new_name}, value={new_val}\n")

                # Append the chosen object name to the group's members if not already there
                if chosen_name not in member_names and chosen_name not in appended_members:
                    appended_members.append(chosen_name)
                    log.write(f"Group '{grp_name}' ({scope}) member '{mem}' translated -> '{chosen_name}' (value {trans})\n")

            # Build updated member list
            if appended_members:
                all_members = member_names + appended_members
                # de-duplicate preserving order
                seen = set()
                ordered = []
                for n in all_members:
                    if n not in seen:
                        seen.add(n)
                        ordered.append(n)
                # rebuild line
                rebuilt_members = " ".join(safe_token(n) for n in ordered)
                new_line = f"{grp_prefix_full}[{rebuilt_members}]{suffix}\n"
                output_lines.append(new_line)
                log.write(f"UPDATED GROUP LINE:\n  OLD: {stripped}\n  NEW: {new_line.rstrip()}\n\n")
            else:
                # no changes for this group
                output_lines.append(raw)

    # Insert newly created address objects near the top (after any preamble comments),
    # or you can append at the end. Here we append them at the end for simplicity.
    if new_obj_lines:
        output_lines.extend(new_obj_lines)

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(output_lines)

    print(f"Updated {CONFIG_FILE} (backup at {CONFIG_FILE}.bak)")
    print(f"Log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
