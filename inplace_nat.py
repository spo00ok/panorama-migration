#!/usr/bin/env python3
import os
import re
import ipaddress
import shutil

CONFIG_FILE       = "panorama.set"
TRANSLATION_FILE  = "translation.input"
LOG_FILE          = "translate_nat_inline_ips.log"

# ------------------- Translation loading -------------------

def load_translation():
    """
    translation.input rows (any mix):
      single_ip,new_ip
      cidr,new_cidr
      start-end,new_ip_or_cidr     (range on the left)
    Returns:
      one_to_one: dict[str_ip] -> IPvXAddress
      networks:   list[(IPvXNetwork old, IPvXNetwork new)]  (sorted most-specific first)
      ranges:     list[(IPvXAddress start, IPvXAddress end, rhs_type, rhs_val)]
                  rhs_type in {"ip","subnet"}; rhs_val IPvXAddress or IPvXNetwork
    """
    one_to_one, networks, ranges = {}, [], []
    with open(TRANSLATION_FILE, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw or "," not in raw:
                continue
            orig, new = [p.strip() for p in raw.split(",", 1)]

            # Range on LHS
            if "-" in orig and "/" not in orig:
                try:
                    s_txt, e_txt = [p.strip() for p in orig.split("-", 1)]
                    s = ipaddress.ip_address(s_txt); e = ipaddress.ip_address(e_txt)
                    if type(s) is type(e) and int(s) <= int(e):
                        try:
                            rhs = ipaddress.ip_address(new); ranges.append((s, e, "ip", rhs))
                        except ValueError:
                            try:
                                rhs = ipaddress.ip_network(new, strict=False); ranges.append((s, e, "subnet", rhs))
                            except ValueError:
                                pass
                except ValueError:
                    pass
                continue

            # Subnet on LHS
            if "/" in orig:
                try:
                    old_net = ipaddress.ip_network(orig, strict=False)
                    new_net = ipaddress.ip_network(new, strict=False)
                    if old_net.version == new_net.version:
                        networks.append((old_net, new_net))
                except ValueError:
                    pass
                continue

            # Single IP on LHS
            try:
                old_ip = ipaddress.ip_address(orig); new_ip = ipaddress.ip_address(new)
                if old_ip.version == new_ip.version:
                    one_to_one[str(old_ip)] = new_ip
            except ValueError:
                pass

    # prefer most-specific subnet match first
    networks.sort(key=lambda t: t[0].prefixlen, reverse=True)
    return one_to_one, networks, ranges

# ------------------- Mapping logic -------------------

def convert_single_ip(ip, one_to_one, networks, ranges):
    """Return mapped host IP (IPv4/IPv6) or None."""
    s = str(ip)
    if s in one_to_one:
        return one_to_one[s]

    for old_net, new_net in networks:
        if ip.version == old_net.version and ip in old_net:
            off = int(ip) - int(old_net.network_address)
            if off < new_net.num_addresses:
                return type(new_net.network_address)(int(new_net.network_address) + off)

    for start, end, rhs_type, rhs_val in ranges:
        if ip.version == start.version and int(start) <= int(ip) <= int(end):
            if rhs_type == "ip":
                return rhs_val
            else:
                off = int(ip) - int(start)
                if off < rhs_val.num_addresses:
                    return type(rhs_val.network_address)(int(rhs_val.network_address) + off)
    return None

def translate_token(token, one_to_one, networks, ranges):
    """
    Translate a token that may be:
      - single IP
      - single IP with /mask (preserve mask)
      - range A-B  (map both endpoints)
    Keep token 'shape' (IP stays IP, range stays range). Preserve quotes if present.
    """
    raw = token.strip()
    q = raw.startswith('"') and raw.endswith('"')
    core = raw[1:-1] if q else raw

    # Range?
    if "-" in core and not re.search(r"[g-zG-Z]", core):
        try:
            a_txt, b_txt = [p.strip() for p in core.split("-", 1)]
            a = ipaddress.ip_address(a_txt); b = ipaddress.ip_address(b_txt)
        except ValueError:
            return token
        a_new = convert_single_ip(a, one_to_one, networks, ranges) or a
        b_new = convert_single_ip(b, one_to_one, networks, ranges) or b
        out = f"{a_new}-{b_new}"
        return f'"{out}"' if q else out

    # Single IP (optional /mask)
    m = re.match(r"^([0-9a-fA-F:\.]+)(?:/(\d{1,3}))?$", core)
    if not m:
        return token
    ip_txt, mask = m.group(1), m.group(2)
    try:
        ip = ipaddress.ip_address(ip_txt)
    except ValueError:
        return token

    mapped = convert_single_ip(ip, one_to_one, networks, ranges)
    if mapped is None:
        return token

    out = str(mapped) + (f"/{mask}" if mask else "")
    return f'"{out}"' if q else out

# ------------------- NAT line matching -------------------

NAT_LINE_RE = re.compile(
    r'^set\s+(?:device-group\s+\S+|shared)\s+(?:pre|post)-rulebase nat\s+rules\s+\S+|'
    r'^set\s+(?:device-group\s+\S+|shared)\s+rulebase nat\s+rules\s+\S+',
    re.IGNORECASE
)

TOKEN_LIKE_IP = re.compile(r'^[0-9a-fA-F:\.]+(?:/\d{1,3})?$')

# ------------------- Main -------------------

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    # backup
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    one_to_one, networks, ranges = load_translation()

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    out_lines = []
    changes = 0

    with open(LOG_FILE, "w", encoding="utf-8", errors="replace") as log:
        log.write("=== NAT Inline IP Translation Log ===\n\n")

        for line in lines:
            s = line.strip()
            if not NAT_LINE_RE.match(s):
                out_lines.append(line)
                continue

            tokens = line.split()
            changed = False

            for i, tok in enumerate(tokens):
                looks_ipish = TOKEN_LIKE_IP.match(tok.strip('"')) or ("-" in tok and not re.search("[g-zG-Z]", tok))
                if not looks_ipish:
                    continue
                new_tok = translate_token(tok, one_to_one, networks, ranges)
                if new_tok != tok:
                    tokens[i] = new_tok
                    changed = True

            if changed:
                new_line = " ".join(tokens)
                if not new_line.endswith("\n"):
                    new_line += "\n"
                log.write(f"REPLACED:\n  OLD: {line.rstrip()}\n  NEW: {new_line.rstrip()}\n\n")
                out_lines.append(new_line)
                changes += 1
            else:
                out_lines.append(line)

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(out_lines)

    print(f" Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f" {changes} NAT line(s) modified")
    print(f" Translation log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
