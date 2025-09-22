#!/usr/bin/env python3
import os
import re
import ipaddress
import shutil

CONFIG_FILE      = "panorama.set"       # your panorama set-command config
TRANSLATION_FILE = "translation.input"  # original,new pairs
LOG_FILE         = "translate_nat_inline_ips.log"

def load_translation():
    """
    Load translation mappings.
    Exact IPs take priority over network/range matches.
    """
    one_to_one = {}   # exact IP -> new value
    networks   = []   # (ip_network, new value)
    ranges     = []   # (start_ip, end_ip, new value)

    with open(TRANSLATION_FILE, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw or "," not in raw:
                continue
            orig, new = [p.strip() for p in raw.split(",",1)]

            if "-" in orig and not "/" in orig:     # IP range
                start, end = [ipaddress.ip_address(p) for p in orig.split("-")]
                ranges.append((start, end, new))
            elif "/" in orig:                       # subnet
                networks.append((ipaddress.ip_network(orig, strict=False), new))
            else:                                   # single IP
                one_to_one[orig] = new
    return one_to_one, networks, ranges

def translate_ip(token, one_to_one, networks, ranges):
    """
    Return translated value for a token if it matches;
    otherwise return the token unchanged.
    """
    clean = token.strip('"')
    # 1: exact match
    if clean in one_to_one:
        return one_to_one[clean]

    # 2: subnet match
    try:
        ip = ipaddress.ip_address(clean.split("/")[0])
        for net, new in networks:
            if ip in net:
                return new
    except ValueError:
        pass

    # 3: range match
    try:
        ip = ipaddress.ip_address(clean)
        for start, end, new in ranges:
            if start <= ip <= end:
                return new
    except ValueError:
        pass

    return token  # unchanged

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    one_to_one, networks, ranges = load_translation()

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    output = []
    with open(LOG_FILE, "w", encoding="utf-8", errors="replace") as log:
        log.write("=== NAT Inline IP Translation Log ===\n\n")

        # Regex to capture NAT rule lines
        nat_rule_re = re.compile(
            r'^set (device-group\s+\S+|shared)\s+rulebase nat rules ',
            re.IGNORECASE
        )

        for line in lines:
            stripped = line.strip()
            if nat_rule_re.match(stripped):
                old_line = line
                tokens = line.split()
                changed = False
                for i, t in enumerate(tokens):
                    # look for literal IP, subnet or range and skip tokens with letters
                    if (re.match(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$", t) or "-" in t) and not re.search("[a-zA-Z]", t):
                        new_val = translate_ip(t, one_to_one, networks, ranges)
                        if new_val != t:
                            tokens[i] = new_val
                            changed = True
                if changed:
                    line = " ".join(tokens) + "\n"
                    log.write("REPLACED:\n")
                    log.write("  OLD: " + old_line.rstrip() + "\n")
                    log.write("  NEW: " + line.rstrip() + "\n\n")
            output.append(line)

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(output)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Translation log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
