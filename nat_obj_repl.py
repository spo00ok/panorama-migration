#!/usr/bin/env python3
import os
import re
import ipaddress
import shutil

CONFIG_FILE      = "panorama.set"       # Panorama config in set-command format
TRANSLATION_FILE = "translation.input"  # old,new mappings
LOG_FILE         = "replace_nat_address_objects_with_translated.log"

def load_translation():
    """
    Load translation mappings, giving priority to exact IP matches.
    """
    one_to_one = {}   # single IP -> translated IP
    networks   = []   # (ip_network, translated net)
    ranges     = []   # (start_ip, end_ip, translated range)
    with open(TRANSLATION_FILE, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw or "," not in raw:
                continue
            orig, new = [p.strip() for p in raw.split(",",1)]
            if "-" in orig and not "/" in orig:  # range
                start, end = [ipaddress.ip_address(p) for p in orig.split("-")]
                ranges.append((start, end, new))
            elif "/" in orig:                    # subnet
                networks.append((ipaddress.ip_network(orig, strict=False), new))
            else:                                # single IP
                one_to_one[orig] = new
    return one_to_one, networks, ranges

def translated_value(ip_str, one_to_one, networks, ranges):
    """
    If ip_str matches a translation rule, return the translated value; else None.
    """
    if ip_str in one_to_one:
        return one_to_one[ip_str]
    try:
        ip = ipaddress.ip_address(ip_str.split("/")[0])
        for net, new in networks:
            if ip in net:
                return new
        for start, end, new in ranges:
            if start <= ip <= end:
                return new
    except ValueError:
        pass
    return None

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    one_to_one, networks, ranges = load_translation()

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    # ------------------------------------------------------------------
    # Build a lookup: address object name -> its IP/subnet/range value
    # ------------------------------------------------------------------
    addr_values = {}
    addr_re = re.compile(
        r'^set (device-group\s+\S+|shared)\s+address\s+(\S+)\s+(ip-netmask|ip-range)\s+(\S+)',
        re.IGNORECASE
    )
    for l in lines:
        m = addr_re.match(l.strip())
        if m:
            addr_values[m.group(2)] = m.group(4)

    # ------------------------------------------------------------------
    # Find NAT rule lines and replace object references where needed
    # ------------------------------------------------------------------
    nat_re = re.compile(
        r'^set (device-group\s+\S+|shared)\s+rulebase nat rules ',
        re.IGNORECASE
    )

    output = []
    with open(LOG_FILE, "w", encoding="utf-8", errors="replace") as log:
        log.write("=== NAT Address Object Replacement Log ===\n\n")

        for line in lines:
            stripped = line.strip()
            if nat_re.match(stripped):
                old_line = line
                tokens = line.split()
                changed = False
                for i, t in enumerate(tokens):
                    # Is token the name of an address object?
                    if t in addr_values:
                        old_val = addr_values[t]
                        new_val = translated_value(
                            old_val.split("/")[0].split("-")[0],
                            one_to_one, networks, ranges
                        )
                        if new_val:
                            # look for an existing address object whose value is new_val
                            for obj_name, obj_val in addr_values.items():
                                if obj_val == new_val:
                                    tokens[i] = obj_name
                                    changed = True
                                    log.write(f"REPLACED:\n"
                                              f"  OLD: {old_line.rstrip()}\n"
                                              f"  ->  replaced address object '{t}' "
                                              f"(value {old_val}) with '{obj_name}' "
                                              f"(value {obj_val})\n\n")
                                    break
                if changed:
                    line = " ".join(tokens) + "\n"
            output.append(line)

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(output)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Detailed log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
