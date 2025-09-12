#!/usr/bin/env python3
import ipaddress
import re
import os

CONFIG_FILE = "panorama.set"
TRANSLATION_FILE = "translation.input"
LOG_FILE = "translate_address_groups.log"

translation = {}

def load_translation():
    with open(TRANSLATION_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or "," not in line:
                continue
            orig_str, new_str = line.split(",")
            orig_net = ipaddress.ip_network(orig_str.strip(), strict=False)
            new_net = ipaddress.ip_network(new_str.strip(), strict=False)
            translation[str(orig_net)] = str(new_net)

def translate_value(value):
    """Translate an IP, subnet, or range using the priority rules."""
    value = value.strip()
    try:
        ip_net = ipaddress.ip_network(value, strict=False)

        # 1:1 priority (exact mapping)
        for net_str, new_str in translation.items():
            if str(ip_net) == net_str:
                return new_str if "/" in new_str else str(ipaddress.ip_network(new_str, strict=False).network_address)

        # Single IP (/32) inside a translated subnet
        if ip_net.prefixlen == 32:
            ip = ip_net.network_address
            for net_str, new_str in translation.items():
                net = ipaddress.ip_network(net_str, strict=False)
                new_net = ipaddress.ip_network(new_str, strict=False)
                if ip in net:
                    offset = int(ip) - int(net.network_address)
                    mapped_ip = ipaddress.ip_address(int(new_net.network_address) + offset)
                    return str(mapped_ip)

        # Subnet inside a translated subnet
        for net_str, new_str in translation.items():
            net = ipaddress.ip_network(net_str, strict=False)
            new_net = ipaddress.ip_network(new_str, strict=False)
            if ip_net.subnet_of(net):
                offset = int(ip_net.network_address) - int(net.network_address)
                mapped_base = ipaddress.ip_address(int(new_net.network_address) + offset)
                return str(ipaddress.ip_network(f"{mapped_base}/{ip_net.prefixlen}", strict=False))
    except ValueError:
        pass

    # IP range
    if "-" in value:
        try:
            start_ip, end_ip = value.split("-")
            start_ip = ipaddress.ip_address(start_ip.strip())
            end_ip = ipaddress.ip_address(end_ip.strip())
            new_start, new_end = None, None
            for net_str, new_str in translation.items():
                net = ipaddress.ip_network(net_str, strict=False)
                new_net = ipaddress.ip_network(new_str, strict=False)
                if start_ip in net:
                    offset = int(start_ip) - int(net.network_address)
                    new_start = ipaddress.ip_address(int(new_net.network_address) + offset)
                if end_ip in net:
                    offset = int(end_ip) - int(net.network_address)
                    new_end = ipaddress.ip_address(int(new_net.network_address) + offset)
            if new_start and new_end:
                return f"{new_start}-{new_end}"
        except Exception:
            return None
    return None

def unique(seq):
    seen, result = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            result.append(x)
    return result

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return
    if not os.path.exists(TRANSLATION_FILE):
        print(f"Translation file {TRANSLATION_FILE} not found.")
        return

    load_translation()

    with open(CONFIG_FILE, "r") as f:
        lines = f.readlines()

    output_lines = []
    with open(LOG_FILE, "w") as log:
        for line in lines:
            stripped = line.strip()
            if re.match(r"^set (device-group \S+|shared) address-group ", stripped) and " static " in stripped:
                m = re.search(r"static\s+\[([^\]]+)\]", stripped)
                if m:
                    members = m.group(1).split()
                    new_members = list(members)
                    for member in members:
                        t = translate_value(member)
                        if t and t not in new_members:
                            new_members.append(t)
                            log.write(f"Group update: {member} -> {t}\n")
                    new_members = unique(new_members)
                    new_line = re.sub(r"static\s+\[[^\]]+\]", "static [ " + " ".join(new_members) + " ]", stripped)
                    output_lines.append(new_line + "\n")
                    continue
            output_lines.append(line)

    with open(CONFIG_FILE, "w") as f:
        f.writelines(output_lines)

    print(f"Processing complete. Updated config written to {CONFIG_FILE}")
    print(f"Log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
