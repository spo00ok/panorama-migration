#!/usr/bin/env python3
import ipaddress
import re
import os

CONFIG_FILE = "panorama.set"
TRANSLATION_FILE = "translation.input"
LOG_FILE = "inline_ip_conversion.log"

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
    """Map single IP, subnet or range with 1:1 priority then subnet offset."""
    value = value.strip()
    try:
        ip_net = ipaddress.ip_network(value, strict=False)

        # 1:1 exact network match
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

def normalize_name(value: str) -> str:
    """Create a valid address-object name from a value."""
    return "ADDR_" + value.replace(".", "_").replace("/", "_").replace("-", "_")

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

    # Collect already-defined address objects (value -> name)
    existing_objects = {}
    for l in lines:
        if " address " in l and not "address-group" in l:
            parts = l.split()
            if parts[1] == "device-group":
                dg = parts[2]
                name = parts[4]
                field = parts[5] if len(parts) > 5 else None
                val = " ".join(parts[6:]) if len(parts) > 6 else None
            else:
                dg = "shared"
                name = parts[2]
                field = parts[3] if len(parts) > 3 else None
                val = " ".join(parts[4:]) if len(parts) > 4 else None
            if field in ["ip-netmask", "ip-range"] and val:
                existing_objects[val.strip()] = name

    output_lines = []
    new_objects = set()

    with open(LOG_FILE, "w") as log:
        for line in lines:
            stripped = line.strip()

            # Security rule with potential inline IPs/subnets/ranges
            if re.match(r"^set (device-group \S+|shared) pre-rulebase security rules ", stripped):
                parts = stripped.split()
                dg = parts[2] if parts[1] == "device-group" else "shared"
                rule_name = parts[5]  # after 'rules'
                new_parts = []
                for token in parts:
                    if re.match(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$", token) or "-" in token:
                        # skip if token looks like FQDN (letters)
                        if re.search("[a-zA-Z]", token):
                            new_parts.append(token)
                            continue
                        val = translate_value(token) or token
                        if val in existing_objects:
                            obj_name = existing_objects[val]
                        else:
                            obj_name = normalize_name(val)
                            if (dg, obj_name) not in new_objects:
                                if dg == "shared":
                                    output_lines.append(f"set shared address {obj_name} ip-netmask {val}\n")
                                else:
                                    output_lines.append(f"set device-group {dg} address {obj_name} ip-netmask {val}\n")
                                log.write(f"Created object {obj_name} = {val} in {dg}\n")
                                existing_objects[val] = obj_name
                                new_objects.add((dg, obj_name))
                        new_parts.append(obj_name)
                        log.write(f"Rule {rule_name}: replaced {token} -> {obj_name}\n")
                    else:
                        new_parts.append(token)
                line = " ".join(new_parts) + "\n"
            output_lines.append(line)

    with open(CONFIG_FILE, "w") as f:
        f.writelines(output_lines)

    print(f"Processing complete. Updated config written to {CONFIG_FILE}")
    print(f"Log written to {LOG_FILE}")

if __name__ == "__main__":
    main()

                if modified:
                    line = " ".join(new_parts) + "\n"

            output_lines.append(line)

    with open(CONFIG_FILE, "w") as f:
        f.writelines(output_lines)

    print(f"Processing complete. Updated config written to {CONFIG_FILE}")
    print(f"Log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
