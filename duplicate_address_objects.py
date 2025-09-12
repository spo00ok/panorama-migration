import ipaddress
import re
import shutil

CONFIG_FILE = "../panorama.set"
TRANSLATION_FILE = "../translation.input"
LOG_FILE = "../logs/object_duplication.log"

# Backup original config
shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

# -------------------------------------------------------------------
# Load translation mappings (IPs + subnets) from translation.input
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# Translate an IP, subnet, or range
# - Single IP: mapped 1:1 if present
# - Subnet: mapped if entire network matches
# - Range: each endpoint translated, recombined
# -------------------------------------------------------------------
def translate_value(value):
    value = value.strip()

    # Single IP or subnet
    try:
        ip_net = ipaddress.ip_network(value, strict=False)
        for net_str, new_str in translation.items():
            net = ipaddress.ip_network(net_str)
            new_net = ipaddress.ip_network(new_str)
            if ip_net == net:  # exact network match
                if ip_net.prefixlen == 32:
                    return str(new_net.network_address)
                else:
                    return str(new_net)
        return None
    except ValueError:
        pass

    # Range
    if "-" in value:
        try:
            start_ip, end_ip = value.split("-")
            start_ip = ipaddress.ip_address(start_ip.strip())
            end_ip = ipaddress.ip_address(end_ip.strip())

            new_start, new_end = None, None
            for net_str, new_str in translation.items():
                net = ipaddress.ip_network(net_str)
                new_net = ipaddress.ip_network(new_str)

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

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
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
    created_pdc = set()   # track created objects for idempotency
    object_map = {}       # map orig->new for policy reference updates

    with open(LOG_FILE, "w") as log:
        for line in lines:
            stripped = line.strip()

            # --------------------------------------------------------
            # Handle address object definitions
            # --------------------------------------------------------
            if re.match(r"^set (device-group \S+|shared) address ", stripped):
                parts = stripped.split()

                if parts[1] == "device-group":
                    dg = parts[2]
                    name = parts[4]
                    field = parts[5] if len(parts) > 5 else None
                    value = " ".join(parts[6:]) if len(parts) > 6 else None
                else:  # shared
                    dg = "shared"
                    name = parts[2]
                    field = parts[3] if len(parts) > 3 else None
                    value = " ".join(parts[4:]) if len(parts) > 4 else None

                # ✅ Skip non-IP fields and fqdn objects
                if field in ["ip-netmask", "ip-range"] and value:
                    t = translate_value(value)
                    if t:
                        new_name = name + "_pdc"
                        if (dg, new_name) not in created_pdc:
                            # Create duplicate in same DG
                            if dg == "shared":
                                new_line = f"set shared address {new_name} {field} {t}\n"
                            else:
                                new_line = f"set device-group {dg} address {new_name} {field} {t}\n"

                            output_lines.append(line)          # keep original
                            output_lines.append(new_line)      # add new
                            log.write(f"{dg}:{name} {value} -> {new_name} {t}\n")

                            created_pdc.add((dg, new_name))
                            object_map[(dg, name)] = new_name
                            continue

            # --------------------------------------------------------
            # Handle security policy references
            # --------------------------------------------------------
            if re.match(r"^set (device-group \S+|shared) pre-rulebase security rules ", stripped):
                parts = stripped.split()
                if parts[1] == "device-group":
                    dg = parts[2]
                else:
                    dg = "shared"

                # Append duplicate object references if rule mentions the original
                for (obj_dg, orig_name), new_name in object_map.items():
                    if dg == obj_dg and f" {orig_name} " in f" {stripped} ":
                        if f" {new_name} " not in f" {stripped} ":
                            line = line.rstrip() + f" {new_name}\n"
                            log.write(f"Updated rule in {dg}: added {new_name} alongside {orig_name}\n")

            output_lines.append(line)

    # Write back modified config
    with open(CONFIG_FILE, "w") as f:
        f.writelines(output_lines)

    print(f"Processing complete. Updated config written to {CONFIG_FILE}")
    print(f"Log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
