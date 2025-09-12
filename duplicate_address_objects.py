import ipaddress
import re
import shutil

CONFIG_FILE = "../panorama.set"
TRANSLATION_FILE = "../translation.input"
LOG_FILE = "../logs/object_duplication.log"

# Backup original config
shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

# Load translation mappings
ip_map, subnet_map = {}, {}
with open(TRANSLATION_FILE, "r") as f:
    for line in f:
        line = line.strip()
        if not line or "," not in line:
            continue
        orig_str, new_str = [x.strip() for x in line.split(",")]
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", orig_str):  # direct IP
            ip_map[orig_str] = new_str
        else:  # subnet translation
            subnet_map[str(ipaddress.ip_network(orig_str, strict=False))] = str(
                ipaddress.ip_network(new_str, strict=False)
            )

with open(LOG_FILE, "w") as log:
    log.write("=== Address Object Duplication Log ===\n")

def unique(seq):
    seen, result = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            result.append(x)
    return result

def translate_value(value):
    """Translate IPs, subnets, or ranges using translation.input"""
    if value in ip_map:
        return ip_map[value]

    try:
        if "/" in value:  # subnet
            net = ipaddress.ip_network(value, strict=False)
            if str(net) in subnet_map:
                return subnet_map[str(net)]
    except Exception:
        pass

    if "-" in value:  # IP range
        start, end = value.split("-")
        ns, ne = translate_value(start.strip()), translate_value(end.strip())
        if ns or ne:
            return f"{ns or start.strip()}-{ne or end.strip()}"

    return None

output_lines = []
created_pdc = set()

# Match rules
rule_pattern = re.compile(r"^set (device-group \S+|shared) rulebase security rules (\S+) (.+)$")

with open(CONFIG_FILE, "r") as infile, open(LOG_FILE, "a") as log:
    for line in infile:
        stripped = line.strip()

        # Duplicate address objects
        if re.match(r"^set (device-group \S+|shared) address ", stripped):
            parts = stripped.split()

            if parts[1] == "device-group":
                dg = parts[2]
                name = parts[4]
                # everything after the name is optional (field, value, description, etc.)
                field = parts[5] if len(parts) > 5 else None
                value = parts[6] if len(parts) > 6 else None
            else:  # shared scope
                dg = "shared"
                name = parts[2]
                field = parts[3] if len(parts) > 3 else None
                value = parts[4] if len(parts) > 4 else None

            # ✅ Only act if field is ip-netmask/ip-range/fqdn
            if field in ["ip-netmask", "ip-range", "fqdn"] and value:
                t = translate_value(value)
                if t:
                    new_name = name + "_pdc"
                    if (dg, new_name) not in created_pdc:
                        # Create duplicate object in the SAME DG
                        if dg == "shared":
                            new_line = f"set shared address {new_name} {field} {t}\n"
                        else:
                            new_line = f"set device-group {dg} address {new_name} {field} {t}\n"

                        output_lines.append(line)          # keep original
                        output_lines.append(new_line)      # add new
                        log.write(f"{dg}:{name} {value} -> {new_name} {t}\n")

                        created_pdc.add((dg, new_name))
                        continue
                        
        # Update rule references
        m = rule_pattern.match(stripped)
        if m:
            dg_scope, rule_name, remainder = m.groups()
            new_remainder = remainder
            for field in ["source", "destination"]:
                if f"{field} " in new_remainder:
                    pattern = re.compile(rf"{field}(?:\s+\[([^\]]+)\]| ([^\s]+))")
                    mm = pattern.search(new_remainder)
                    if mm:
                        entries = mm.group(1).split() if mm.group(1) else [mm.group(2)]
                        new_entries = list(entries)
                        for e in entries:
                            if not e.endswith("_pdc"):
                                pdce = e + "_pdc"
                                if pdce not in new_entries:
                                    new_entries.append(pdce)
                                    log.write(f"Rule {rule_name} ({field}): {e} -> {pdce}\n")
                        new_entries = unique(new_entries)
                        new_remainder = pattern.sub(f"{field} [ {' '.join(new_entries)} ]", new_remainder)
            output_lines.append(f"set {dg_scope} rulebase security rules {rule_name} {new_remainder}\n")
            continue

        output_lines.append(line)

with open(CONFIG_FILE, "w") as outfile:
    outfile.writelines(output_lines)
