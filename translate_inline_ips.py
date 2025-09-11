import ipaddress
import re
import shutil

CONFIG_FILE = "../panorama.set"
TRANSLATION_FILE = "../translation.input"
LOG_FILE = "../logs/inline_ip_translation.log"

shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

ip_map, subnet_map = {}, {}
with open(TRANSLATION_FILE, "r") as f:
    for line in f:
        line = line.strip()
        if not line or "," not in line:
            continue
        orig_str, new_str = [x.strip() for x in line.split(",")]
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", orig_str):
            ip_map[orig_str] = new_str
        else:
            subnet_map[str(ipaddress.ip_network(orig_str, strict=False))] = str(ipaddress.ip_network(new_str, strict=False))

with open(LOG_FILE, "w") as log:
    log.write("=== Inline IP Translation Log ===\n")

def unique(seq):
    seen, result = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            result.append(x)
    return result

def translate_ip(ip):
    if ip in ip_map:
        return ip_map[ip]
    try:
        addr = ipaddress.ip_address(ip)
        for net_str, new_net_str in subnet_map.items():
            net = ipaddress.ip_network(net_str)
            new_net = ipaddress.ip_network(new_net_str)
            if addr in net:
                offset = int(addr) - int(net.network_address)
                return str(new_net.network_address + offset)
    except Exception:
        pass
    return None

output_lines = []
rule_pattern = re.compile(r"^set (device-group \S+|shared) rulebase security rules (\S+) (.+)$")

with open(CONFIG_FILE, "r") as infile, open(LOG_FILE, "a") as log:
    for line in infile:
        stripped = line.strip()
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
                            t = translate_ip(e)
                            if t and t not in new_entries:
                                new_entries.append(t)
                                log.write(f"Rule {rule_name} ({field}): {e} -> {t}\n")
                        new_entries = unique(new_entries)
                        new_remainder = pattern.sub(f"{field} [ {' '.join(new_entries)} ]", new_remainder)
            output_lines.append(f"set {dg_scope} rulebase security rules {rule_name} {new_remainder}\n")
        else:
            output_lines.append(line)

with open(CONFIG_FILE, "w") as outfile:
    outfile.writelines(output_lines)
