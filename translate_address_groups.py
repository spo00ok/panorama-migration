import ipaddress
import re
import shutil

CONFIG_FILE = "../panorama.set"
TRANSLATION_FILE = "../translation.input"
LOG_FILE = "../logs/address_group_translation.log"

shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

# Load translation mappings
ip_map = {}
subnet_map = {}

with open(TRANSLATION_FILE, "r") as f:
    for line in f:
        line = line.strip()
        if not line or "," not in line:
            continue
        orig_str, new_str = [x.strip() for x in line.split(",")]
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", orig_str):
            ip_map[orig_str] = new_str
        else:
            orig_net = ipaddress.ip_network(orig_str, strict=False)
            new_net = ipaddress.ip_network(new_str, strict=False)
            subnet_map[str(orig_net)] = str(new_net)

with open(LOG_FILE, "w") as log:
    log.write("=== Address Group Translation Log ===\n")

def unique(seq):
    seen, result = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            result.append(x)
    return result

def translate_member(member):
    if member in ip_map:
        return ip_map[member]
    try:
        if "/" in member:
            net = ipaddress.ip_network(member, strict=False)
            if str(net) in subnet_map:
                return subnet_map[str(net)]
    except Exception:
        pass
    return None

output_lines = []
with open(CONFIG_FILE, "r") as infile, open(LOG_FILE, "a") as log:
    for line in infile:
        stripped = line.strip()
        if " address-group " in stripped and " static " in stripped:
            parts = stripped.split()
            members = re.findall(r"\[([^\]]+)\]", stripped)
            if members:
                member_list = members[0].split()
                translated = []
                for m in member_list:
                    t = translate_member(m)
                    if t:
                        translated.append(t)
                        log.write(f"Address-group {parts[2]}: {m} -> {t}\n")
                all_members = unique(member_list + translated)
                new_line = re.sub(r"\[([^\]]+)\]", "[ " + " ".join(all_members) + " ]", stripped)
                output_lines.append(new_line + "\n")
                continue
        output_lines.append(line)

with open(CONFIG_FILE, "w") as outfile:
    outfile.writelines(output_lines)
