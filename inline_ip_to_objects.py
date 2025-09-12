import re
import shutil

CONFIG_FILE = "../panorama.set"
LOG_FILE = "../logs/inline_ip_conversion.log"

shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

rule_pattern = re.compile(r"^set (device-group \S+|shared) rulebase security rules (\S+) (.+)$")
ip_pattern = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
subnet_pattern = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
range_pattern = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}(?:\.\d{1,3}){3}$")

existing_objects = {}

with open(CONFIG_FILE, "r") as infile:
    for line in infile:
        if " address " in line and not "address-group" in line:
            parts = line.split()
            dg = "shared" if parts[1] == "address" else parts[2]
            name = parts[2] if dg == "shared" else parts[3]
            value = parts[-1].strip()
            existing_objects[value] = name

with open(LOG_FILE, "w") as log:
    log.write("=== Inline IP/Subnet/Range Conversion Log ===\n")

def unique(seq):
    seen, result = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            result.append(x)
    return result

def normalize_name(value: str) -> str:
    return "ADDR_" + value.replace(".", "_").replace("/", "_").replace("-", "_")

output_lines = []
new_objects = set()

def replace_tokens(entries, dg, rule_name, field, log):
    new_tokens = []
    for token in entries:
        if ip_pattern.match(token) or subnet_pattern.match(token) or range_pattern.match(token):
            if token in existing_objects:
                obj_name = existing_objects[token]
            else:
                obj_name = normalize_name(token)
                existing_objects[token] = obj_name
                if (dg, obj_name) not in new_objects:
                    if dg == "shared":
                        obj_line = f"set shared address {obj_name} ip-netmask {token}\n"
                    else:
                        obj_line = f"set device-group {dg} address {obj_name} ip-netmask {token}\n"
                    output_lines.append(obj_line)
                    log.write(f"Created object {obj_name} = {token} in {dg}\n")
                    new_objects.add((dg, obj_name))
            if obj_name not in new_tokens:
                new_tokens.append(obj_name)
                log.write(f"Rule {rule_name} ({field}): {token} -> {obj_name}\n")
        else:
            new_tokens.append(token)
    return new_tokens

with open(CONFIG_FILE, "r") as infile, open(LOG_FILE, "a") as log:
    for line in infile:
        stripped = line.strip()
        m = rule_pattern.match(stripped)
        if m:
            dg_scope, rule_name, remainder = m.groups()
            dg = dg_scope.split()[1] if dg_scope.startswith("device-group") else "shared"
            new_remainder = remainder
            for field in ["source", "destination"]:
                if f"{field} " in new_remainder:
                    pattern = re.compile(rf"{field}(?:\s+\[([^\]]+)\]| ([^\s]+))")
                    mm = pattern.search(new_remainder)
                    if mm:
                        entries = mm.group(1).split() if mm.group(1) else [mm.group(2)]
                        new_entries = replace_tokens(entries, dg, rule_name, field, log)
                        new_entries = unique(new_entries)
                        new_remainder = pattern.sub(f"{field} [ {' '.join(new_entries)} ]", new_remainder)
            output_lines.append(f"set {dg_scope} rulebase security rules {rule_name} {new_remainder}\n")
        else:
            output_lines.append(line)

with open(CONFIG_FILE, "w") as outfile:
    outfile.writelines(output_lines)
