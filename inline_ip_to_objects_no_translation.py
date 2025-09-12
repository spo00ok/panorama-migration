#!/usr/bin/env python3
import ipaddress
import re
import os
import shutil

CONFIG_FILE = "panorama.set"
LOG_FILE = "inline_ip_to_objects_no_translation.log"

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

    # Safety backup before editing in place
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

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
        log.write("=== Inline IP to Objects (No Translation) Log ===\n")

        for line in lines:
            stripped = line.strip()

            # Security rule with potential inline IPs/subnets/ranges
            if re.match(r"^set (device-group \S+|shared) pre-rulebase security rules ", stripped):
                parts = stripped.split()
                dg = parts[2] if parts[1] == "device-group" else "shared"
                rule_name = parts[5]  # after 'rules'
                new_parts = []
                for token in parts:
                    # Only handle literal inline IPs / subnets / ranges
                    if (re.match(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$", token) or "-" in token) \
                        and not re.search("[a-zA-Z]", token):
                        val = token   # no translation — keep as-is
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

    print(f"Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"Log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
