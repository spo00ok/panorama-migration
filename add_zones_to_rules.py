#!/usr/bin/env python3
import os
import re
import shutil

CONFIG_FILE = "panorama.set"
LOG_FILE    = "add_zones_to_rules.log"

# Map each device group to the zone to append when needed
ZONE_MAP = {
    "Production": "PROD-ZONE",
    "Production_DMZ": "DMZ-ZONE",
    "shared": "SHARED-ZONE"
}

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    # 🔹 Create a safety backup of the original config
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    with open(CONFIG_FILE, "r") as f:
        lines = f.readlines()

    output_lines = []
    with open(LOG_FILE, "w") as log:
        log.write("=== Zone Append Log ===\n")

        for line in lines:
            stripped = line.strip()

            # Match both pre and post rulebase security rules
            m = re.match(
                r"^set (device-group\s+(\S+)|shared)\s+(pre|post)-rulebase security rules\s+(\S+)\s+(.*)",
                stripped
            )
            if not m:
                output_lines.append(line)
                continue

            dg = "shared" if m.group(1).startswith("shared") else m.group(2)
            rule_name = m.group(4)
            remainder = m.group(5)
            zone_to_add = ZONE_MAP.get(dg)
            if not zone_to_add:
                output_lines.append(line)
                continue

            modified = False
            new_remainder = remainder

            # ✅ Append the device-group's zone only when zones exist and none are 'any'
            for direction in ["from", "to"]:
                # Look for an existing from/to clause (single or [list])
                pat = re.compile(rf"{direction}(?:\s+\[([^\]]+)\]| (\S+))")
                mdir = pat.search(new_remainder)
                if mdir:
                    zones = mdir.group(1).split() if mdir.group(1) else [mdir.group(2)]
                    # Only append if no zone is 'any'
                    if zones and all(z.lower() != "any" for z in zones):
                        if zone_to_add not in zones:
                            zones.append(zone_to_add)
                            new_zones = " ".join(zones)
                            new_remainder = pat.sub(f"{direction} [ {new_zones} ]", new_remainder)
                            log.write(f"Rule {rule_name} ({dg}): appended {zone_to_add} to {direction}\n")
                            modified = True
                # If clause is missing or contains 'any', leave it untouched

            if modified:
                prefix = f"set {'device-group ' + dg if dg != 'shared' else 'shared'} {m.group(3)}-rulebase security rules {rule_name}"
                # Replace the current rule line with the updated one
                line = f"{prefix} {new_remainder}\n"

            output_lines.append(line)

    # 🔹 Overwrite the original config file with the updated lines
    with open(CONFIG_FILE, "w") as f:
        f.writelines(output_lines)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Zone append log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
