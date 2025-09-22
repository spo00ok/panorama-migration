#!/usr/bin/env python3
import os
import re
import shutil

CONFIG_FILE   = "panorama.set"          # Panorama set-command config
MAPPING_FILE  = "zone_mapping.input"    # Device-group,zone pairs
LOG_FILE      = "add_zones_from_mapping_only.log"

def load_mapping():
    mapping = {}
    with open(MAPPING_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or "," not in line:
                continue
            dg, zone = [p.strip() for p in line.split(",", 1)]
            mapping[dg] = zone
    return mapping

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    mapping = load_mapping()
    if not mapping:
        print("No device-group to zone mappings found.")
        return

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    output = []
    with open(LOG_FILE, "w", encoding="utf-8", errors="replace") as log:
        log.write("=== Add Zones from Mapping File Log ===\n\n")

        # Security or NAT rule line
        rule_re = re.compile(
            r'^set device-group (\S+) (pre|post)-rulebase (security|application-override) rules ',
            re.IGNORECASE
        )

        for line in lines:
            stripped = line.strip()
            m = rule_re.match(stripped)
            if m:
                dg = m.group(1)
                if dg in mapping:           # Only modify if DG in mapping
                    zone = mapping[dg]
                    old_line = line

                    # Add zone if rule has zones specified and none is 'any'
                    # Match 'from' or 'to' zone blocks that are not 'any'
                    if re.search(r'\b(from|to)\s+(?!any\b)', stripped):
                        if f' {zone} ' not in stripped:
                            # Simple example: append zone to the end of the line
                            # Adjust logic if you only want to add to 'from' or 'to'
                            line = old_line.rstrip() + f" {zone}\n"
                            log.write(f"UPDATED: {dg} -> added zone '{zone}'\n"
                                      f"  OLD: {old_line.rstrip()}\n"
                                      f"  NEW: {line.rstrip()}\n\n")

            output.append(line)

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(output)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Log written to {LOG_FILE}")

if __name__ == "__main__":
    main()

