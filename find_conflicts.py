#!/usr/bin/env python3
import os
import re
import shutil
from collections import defaultdict

CONFIG_FILE = "panorama.set"
LOG_FILE    = "conflicting_address_names.log"

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    # Safety backup of the config (optional, not required to run)
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    # Dictionaries: { (dg, name) : set(values) }
    addr_objects = defaultdict(set)
    addr_groups  = defaultdict(set)

    with open(CONFIG_FILE, "r") as f:
        for line in f:
            stripped = line.strip()

            # Address object lines
            m_obj = re.match(r"^set (device-group\s+(\S+)|shared) address (\S+) (ip-netmask|ip-range) (.+)", stripped)
            if m_obj:
                dg = "shared" if m_obj.group(1).startswith("shared") else m_obj.group(2)
                name = m_obj.group(3)
                value = m_obj.group(5).strip()
                addr_objects[(dg, name)].add(value)
                continue

            # Address group static members
            m_grp = re.match(r"^set (device-group\s+(\S+)|shared) address-group (\S+) static \[([^\]]+)\]", stripped)
            if m_grp:
                dg = "shared" if m_grp.group(1).startswith("shared") else m_grp.group(2)
                name = m_grp.group(3)
                members = " ".join(sorted(m_grp.group(4).split()))
                addr_groups[(dg, name)].add(members)
                continue

    # Find conflicts
    with open(LOG_FILE, "w") as log:
        log.write("=== Conflicting Address Names Log ===\n\n")

        # Address objects with same name but different values
        for (dg, name), vals in addr_objects.items():
            if len(vals) > 1:
                log.write(f"[Address Object] Device-Group: {dg}, Name: {name}\n")
                for v in vals:
                    log.write(f"    value: {v}\n")
                log.write("\n")

        # Address groups with same name but different member sets
        for (dg, name), members in addr_groups.items():
            if len(members) > 1:
                log.write(f"[Address Group] Device-Group: {dg}, Name: {name}\n")
                for m in members:
                    log.write(f"    members: {m}\n")
                log.write("\n")

    print(f"Scan complete. Conflicts logged to {LOG_FILE}")
    print(f"A backup of the config was saved as {CONFIG_FILE}.bak")

if __name__ == "__main__":
    main()
