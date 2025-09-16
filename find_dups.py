#!/usr/bin/env python3
import os
import re
from collections import defaultdict

CONFIG_FILE = "panorama.set"
LOG_FILE    = "same_members_different_names.log"

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    # value -> set of names for address/service objects
    object_values = defaultdict(set)
    # members (sorted string) -> set of names for address/service groups
    group_members = defaultdict(set)

    with open(CONFIG_FILE, "r") as f:
        for line in f:
            stripped = line.strip()

            # --- Address or Service objects ---
            # Example: set device-group DG1 address WebSrv1 ip-netmask 10.1.1.5
            m_obj = re.match(
                r"^set (device-group\s+\S+|shared)\s+(address|service)\s+(\S+)\s+(ip-netmask|ip-range|protocol|port)\s+(.+)",
                stripped
            )
            if m_obj:
                # Use object value string (everything after field) as key
                value = m_obj.group(5).strip()
                object_values[value].add(m_obj.group(3))
                continue

            # --- Address or Service groups ---
            # Example: set device-group DG1 address-group WebServers static [ web1 web2 ]
            m_grp = re.match(
                r"^set (device-group\s+\S+|shared)\s+(address-group|service-group)\s+(\S+)\s+static\s+\[([^\]]+)\]",
                stripped
            )
            if m_grp:
                members = " ".join(sorted(m_grp.group(4).split()))
                group_members[members].add(m_grp.group(3))
                continue

    with open(LOG_FILE, "w") as log:
        log.write("=== Same Members / Values but Different Names Log ===\n\n")

        # Objects with identical value but different names
        for val, names in object_values.items():
            if len(names) > 1:
                log.write(f"[Objects] Value: {val}\n")
                for n in sorted(names):
                    log.write(f"    Name: {n}\n")
                log.write("\n")

        # Groups with identical member list but different names
        for mems, names in group_members.items():
            if len(names) > 1:
                log.write(f"[Groups] Members: {mems}\n")
                for n in sorted(names):
                    log.write(f"    Name: {n}\n")
                log.write("\n")

    print(f"✅ Scan complete. Conflicts logged to {LOG_FILE}")

if __name__ == "__main__":
    main()
