#!/usr/bin/env python3
import os
import re
import shutil

CONFIG_FILE = "panorama.set"
LOG_FILE    = "prepend_svb_host.log"

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    # 🔹 Backup the config before editing
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    with open(CONFIG_FILE, "r") as f:
        lines = f.readlines()

    output_lines = []
    with open(LOG_FILE, "w") as log:
        log.write("=== Prepend 'svb_host' to Address Objects and Groups Log ===\n\n")

        for line in lines:
            stripped = line.strip()

            # Match address object or address-group definitions in device-group or shared
            # Examples:
            # set device-group DG1 address myObject ip-netmask 10.1.1.5
            # set device-group DG1 address-group myGroup static [ ... ]
            m = re.match(
                r"^set (device-group\s+\S+|shared)\s+(address|address-group)\s+(\S+)\s+(.*)",
                stripped
            )
            if m:
                prefix = m.group(1)           # device-group <name> or shared
                obj_type = m.group(2)         # address or address-group
                obj_name = m.group(3)         # current object/group name
                rest = m.group(4)             # the rest of the line

                # Only prepend if not already starting with svb_host
                if not obj_name.startswith("svb_host"):
                    new_name = "svb_host" + obj_name
                    new_line = f"set {prefix} {obj_type} {new_name} {rest}\n"
                    output_lines.append(new_line)
                    log.write("RENAMED:\n")
                    log.write("  OLD: " + stripped + "\n")
                    log.write("  NEW: " + new_line.strip() + "\n\n")
                    continue

            # All other lines stay unchanged
            output_lines.append(line)

    # 🔹 Overwrite the config file with updated lines
    with open(CONFIG_FILE, "w") as f:
        f.writelines(output_lines)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Name change log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
