#!/usr/bin/env python3
import os
import re
import shutil

CONFIG_FILE = "panorama.set"
LOG_FILE    = "prepend_svb_host_update_refs.log"

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    # 🔹 Backup the config before editing
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    with open(CONFIG_FILE, "r") as f:
        lines = f.readlines()

    # ------------------------------------------------------------------
    # 1️⃣ Collect all address object & group names
    # ------------------------------------------------------------------
    rename_map = {}  # old_name -> new_name
    for l in lines:
        m = re.match(
            r"^set (device-group\s+\S+|shared)\s+(address|address-group)\s+(\S+)\s+",
            l.strip()
        )
        if m:
            old_name = m.group(3)
            if not old_name.startswith("svb_host_"):
                new_name = "svb_host_" + old_name
                rename_map[old_name] = new_name

    output_lines = []
    with open(LOG_FILE, "w") as log:
        log.write("=== Prepend 'svb_host_' to Object Names and References Log ===\n\n")

        for line in lines:
            stripped = line.strip()
            old_line = line

            # ------------------------------------------------------------------
            # 2️⃣ Rename the definitions themselves
            # ------------------------------------------------------------------
            m = re.match(
                r"^set (device-group\s+\S+|shared)\s+(address|address-group)\s+(\S+)\s+(.*)",
                stripped
            )
            if m:
                obj_name = m.group(3)
                if obj_name in rename_map:
                    new_name = rename_map[obj_name]
                    line = f"set {m.group(1)} {m.group(2)} {new_name} {m.group(4)}\n"
                    log.write("RENAMED DEFINITION:\n")
                    log.write("  OLD: " + old_line.rstrip() + "\n")
                    log.write("  NEW: " + line.rstrip() + "\n\n")

            else:
                # ------------------------------------------------------------------
                # 3️⃣ Update references inside security or NAT rules
                # ------------------------------------------------------------------
                if re.match(r"^set (device-group \S+|shared) (pre|post)-rulebase security rules ", stripped) \
                   or re.match(r"^set (device-group \S+|shared) rulebase nat rules ", stripped):
                    tokens = line.split()
                    changed = False
                    for i, t in enumerate(tokens):
                        if t in rename_map:
                            tokens[i] = rename_map[t]
                            changed = True
                    if changed:
                        line = " ".join(tokens) + "\n"
                        log.write("UPDATED REFERENCE:\n")
                        log.write("  OLD: " + old_line.rstrip() + "\n")
                        log.write("  NEW: " + line.rstrip() + "\n\n")

            output_lines.append(line)

    # 🔹 Overwrite the config file with all changes
    with open(CONFIG_FILE, "w") as f:
        f.writelines(output_lines)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Log of changes written to {LOG_FILE}")

if __name__ == "__main__":
    main()
