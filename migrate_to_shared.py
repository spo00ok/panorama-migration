#!/usr/bin/env python3
import os
import re
import shutil

CONFIG_FILE = "panorama.set"
LOG_FILE    = "migrate_to_shared.log"

# Patterns for object types to migrate
OBJ_TYPES = ["address", "address-group", "service", "service-group"]

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    # 🔹 Backup the original file
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    with open(CONFIG_FILE, "r") as f:
        lines = f.readlines()

    shared_defs = set()  # store full shared commands for duplicate detection
    for l in lines:
        if re.match(r"^set shared ", l):
            # record exact shared object lines for later comparison
            shared_defs.add(l.strip())

    output_lines = []
    with open(LOG_FILE, "w") as log:
        log.write("=== Migration Log: Device-group objects moved to Shared ===\n\n")

        for line in lines:
            stripped = line.strip()

            # Match device-group object lines for the types we want
            m = re.match(r"^set device-group \S+ (" + "|".join(OBJ_TYPES) + r") ", stripped)
            if m:
                # Create equivalent shared command
                shared_line = re.sub(r"^set device-group \S+ ", "set shared ", stripped, count=1)

                if shared_line in shared_defs:
                    # Already exists in shared exactly – skip and remove DG line
                    log.write("SKIPPED (duplicate exists in shared):\n")
                    log.write("  " + stripped + "\n\n")
                    # do not add device-group line back to output (removes it)
                    continue
                else:
                    # Add to output as shared, remove original DG line
                    output_lines.append(shared_line + "\n")
                    shared_defs.add(shared_line)
                    log.write("MOVED:\n")
                    log.write("  FROM: " + stripped + "\n")
                    log.write("  TO:   " + shared_line + "\n\n")
                    continue  # skip original DG line (removal)

            # All other lines stay unchanged
            output_lines.append(line)

    # 🔹 Rewrite config in place
    with open(CONFIG_FILE, "w") as f:
        f.writelines(output_lines)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Migration log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
