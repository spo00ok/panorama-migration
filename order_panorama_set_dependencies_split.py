#!/usr/bin/env python3
import re
import os
import shutil
from collections import defaultdict

CONFIG_FILE = "panorama.set"
LOG_FILE    = "ordering.log"

# Buckets and the order in which they will be scanned
BUCKET_ORDER = [
    "address_obj",
    "address_group",
    "service_obj",
    "service_group",
    "tag",
    "security_rule",
    "nat_rule",
    "other"
]

def classify_line(line):
    s = line.strip()

    if re.match(r"^set (device-group\s+\S+|shared)\s+address\s+\S+\s+", s):
        return "address_obj"
    if re.match(r"^set (device-group\s+\S+|shared)\s+address-group\s+\S+\s+", s):
        return "address_group"
    if re.match(r"^set (device-group\s+\S+|shared)\s+service\s+\S+\s+", s):
        return "service_obj"
    if re.match(r"^set (device-group\s+\S+|shared)\s+service-group\s+\S+\s+", s):
        return "service_group"
    if re.match(r"^set (device-group\s+\S+|shared)\s+tag\s+\S+", s):
        return "tag"
    if re.match(r"^set (device-group \S+|shared) (pre|post)-rulebase security rules ", s):
        return "security_rule"
    if re.match(r"^set (device-group \S+|shared) rulebase nat rules ", s):
        return "nat_rule"
    return "other"

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    # bucket -> list of lines
    buckets = {b: [] for b in BUCKET_ORDER}

    with open(CONFIG_FILE, "r") as f:
        for line in f:
            bucket = classify_line(line)
            buckets[bucket].append(line)

    with open(LOG_FILE, "w") as log:
        log.write("=== Panorama set-command ordering log ===\n\n")

        for bucket in BUCKET_ORDER:
            lines = buckets[bucket]
            out_file = f"{bucket}.set"
            with open(out_file, "w") as out:
                out.writelines(lines)
            log.write(f"{bucket}: {len(lines)} lines -> {out_file}\n")

    print("✅ Split complete.")
    print(f"✅ Summary written to {LOG_FILE}")
    print(f"✅ Backup of original config saved as {CONFIG_FILE}.bak")

if __name__ == "__main__":
    main()
