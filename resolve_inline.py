#!/usr/bin/env python3
import os
import re
import shutil

CONFIG_FILE = "panorama.set"
LOG_FILE    = "replace_inline_ips_with_objects.log"

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    # 🔹 Backup original config before modifying
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    with open(CONFIG_FILE, "r") as f:
        lines = f.readlines()

    # ------------------------------------------------------------------
    # Step 1: Map each address object value -> object name
    # ------------------------------------------------------------------
    value_to_obj = {}
    for l in lines:
        m = re.match(
            r"^set (device-group\s+\S+|shared)\s+address\s+(\S+)\s+(ip-netmask|ip-range)\s+(.+)",
            l.strip()
        )
        if m:
            name = m.group(2)
            value = m.group(4).strip()
            # store only the first object with that exact value
            value_to_obj.setdefault(value, name)

    # ------------------------------------------------------------------
    # Step 2: Replace inline IPs in security rule lines if an object exists
    # ------------------------------------------------------------------
    output_lines = []
    with open(LOG_FILE, "w") as log:
        log.write("=== Inline IP Replacement Log ===\n\n")

        for line in lines:
            stripped = line.strip()

            # Match both pre and post-rulebase security rules
            if re.match(r"^set (device-group \S+|shared) (pre|post)-rulebase security rules ", stripped):
                old_line = line
                tokens = line.split()
                new_tokens = []
                modified = False

                for token in tokens:
                    # literal IP, subnet or range (skip tokens with letters -> object names/FQDNs)
                    if (re.match(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$", token) or "-" in token) \
                        and not re.search("[a-zA-Z]", token):
                        if token in value_to_obj:
                            new_tokens.append(value_to_obj[token])
                            log.write("REPLACED:\n")
                            log.write("  OLD: " + old_line.rstrip() + "\n")
                            log.write("  ->  replaced '" + token + "' with object '" + value_to_obj[token] + "'\n\n")
                            modified = True
                            continue
                    new_tokens.append(token)

                if modified:
                    line = " ".join(new_tokens) + "\n"

            output_lines.append(line)

    # 🔹 Overwrite the config file in place with updated lines
    with open(CONFIG_FILE, "w") as f:
        f.writelines(output_lines)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Replacement log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
