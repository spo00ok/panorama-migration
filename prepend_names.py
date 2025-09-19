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

    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    with open(CONFIG_FILE, "r") as f:
        lines = f.readlines()

    rename_map = {}
    # 1️⃣ Collect address object / address-group names only
    for l in lines:
        m = re.match(
            r'^set (device-group\s+\S+|shared)\s+(address|address-group)\s+(".*?"|\S+)\s+',
            l.strip()
        )
        if m:
            obj_name = m.group(3)
            # handle quoted or unquoted names
            if obj_name.startswith('"'):
                inner = obj_name.strip('"')
                if not inner.startswith("svb_host_"):
                    rename_map[inner] = 'svb_host_' + inner
            else:
                if not obj_name.startswith("svb_host_"):
                    rename_map[obj_name] = 'svb_host_' + obj_name

    output_lines = []
    with open(LOG_FILE, "w") as log:
        log.write("=== Prepend 'svb_host_' to Object Names and References Log ===\n\n")

        for line in lines:
            stripped = line.strip()
            old_line = line

            # 2️⃣ Rename only the definitions themselves
            m = re.match(
                r'^set (device-group\s+\S+|shared)\s+(address|address-group)\s+(".*?"|\S+)\s+(.*)',
                stripped
            )
            if m:
                name_token = m.group(3)
                rest = m.group(4)
                if name_token.startswith('"'):
                    inner = name_token.strip('"')
                    if inner in rename_map:
                        new_name = '"' + rename_map[inner] + '"'
                        line = f"set {m.group(1)} {m.group(2)} {new_name} {rest}\n"
                        log.write(f"RENAMED DEFINITION:\n  OLD: {old_line.rstrip()}\n"
                                  f"  NEW: {line.rstrip()}\n\n")
                else:
                    if name_token in rename_map:
                        new_name = rename_map[name_token]
                        line = f"set {m.group(1)} {m.group(2)} {new_name} {rest}\n"
                        log.write(f"RENAMED DEFINITION:\n  OLD: {old_line.rstrip()}\n"
                                  f"  NEW: {line.rstrip()}\n\n")

            else:
                # 3️⃣ Update references inside rules BUT NOT the rule name itself
                if re.match(
                    r'^set (device-group \S+|shared) (pre|post)-rulebase (security|application-override) rules ',
                    stripped
                ):
                    tokens = line.split()
                    changed = False
                    # tokens[0..4] are: set device-group <DG>|shared pre|post-rulebase <type> rules <RuleName>
                    # Skip token for <RuleName> (index 6)
                    for i, t in enumerate(tokens):
                        if i <= 6:  # up to and including the rule name token
                            continue
                        # match unquoted object name references only
                        clean = t.strip('"')
                        if clean in rename_map:
                            # preserve quotes if present
                            if t.startswith('"'):
                                tokens[i] = '"' + rename_map[clean] + '"'
                            else:
                                tokens[i] = rename_map[clean]
                            changed = True
                    if changed:
                        line = " ".join(tokens) + "\n"
                        log.write(f"UPDATED REFERENCE:\n  OLD: {old_line.rstrip()}\n"
                                  f"  NEW: {line.rstrip()}\n\n")

            output_lines.append(line)

    with open(CONFIG_FILE, "w") as f:
        f.writelines(output_lines)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Log of changes written to {LOG_FILE}")

if __name__ == "__main__":
    main()

    main()
