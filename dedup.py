#!/usr/bin/env python3
import os
import re
import shutil

CONFIG_FILE = "panorama.set"
LOG_FILE    = "deduplicate_addresses_and_groups.log"

def parse_config(lines):
    """Collect address objects and address groups with their values/members."""
    addr_objects = {}    # value -> [names]
    group_objects = {}   # sorted tuple of members -> [names]
    addr_values = {}     # name -> value (for later replacement)
    group_members = {}   # name -> tuple of members

    # Address object regex
    addr_re = re.compile(
        r'^set (device-group\s+\S+|shared)\s+address\s+(\S+)\s+(ip-netmask|ip-range)\s+(\S+)',
        re.IGNORECASE
    )
    # Address group regex (static members only)
    group_re = re.compile(
        r'^set (device-group\s+\S+|shared)\s+address-group\s+(\S+)\s+static\s+\[([^\]]+)\]',
        re.IGNORECASE
    )

    for l in lines:
        s = l.strip()
        m = addr_re.match(s)
        if m:
            name, val = m.group(2), m.group(4)
            addr_values[name] = val
            addr_objects.setdefault(val, []).append(name)
            continue
        m = group_re.match(s)
        if m:
            name = m.group(2)
            members = tuple(sorted(m.group(3).split()))
            group_members[name] = members
            group_objects.setdefault(members, []).append(name)
    return addr_objects, group_objects, addr_values, group_members

def prompt_user(dupes, obj_type):
    """Prompt user to select which duplicate to keep."""
    keep_map = {}  # name_to_keep -> [duplicates_to_replace]
    for key, names in dupes.items():
        if len(names) < 2:
            continue
        print(f"\nDuplicate {obj_type} for value/members: {key}")
        for i, n in enumerate(names, 1):
            print(f"  {i}) {n}")
        print("  s) skip this duplicate set")
        choice = input("Select number of the name to keep (or 's' to skip): ").strip().lower()
        if choice == 's':
            continue
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(names):
                keep = names[idx]
                to_replace = [n for n in names if n != keep]
                keep_map[keep] = to_replace
        except ValueError:
            print("Invalid choice, skipping.")
    return keep_map

def update_rules(lines, addr_keep_map):
    """Replace references in Security and NAT rules to duplicates with the chosen name."""
    rule_re = re.compile(
        r'^set (device-group\s+\S+|shared)\s+((pre|post)-rulebase (security|application-override)|rulebase nat) rules ',
        re.IGNORECASE
    )
    output = []
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        for line in lines:
            s = line.strip()
            if rule_re.match(s):
                tokens = line.split()
                changed = False
                for i, t in enumerate(tokens):
                    for keep, dups in addr_keep_map.items():
                        if t in dups:
                            tokens[i] = keep
                            changed = True
                            log.write(f"RULE UPDATE: replaced {t} with {keep} in:\n  {line}")
                if changed:
                    line = " ".join(tokens) + "\n"
            output.append(line)
    return output

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    addr_objs, group_objs, addr_values, group_members = parse_config(lines)

    # Find duplicates: same value -> multiple names
    addr_dupes = {k:v for k,v in addr_objs.items() if len(v)>1}
    group_dupes = {k:v for k,v in group_objs.items() if len(v)>1}

    if not addr_dupes and not group_dupes:
        print("No duplicates found.")
        return

    print("\n=== Deduplication Interactive Tool ===")
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write("=== Deduplication Log ===\n\n")

    keep_map = {}
    keep_map.update(prompt_user(addr_dupes, "address object"))
    keep_map.update(prompt_user(group_dupes, "address group"))

    if not keep_map:
        print("No duplicates selected for merging.")
        return

    # Update rules (Security & NAT)
    new_lines = update_rules(lines, keep_map)

    # Remove the definitions of the duplicates the user chose to replace
    filtered = []
    for line in new_lines:
        s = line.strip()
        drop = False
        for keep, dups in keep_map.items():
            for dup in dups:
                if re.match(rf'^set (device-group\s+\S+|shared)\s+(address|address-group)\s+{re.escape(dup)}\b', s):
                    drop = True
                    break
            if drop: break
        if not drop:
            filtered.append(line)

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(filtered)

    print(f"\n✅ Finished. Updated {CONFIG_FILE} (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Details of replacements logged to {LOG_FILE}")

if __name__ == "__main__":
    main()
