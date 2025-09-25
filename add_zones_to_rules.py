#!/usr/bin/env python3
import re
import shutil

CONFIG_FILE = "panorama.set"        # Panorama set-command config
MAPPING_FILE = "zone_mapping.input" # device-group to zone mapping
LOG_FILE = "add_zones.log"

def load_mapping():
    """Load device-group -> zone mapping from zone_mapping.input"""
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
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")
    mapping = load_mapping()

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    output = []
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write("=== Add zones based on device-group mapping ===\n\n")

        # Match security rule zone lines
        zone_re = re.compile(
            r'^set (device-group\s+(\S+)) (?:pre|post)-rulebase security rules ("[^"]+"|\S+) '
            r'(from|to) (.+)$', re.IGNORECASE)

        for raw in lines:
            stripped = raw.strip()
            m = zone_re.match(stripped)
            if not m:
                output.append(raw)
                continue

            full_scope, dg_name, rule_name, direction, zones_part = m.groups()
            mapped_zone = mapping.get(dg_name)
            if not mapped_zone:
                output.append(raw)
                continue

            # Tokenize the existing zone list (handles quoted zone names)
            import shlex
            tokens = shlex.split(zones_part)

            # Skip if mapped zone already present
            if mapped_zone in [t.strip('"') for t in tokens]:
                output.append(raw)
                continue

            # Add mapped zone and bracket if needed
            if len(tokens) == 1:
                # Only one existing zone -> add brackets with required spaces
                new_zones = f"[ {tokens[0]} {mapped_zone} ]"
            else:
                # Already bracketed or multi-zones -> just append mapped_zone,
                # preserving any existing bracket syntax.
                if zones_part.strip().startswith("["):
                    # insert before closing bracket, maintain spaces
                    new_zones = re.sub(r'\]\s*$', f' {mapped_zone} ]', zones_part)
                else:
                    # multiple zones but not bracketed: wrap all in brackets
                    new_zones = "[ " + " ".join(tokens + [mapped_zone]) + " ]"

            new_line = f"set {full_scope} pre-rulebase security rules {rule_name} {direction} {new_zones}\n"
            output.append(new_line)
            log.write(f"UPDATED:\n  OLD: {stripped}\n  NEW: {new_line.rstrip()}\n\n")

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(output)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Detailed changes logged to {LOG_FILE}")

if __name__ == "__main__":
    main()

