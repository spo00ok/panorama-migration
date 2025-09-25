#!/usr/bin/env python3
import shlex
import shutil

CONFIG_FILE  = "panorama.set"         # Panorama set-command config
MAPPING_FILE = "zone_mapping.input"   # device-group to zone mapping
LOG_FILE     = "add_zones.log"

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

def needs_quotes(s: str) -> bool:
    return any(c.isspace() for c in s)

def rule_token(rule_name: str) -> str:
    """Rebuild rule name token, quoting if it contains spaces."""
    return f'"{rule_name}"' if needs_quotes(rule_name) else rule_name

def main():
    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")
    mapping = load_mapping()

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    out = []
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write("=== Add zones based on device-group mapping (tokenized matcher) ===\n\n")

        for raw in lines:
            line = raw.rstrip("\n")
            stripped = line.strip()

            # Fast path: must start with 'set device-group '
            if not stripped.lower().startswith("set device-group "):
                out.append(raw)
                continue

            try:
                toks = shlex.split(stripped)
            except ValueError:
                out.append(raw)
                continue

            # Expect at least: set device-group <DG> <pre|post>-rulebase security rules <rule-name> <from|to> <zones...>
            if len(toks) < 9:
                out.append(raw)
                continue
            if toks[0].lower() != "set" or toks[1].lower() != "device-group":
                out.append(raw)
                continue

            dg = toks[2]
            prepost = toks[3].lower()
            if prepost not in ("pre-rulebase", "post-rulebase"):
                out.append(raw)
                continue

            if toks[4].lower() != "security" or toks[5].lower() != "rules":
                out.append(raw)
                continue

            rule_name = toks[6]  # shlex returns unquoted rule name as single token
            prop = toks[7].lower()

            # Only operate on 'from' or 'to' zone lines
            if prop not in ("from", "to"):
                out.append(raw)
                continue

            mapped_zone = mapping.get(dg)
            if not mapped_zone:
                out.append(raw)
                continue

            zone_tokens = toks[8:]
            if not zone_tokens:
                out.append(raw)
                continue

            # 1️⃣ Skip if the clause is literally "any"
            if len(zone_tokens) == 1 and zone_tokens[0].lower() == "any":
                out.append(raw)
                continue

            # Determine zone list and whether already bracketed
            bracketed = False
            zones = []
            if zone_tokens[0] == "[" and zone_tokens[-1] == "]" and len(zone_tokens) >= 3:
                bracketed = True
                zones = zone_tokens[1:-1]  # inside brackets
            else:
                zones = zone_tokens[:]

            # 2️⃣ Skip if mapped zone already present
            if mapped_zone in zones:
                out.append(raw)
                continue

            # 3️⃣ Add mapped zone and normalise to bracketed form when needed
            if bracketed:
                new_zone_str = "[ " + " ".join(zones + [mapped_zone]) + " ]"
            else:
                if len(zones) == 1:
                    new_zone_str = "[ " + zones[0] + " " + mapped_zone + " ]"
                else:
                    new_zone_str = "[ " + " ".join(zones + [mapped_zone]) + " ]"

            # Rebuild the line
            new_line = (
                "set device-group "
                + dg
                + " "
                + prepost
                + " security rules "
                + rule_token(rule_name)
                + " "
                + prop
                + " "
                + new_zone_str
            )

            out.append(new_line + "\n")
            log.write("UPDATED:\n  OLD: " + stripped + "\n  NEW: " + new_line + "\n\n")

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(out)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Log written to {LOG_FILE}")

if __name__ == "__main__":
    main()
