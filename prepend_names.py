#!/usr/bin/env python3
import os
import re
import shutil

CONFIG_FILE = "panorama.set"                  # Panorama set-command config
LOG_FILE    = "prepend_svb_host_update_refs.log"

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    shutil.copy(CONFIG_FILE, CONFIG_FILE + ".bak")

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    # ------------------------------------------------------------------
    # Collect address-object and address-group names to rename
    # ------------------------------------------------------------------
    rename_map = {}
    for l in lines:
        m = re.match(
            r'^set (device-group\s+\S+|shared)\s+(address|address-group)\s+(".*?"|\S+)\s+',
            l.strip()
        )
        if m:
            obj_name = m.group(3)
            if obj_name.startswith('"'):
                inner = obj_name.strip('"')
                if not inner.startswith("svb_host_"):
                    rename_map[inner] = "svb_host_" + inner
            else:
                if not obj_name.startswith("svb_host_"):
                    rename_map[obj_name] = "svb_host_" + obj_name

    output_lines = []
    with open(LOG_FILE, "w", encoding="utf-8", errors="replace") as log:
        log.write("=== Prepend 'svb_host_' to Object Names and References Log ===\n\n")

        for line in lines:
            stripped = line.strip()
            old_line = line

            # ------------------------------------------------------------------
            # Rename address/address-group definitions themselves
            # ------------------------------------------------------------------
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
                # ------------------------------------------------------------------
                # Update references in Security or NAT rules
                #     – include NAT source/destination sections.
                # ------------------------------------------------------------------
                m_rule = re.match(
                    r'^set (device-group\s+\S+|shared)\s+((pre|post)-rulebase (security|application-override)|rulebase nat) '
                    r'rules ("[^"]+"|\S+)\s+(.*)$',
                    stripped
                )
                if m_rule:
                    rule_prefix = f"set {m_rule.group(1)} {m_rule.group(2)} rules {m_rule.group(5)} "
                    remainder = m_rule.group(6)

                    # --- Replace inside square brackets ---
                    def replace_inside_brackets(match):
                        inner = match.group(1)
                        tokens = inner.split()
                        out_tokens = []
                        for tok in tokens:
                            clean = tok.strip('"')
                            # ✅ Only prefix if it's NAT source/destination object or any address-object reference
                            if clean in rename_map:
                                if tok.startswith('"'):
                                    out_tokens.append('"' + rename_map[clean] + '"')
                                else:
                                    out_tokens.append(rename_map[clean])
                            else:
                                out_tokens.append(tok)
                        return "[" + " ".join(out_tokens) + "]"

                    remainder = re.sub(r'\[([^\]]+)\]', replace_inside_brackets, remainder)

                    # --- Replace single tokens (for unbracketed src/dst too) ---
                    def replace_single(match):
                        tok = match.group(0)
                        clean = tok.strip('"')
                        if clean in rename_map:
                            return '"' + rename_map[clean] + '"' if tok.startswith('"') else rename_map[clean]
                        return tok

                    remainder = re.sub(r'(".*?"|\S+)', replace_single, remainder)

                    # ✅ NAT-specific: we only touch source/destination address objects or groups,
                    # but since NAT references to address objects appear only in those fields,
                    # the above replacement effectively covers them.
                    line = rule_prefix + remainder + "\n"
                    log.write(f"UPDATED REFERENCE:\n  OLD: {old_line.rstrip()}\n"
                              f"  NEW: {line.rstrip()}\n\n")

            output_lines.append(line)

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(output_lines)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Log of changes written to {LOG_FILE}")

if __name__ == "__main__":
    main()
