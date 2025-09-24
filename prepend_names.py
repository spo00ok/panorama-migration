#!/usr/bin/env python3
import os
import re
import shutil

CONFIG_FILE = "panorama.set"                  # Panorama set-command config
LOG_FILE    = "prepend_svb_host_update_refs.log"

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
    # 1) Build rename_map from address / address-group definitions
    # ------------------------------------------------------------------
    rename_map = {}
    for l in lines:
        m = re.match(
            r'^set (device-group\s+\S+|shared)\s+(address|address-group)\s+(".*?"|\S+)\s+',
            l.strip()
        )
        if m:
            name_tok = m.group(3)
            if name_tok.startswith('"'):
                inner = name_tok.strip('"')
                if not inner.startswith("svb_host_"):
                    rename_map[inner] = "svb_host_" + inner
            else:
                if not name_tok.startswith("svb_host_"):
                    rename_map[name_tok] = "svb_host_" + name_tok

    output_lines = []
    with open(LOG_FILE, "w", encoding="utf-8", errors="replace") as log:
        log.write("=== Prepend 'svb_host_' to Object Names, References, and Address-Group Members ===\n\n")

        for line in lines:
            stripped = line.strip()
            old_line = line

            # ------------------------------------------------------------------
            # 2) Handle address-group static member lines FIRST
            # ------------------------------------------------------------------
            m_member = re.match(
                r'^(set (?:device-group\s+\S+|shared)\s+address-group\s+\S+\s+static\s+)\[([^\]]+)\](.*)$',
                stripped
            )
            if m_member:
                prefix, members_str, suffix = m_member.groups()
                # split members safely (handles quoted names with spaces)
                import shlex
                tokens = shlex.split(members_str)
                new_tokens = []
                changed = False
                for tok in tokens:
                    clean = tok.strip('"')
                    if clean in rename_map:
                        name = rename_map[clean]
                        if tok.startswith('"'):
                            name = '"' + name + '"'
                        new_tokens.append(name)
                        changed = True
                    else:
                        new_tokens.append(tok)
                if changed:
                    line = f"{prefix}[{' '.join(new_tokens)}]{suffix}\n"
                    log.write(f"UPDATED ADDRESS-GROUP MEMBERS:\n  OLD: {old_line.rstrip()}\n"
                              f"  NEW: {line.rstrip()}\n\n")

            else:
                # ------------------------------------------------------------------
                # 3) Rename object definitions themselves
                # ------------------------------------------------------------------
                m_def = re.match(
                    r'^set (device-group\s+\S+|shared)\s+(address|address-group)\s+(".*?"|\S+)\s+(.*)$',
                    stripped
                )
                if m_def:
                    name_tok = m_def.group(3)
                    rest = m_def.group(4)
                    if name_tok.startswith('"'):
                        inner = name_tok.strip('"')
                        if inner in rename_map:
                            new_name = '"' + rename_map[inner] + '"'
                            line = f"set {m_def.group(1)} {m_def.group(2)} {new_name} {rest}\n"
                            log.write(f"RENAMED DEFINITION:\n  OLD: {old_line.rstrip()}\n"
                                      f"  NEW: {line.rstrip()}\n\n")
                    else:
                        if name_tok in rename_map:
                            new_name = rename_map[name_tok]
                            line = f"set {m_def.group(1)} {m_def.group(2)} {new_name} {rest}\n"
                            log.write(f"RENAMED DEFINITION:\n  OLD: {old_line.rstrip()}\n"
                                      f"  NEW: {line.rstrip()}\n\n")

                else:
                    # ------------------------------------------------------------------
                    # 4) Update references inside Security OR NAT rules
                    #    - supports: pre/post security, application-override,
                    #                rulebase nat, pre/post nat
                    # ------------------------------------------------------------------
                    m_rule = re.match(
                        r'^set (device-group\s+\S+|shared)\s+'
                        r'((?:pre|post)-rulebase (?:security|application-override|nat)|rulebase nat) '
                        r'rules ("[^"]+"|\S+)\s+(.*)$',
                        stripped
                    )
                    if m_rule:
                        prefix = f"set {m_rule.group(1)} {m_rule.group(2)} rules {m_rule.group(3)} "
                        remainder = m_rule.group(4)

                        # Replace tokens inside [ ... ] lists first
                        def replace_inside_brackets(match):
                            inner = match.group(1)
                            tokens = inner.split()
                            out = []
                            for tok in tokens:
                                clean = tok.strip('"')
                                if clean in rename_map:
                                    out.append(('"' + rename_map[clean] + '"') if tok.startswith('"')
                                               else rename_map[clean])
                                else:
                                    out.append(tok)
                            return "[" + " ".join(out) + "]"

                        remainder = re.sub(r'\[([^\]]+)\]', replace_inside_brackets, remainder)

                        # Then replace any remaining standalone tokens (unbracketed)
                        def replace_single(match):
                            tok = match.group(0)
                            clean = tok.strip('"')
                            if clean in rename_map:
                                return '"' + rename_map[clean] + '"' if tok.startswith('"') else rename_map[clean]
                            return tok

                        remainder = re.sub(r'(".*?"|\S+)', replace_single, remainder)

                        line = prefix + remainder + "\n"
                        log.write(f"UPDATED REFERENCE:\n  OLD: {old_line.rstrip()}\n"
                                  f"  NEW: {line.rstrip()}\n\n")

            output_lines.append(line)

    with open(CONFIG_FILE, "w", encoding="utf-8", errors="replace") as f:
        f.writelines(output_lines)

    print(f"✅ Updated {CONFIG_FILE} in place (backup saved as {CONFIG_FILE}.bak)")
    print(f"✅ Changes logged to {LOG_FILE}")

if __name__ == "__main__":
    main()
