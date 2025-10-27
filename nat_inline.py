#!/usr/bin/env python3
import os
import re
import ipaddress

CONFIG_FILE       = "panorama.set"
TRANSLATION_FILE  = "translation.input"
OUT_CHANGED_NATS  = "modified_nats.set"
LOG_FILE          = "translate_nat_inline_ips.log"

# ------------------- Translation loading -------------------

def load_translation():
    """
    translation.input rows (any mix):
      single_ip,new_ip
      cidr,new_cidr
      start-end,new_ip_or_cidr     (range on the left)
    Returns:
      one_to_one: dict[str_ip] -> IPvXAddress
      networks:   list[(IPvXNetwork old, IPvXNetwork new)]  (sorted most-specific first)
      ranges:     list[(IPvXAddress start, IPvXAddress end, rhs_type, rhs_val)]
                  rhs_type in {"ip","subnet"}; rhs_val IPvXAddress or IPvXNetwork
    """
    one_to_one, networks, ranges = {}, [], []
    with open(TRANSLATION_FILE, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw or "," not in raw:
                continue
            orig, new = [p.strip() for p in raw.split(",", 1)]

            # Range on LHS
            if "-" in orig and "/" not in orig:
                try:
                    s_txt, e_txt = [p.strip() for p in orig.split("-", 1)]
                    s = ipaddress.ip_address(s_txt); e = ipaddress.ip_address(e_txt)
                    if type(s) is type(e) and int(s) <= int(e):
                        # RHS may be IP or subnet
                        try:
                            rhs = ipaddress.ip_address(new); ranges.append((s, e, "ip", rhs))
                        except ValueError:
                            try:
                                rhs = ipaddress.ip_network(new, strict=False); ranges.append((s, e, "subnet", rhs))
                            except ValueError:
                                pass
                except ValueError:
                    pass
                continue

            # Subnet on LHS
            if "/" in orig:
                try:
                    old_net = ipaddress.ip_network(orig, strict=False)
                    new_net = ipaddress.ip_network(new, strict=False)
                    if old_net.version == new_net.version:
                        networks.append((old_net, new_net))
                except ValueError:
                    pass
                continue

            # Single IP on LHS
            try:
                old_ip = ipaddress.ip_address(orig); new_ip = ipaddress.ip_address(new)
                if old_ip.version == new_ip.version:
                    one_to_one[str(old_ip)] = new_ip
            except ValueError:
                pass

    # prefer most-specific subnet match
    networks.sort(key=lambda t: t[0].prefixlen, reverse=True)
    return one_to_one, networks, ranges

# ------------------- Mapping logic -------------------

def convert_single_ip(ip, one_to_one, networks, ranges):
    """Return mapped host IP (IPv4/IPv6) or None."""
    s = str(ip)
    if s in one_to_one:
        return one_to_one[s]

    for old_net, new_net in networks:
        if ip.version == old_net.version and ip in old_net:
            off = int(ip) - int(old_net.network_address)
            if off < new_net.num_addresses:
                return type(new_net.network_address)(int(new_net.network_address) + off)

    for start, end, rhs_type, rhs_val in ranges:
        if ip.version == start.version and int(start) <= int(ip) <= int(end):
            if rhs_type == "ip":
                return rhs_val
            else:
                off = int(ip) - int(start)
                if off < rhs_val.num_addresses:
                    return type(rhs_val.network_address)(int(rhs_val.network_address) + off)
    return None

def translate_token(token, one_to_one, networks, ranges):
    """
    Translate a token that may be:
      - single IP
      - single IP with /mask (preserve mask)
      - range A-B  (map both endpoints)
    Keep token 'shape' (IP stays IP, range stays range). Preserve quotes if present.
    """
    raw = token.strip()
    q = raw.startswith('"') and raw.endswith('"')
    core = raw[1:-1] if q else raw

    # Range?
    if "-" in core and not re.search(r"[g-zG-Z]", core):
        try:
            a_txt, b_txt = [p.strip() for p in core.split("-", 1)]
            a = ipaddress.ip_address(a_txt); b = ipaddress.ip_address(b_txt)
        except ValueError:
            return token
        a_new = convert_single_ip(a, one_to_one, networks, ranges) or a
        b_new = convert_single_ip(b, one_to_one, networks, ranges) or b
        out = f"{a_new}-{b_new}"
        return f'"{out}"' if q else out

    # Single IP (optional /mask)
    m = re.match(r"^([0-9a-fA-F:\.]+)(?:/(\d{1,3}))?$", core)
    if not m:
        return token
    ip_txt, mask = m.group(1), m.group(2)
    try:
        ip = ipaddress.ip_address(ip_txt)
    except ValueError:
        return token

    mapped = convert_single_ip(ip, one_to_one, networks, ranges)
    if mapped is None:
        return token

    out = str(mapped) + (f"/{mask}" if mask else "")
    return f'"{out}"' if q else out

# ------------------- NAT rule parsing -------------------

# Capture rule identity so we can emit the full rule if ANY line for it changed
NAT_LINE_RE = re.compile(
    r'^set\s+(?P<scope>(?:device-group\s+\S+|shared))\s+'
    r'(?P<rb>(?:pre|post)-rulebase nat|rulebase nat)\s+rules\s+'
    r'(?P<rname>"[^"]+"|\S+)\s+(?P<rest>.*)$',
    re.IGNORECASE
)

TOKEN_LIKE_IP = re.compile(r'^[0-9a-fA-F:\.]+(?:/\d{1,3})?$')

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Config file {CONFIG_FILE} not found.")
        return

    one_to_one, networks, ranges = load_translation()

    # rule_key -> list of dicts {orig, new, changed, order}
    per_rule = {}
    # For logging: per rule, list of replacements
    per_rule_changes = {}

    with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            s = line.strip()
            m = NAT_LINE_RE.match(s)
            if not m:
                continue

            scope = m.group("scope")
            rb    = m.group("rb")
            rname = m.group("rname")
            key   = (scope, rb, rname)

            # Translate IP-ish tokens in the WHOLE line
            tokens = line.split()
            changed = False
            replacements = []

            for i, tok in enumerate(tokens):
                looks_ipish = TOKEN_LIKE_IP.match(tok.strip('"')) or ("-" in tok and not re.search("[g-zG-Z]", tok))
                if not looks_ipish:
                    continue
                new_tok = translate_token(tok, one_to_one, networks, ranges)
                if new_tok != tok:
                    replacements.append((tok, new_tok))
                    tokens[i] = new_tok
                    changed = True

            new_line = " ".join(tokens) if changed else line

            per_rule.setdefault(key, []).append({
                "order": lineno,
                "orig": line,
                "new": new_line,
                "changed": changed,
            })
            if changed:
                per_rule_changes.setdefault(key, []).extend(replacements)

    # Emit only rules where any line changed; include ALL lines for that rule (full NAT config)
    changed_rules = [k for k, lines in per_rule.items() if any(d["changed"] for d in lines)]
    with open(OUT_CHANGED_NATS, "w", encoding="utf-8") as outf, \
         open(LOG_FILE, "w", encoding="utf-8") as logf:

        if not changed_rules:
            logf.write("No NAT rules required edits based on provided mappings.\n")
        else:
            logf.write(f"Modified NAT rules: {len(changed_rules)}\n\n")

        for key in sorted(changed_rules, key=lambda k: min(d["order"] for d in per_rule[k])):
            scope, rb, rname = key
            logf.write(f'=== {scope}  {rb}  rule {rname} ===\n')
            # preserve original order
            lines = sorted(per_rule[key], key=lambda d: d["order"])
            for d in lines:
                # write modified version if changed; otherwise original
                outf.write(d["new"] if d["changed"] else d["orig"])
            # log replacements (dedup for readability)
            seen = set()
            for old, new in per_rule_changes.get(key, []):
                if (old, new) in seen:
                    continue
                seen.add((old, new))
                logf.write(f"  {old}  ->  {new}\n")
            logf.write("\n")

    print(f"✅ Wrote full configs for modified NAT rules to {OUT_CHANGED_NATS}")
    print(f"✅ Translation log written to {LOG_FILE}")

if __name__ == "__main__":
    main()

