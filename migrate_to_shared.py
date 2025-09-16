#!/usr/bin/env python3
# migrate_to_shared_everything.py
#
# Migrates from device-groups -> shared:
#   - Address objects (IP/CIDR/range, FQDN; preserves attrs: description, comment, tag, color)
#   - Address-groups: static (members) & dynamic (filter)
#   - EDLs (external-list): preserves full tail
#   - Service objects (protocol/port/...; preserves attrs)
#   - Service groups (members)
#
# Duplicate handling:
#   - If identical -> single shared object (keep original name).
#   - If different AND referenced in a NAT rule -> NAT variant keeps original name; others become *_obj, *_obj2...
#   - If different AND NOT NAT-referenced -> for groups: union members (keep name); for objects: keep one canonical
#     under original name, others become *_obj*.
#
# Rule updates:
#   - Security + NAT rules are updated per-device-group using (dg,name)->new_name mapping.
#
# Insertion/removal:
#   - Insert new shared definitions immediately after the *first* original line for that object name.
#   - Remove all device-group originals.
#
# Idempotent:
#   - Re-runs won't duplicate shared entries.
#
# I/O:
#   - Input/Output: panorama.set (in-place)
#   - Log: migration.log

import re
from collections import defaultdict, OrderedDict

SET_FILE = "panorama.set"
LOG_FILE = "migration.log"

# ---------------- Regexes ----------------
# Device-group scope
RE_DG_ADDR            = re.compile(r'^set\s+device-group\s+(\S+)\s+address\s+(\S+)\s+(.+?)\s*$')
RE_DG_AG_STATIC       = re.compile(r'^set\s+device-group\s+(\S+)\s+address-group\s+(\S+)\s+static\s+(.+?)\s*$')
RE_DG_AG_DYNAMIC      = re.compile(r'^set\s+device-group\s+(\S+)\s+address-group\s+(\S+)\s+dynamic\s+filter\s+(.+?)\s*$')
RE_DG_EDL             = re.compile(r'^set\s+device-group\s+(\S+)\s+external-list\s+(\S+)\s+(.+?)\s*$')

RE_DG_SERVICE         = re.compile(r'^set\s+device-group\s+(\S+)\s+service\s+(\S+)\s+(.+?)\s*$')
RE_DG_SVC_GROUP       = re.compile(r'^set\s+device-group\s+(\S+)\s+service-group\s+(\S+)\s+members\s+\[(.+?)\]\s*$')

# Shared scope (for idempotency and merges)
RE_SH_ADDR            = re.compile(r'^set\s+shared\s+address\s+(\S+)\s+(.+?)\s*$')
RE_SH_AG_STATIC       = re.compile(r'^set\s+shared\s+address-group\s+(\S+)\s+static\s+(.+?)\s*$')
RE_SH_AG_DYNAMIC      = re.compile(r'^set\s+shared\s+address-group\s+(\S+)\s+dynamic\s+filter\s+(.+?)\s*$')
RE_SH_EDL             = re.compile(r'^set\s+shared\s+external-list\s+(\S+)\s+(.+?)\s*$')

RE_SH_SERVICE         = re.compile(r'^set\s+shared\s+service\s+(\S+)\s+(.+?)\s*$')
RE_SH_SVC_GROUP       = re.compile(r'^set\s+shared\s+service-group\s+(\S+)\s+members\s+\[(.+?)\]\s*$')

# Rule lines
RE_RULE_SECURITY      = re.compile(r'^set\s+(?:device-group\s+(\S+)\s+)?rulebase\s+security\s+rules\s+')
RE_RULE_NAT           = re.compile(r'^set\s+(?:device-group\s+(\S+)\s+)?rulebase\s+nat\s+rules\s+')

def tokenize(line: str) -> list:
    return line.rstrip("\n").split()

def normalize_space(s: str) -> str:
    return re.sub(r'\s+', ' ', s.strip())

# ---------------- Attribute-aware parsing for Address & Service tails ----------------
def _pop_attr_pairs(work: str):
    """Pop known attrs (description/comment quoted; tag/color word). Returns (work_wo_attrs, attrs_dict)."""
    desc = comment = tag = color = None

    def pop_q(name):
        nonlocal work
        m = re.search(r'(?:^|\s)'+name+r'\s+"([^"]*)"\s*$', work)
        if m:
            val = m.group(1)
            work = work[:m.start()].rstrip()
            return val
        return None

    def pop_w(name):
        nonlocal work
        m = re.search(r'(?:^|\s)'+name+r'\s+(\S+)\s*$', work)
        if m:
            val = m.group(1)
            work = work[:m.start()].rstrip()
            return val
        return None

    changed = True
    while changed:
        changed = False
        x = pop_q("description");  changed = changed or (x is not None);  desc    = x if x is not None else desc
        x = pop_q("comment");      changed = changed or (x is not None);  comment = x if x is not None else comment
        x = pop_w("tag");          changed = changed or (x is not None);  tag     = x if x is not None else tag
        x = pop_w("color");        changed = changed or (x is not None);  color   = x if x is not None else color

    attrs = {}
    if desc    is not None: attrs["description"] = desc
    if comment is not None: attrs["comment"]     = comment
    if tag     is not None: attrs["tag"]         = tag
    if color   is not None: attrs["color"]       = color
    return work.strip(), attrs

def parse_addr_tail(tail: str):
    """
    Returns:
      core_sig: string signature for equality (ignores attrs). FQDN normalized to 'fqdn <value>'; else raw address.
      emit_tail: tail to emit (core + attrs in stable order).
    """
    work = tail.strip()
    work, attrs = _pop_attr_pairs(work)
    m = re.match(r'^(?:type\s+)?fqdn\s+(.+)$', work, flags=re.IGNORECASE)
    if m:
        core = f"fqdn {normalize_space(m.group(1))}"
    else:
        core = normalize_space(work)
    core_sig = core  # attributes removed already
    emit = core
    if "description" in attrs: emit += f' description "{attrs["description"]}"'
    if "comment"     in attrs: emit += f' comment "{attrs["comment"]}"'
    if "tag"         in attrs: emit += f' tag {attrs["tag"]}'
    if "color"       in attrs: emit += f' color {attrs["color"]}'
    return core_sig, emit

def parse_service_tail(tail: str):
    """
    Service tail can be: protocol tcp/udp/sctp ... port X[,Y] source-port ... timeout ... app-id ... etc.
    We preserve anything as 'core' except known attrs; signature ignores attrs; emit re-adds attrs in stable order.
    """
    work = tail.strip()
    work, attrs = _pop_attr_pairs(work)
    core = normalize_space(work)
    core_sig = core
    emit = core
    if "description" in attrs: emit += f' description "{attrs["description"]}"'
    if "comment"     in attrs: emit += f' comment "{attrs["comment"]}"'
    if "tag"         in attrs: emit += f' tag {attrs["tag"]}'
    if "color"       in attrs: emit += f' color {attrs["color"]}'
    return core_sig, emit

def ag_members_signature(members_list):
    return tuple(sorted(set(members_list)))

# ---------------- Load file ----------------
with open(SET_FILE, "r", encoding="utf-8") as f:
    lines = [ln.rstrip("\n") for ln in f]

# ---------------- First pass: collect objects & rules ----------------
addr_defs = {}     # (dg,name) -> {'sig','emit','first_idx'}
ag_static = defaultdict(lambda: defaultdict(OrderedDict))  # dg -> name -> OrderedSet members
ag_dynamic = {}    # (dg,name) -> {'filter','first_idx'}
edl_defs  = {}     # (dg,name) -> {'tail','first_idx'}

svc_defs  = {}     # (dg,name) -> {'sig','emit','first_idx'}
svc_groups= defaultdict(lambda: defaultdict(list))  # dg -> name -> members list (dedup on emit)

# Existing shared (idempotency)
sh_addr_sig = {}                    # name -> sig
sh_ag_static_members = defaultdict(set)  # name -> set(members)
sh_ag_dynamic = {}                  # name -> filter
sh_edl_tail = {}                    # name -> tail(normalized)

sh_svc_sig = {}                     # name -> sig
sh_svcgrp_members = defaultdict(set)# name -> set(members)

# Rules & NAT references (per DG)
rules = []  # {'idx','dg','tokens','is_nat','line'}
nat_refs_by_dg = defaultdict(set)  # name -> set(DGs)
all_names = set()

for idx, ln in enumerate(lines):
    # ---- DG objects
    m = RE_DG_ADDR.match(ln)
    if m:
        dg, name, tail = m.groups()
        sig, emit = parse_addr_tail(tail)
        addr_defs[(dg, name)] = {'sig': sig, 'emit': emit, 'first_idx': idx}
        all_names.add(name); continue

    m = RE_DG_AG_STATIC.match(ln)
    if m:
        dg, name, member = m.groups()
        ag_static[dg][name][member] = True
        all_names.add(name); continue

    m = RE_DG_AG_DYNAMIC.match(ln)
    if m:
        dg, name, filt = m.groups()
        ag_dynamic[(dg, name)] = {'filter': normalize_space(filt), 'first_idx': idx}
        all_names.add(name); continue

    m = RE_DG_EDL.match(ln)
    if m:
        dg, name, tail = m.groups()
        edl_defs[(dg, name)] = {'tail': normalize_space(tail), 'first_idx': idx}
        all_names.add(name); continue

    m = RE_DG_SERVICE.match(ln)
    if m:
        dg, name, tail = m.groups()
        sig, emit = parse_service_tail(tail)
        svc_defs[(dg, name)] = {'sig': sig, 'emit': emit, 'first_idx': idx}
        all_names.add(name); continue

    m = RE_DG_SVC_GROUP.match(ln)
    if m:
        dg, name, members_blob = m.groups()
        members = [t for t in members_blob.strip().split() if t != "]" and t != "["]
        # Keep order but unique
        seen = set()
        ordered = []
        for t in members:
            if t not in seen:
                ordered.append(t); seen.add(t)
        svc_groups[dg][name] = ordered
        all_names.add(name); continue

    # ---- Shared objects (for idempotency)
    m = RE_SH_ADDR.match(ln)
    if m:
        name, tail = m.groups()
        sig, _ = parse_addr_tail(tail)
        sh_addr_sig[name] = sig
        all_names.add(name); continue

    m = RE_SH_AG_STATIC.match(ln)
    if m:
        name, member = m.groups()
        sh_ag_static_members[name].add(member)
        all_names.add(name); continue

    m = RE_SH_AG_DYNAMIC.match(ln)
    if m:
        name, filt = m.groups()
        sh_ag_dynamic[name] = normalize_space(filt)
        all_names.add(name); continue

    m = RE_SH_EDL.match(ln)
    if m:
        name, tail = m.groups()
        sh_edl_tail[name] = normalize_space(tail)
        all_names.add(name); continue

    m = RE_SH_SERVICE.match(ln)
    if m:
        name, tail = m.groups()
        sig, _ = parse_service_tail(tail)
        sh_svc_sig[name] = sig
        all_names.add(name); continue

    m = RE_SH_SVC_GROUP.match(ln)
    if m:
        name, members_blob = m.groups()
        for t in members_blob.strip().split():
            sh_svcgrp_members[name].add(t)
        all_names.add(name); continue

    # ---- Rules
    msec = RE_RULE_SECURITY.match(ln)
    mnat = RE_RULE_NAT.match(ln)
    if msec or mnat:
        dg = (msec or mnat).group(1)
        toks = tokenize(ln)
        rules.append({'idx': idx, 'dg': dg, 'tokens': toks, 'is_nat': bool(mnat), 'line': ln})
        if mnat and dg is not None:
            for t in toks:
                if t in all_names:
                    nat_refs_by_dg[t].add(dg)
        continue

# ---------------- Build variant lists by name ----------------
def by_name(meta_map):
    out = defaultdict(list)  # name -> list of (scope_name, meta)
    for (scope, name), meta in meta_map.items():
        out[name].append((scope, meta))
    return out

addr_vars = by_name(addr_defs)
ag_s_vars = defaultdict(list)  # name -> list of (scope, members_list)
for dg, groups in ag_static.items():
    for name, od in groups.items():
        ag_s_vars[name].append((dg, list(od.keys())))

ag_d_vars = by_name(ag_dynamic)
edl_vars  = by_name(edl_defs)
svc_vars  = by_name(svc_defs)
svcgrp_vars = defaultdict(list)  # name -> list of (scope, members)
for dg, groups in svc_groups.items():
    for name, members in groups.items():
        svcgrp_vars[name].append((dg, members))

# ---------------- Planning: decide shared emits + per-DG renames ----------------
rule_rename = {}  # (dg,name)->new_name

shared_emit_addr = {}         # name/alt -> emit_tail
shared_emit_ag_s = {}         # name/alt -> members(list)
shared_emit_ag_d = {}         # name/alt -> filter
shared_emit_edl  = {}         # name/alt -> tail
shared_emit_svc  = {}         # name/alt -> emit_tail
shared_emit_svcg = {}         # name/alt -> members(list)

def alloc_alt(base, taken):
    if base not in taken:
        return base
    i = 1
    while True:
        cand = f"{base}{i}"
        if cand not in taken:
            return cand
        i += 1

# ----- Addresses -----
for name, lst in addr_vars.items():
    dg_lst = [(dg, meta['sig'], meta['emit']) for (dg, meta) in lst if dg != "shared"]
    if not dg_lst: continue
    sigs = {sig for (_, sig, _) in dg_lst}
    nat_dgs = nat_refs_by_dg.get(name, set())
    existing_sig = sh_addr_sig.get(name)

    if len(sigs) == 1:
        sig = next(iter(sigs))
        emit = next(e for (_, s, e) in dg_lst if s == sig)
        if existing_sig != sig:
            shared_emit_addr[name] = emit
        for (dg, _, _) in dg_lst:
            rule_rename[(dg, name)] = name
    else:
        canon_dg = next(iter(nat_dgs)) if nat_dgs else dg_lst[0][0]
        canon_sig, canon_emit = next((s, e) for (dg, s, e) in dg_lst if dg == canon_dg)
        if existing_sig != canon_sig:
            shared_emit_addr[name] = canon_emit
        taken = {name}
        alt_for_sig = {}
        for (dg, s, e) in dg_lst:
            if s == canon_sig:
                rule_rename[(dg, name)] = name
            else:
                if s not in alt_for_sig:
                    alt = alloc_alt(f"{name}_obj", taken); taken.add(alt)
                    alt_for_sig[s] = (alt, e)
                    shared_emit_addr[alt] = e
                rule_rename[(dg, name)] = alt_for_sig[s][0]

# ----- Static Address-Groups -----
for name, lst in ag_s_vars.items():
    dg_lst = [(dg, members) for (dg, members) in lst if dg != "shared"]
    if not dg_lst: continue
    nat_dgs = nat_refs_by_dg.get(name, set())
    all_sets = [frozenset(m) for (_, m) in dg_lst]
    all_equal = len(set(all_sets)) == 1

    if all_equal:
        # Canonical members (preserve existing shared members order if present)
        existing = list(sh_ag_static_members.get(name, []))
        ordered = OrderedDict((m, True) for m in existing)
        for _, members in dg_lst:
            for m in members: ordered[m] = True
        shared_emit_ag_s[name] = list(ordered.keys())
        for (dg, _) in dg_lst:
            rule_rename[(dg, name)] = name
    else:
        if nat_dgs:
            canon_dg = next(iter(nat_dgs))
            canon_members = next((m for (dg, m) in dg_lst if dg == canon_dg), dg_lst[0][1])
            shared_emit_ag_s[name] = list(OrderedDict.fromkeys(canon_members))
            taken = {name}
            alt_for_sig = {}
            for (dg, members) in dg_lst:
                key = ag_members_signature(members)
                if key == ag_members_signature(canon_members):
                    rule_rename[(dg, name)] = name
                else:
                    if key not in alt_for_sig:
                        alt = alloc_alt(f"{name}_obj", taken); taken.add(alt)
                        alt_for_sig[key] = alt
                        shared_emit_ag_s[alt] = list(OrderedDict.fromkeys(members))
                    rule_rename[(dg, name)] = alt_for_sig[key]
        else:
            # Union
            ordered = OrderedDict()
            for _, members in dg_lst:
                for m in members: ordered[m] = True
            # prepend already shared members to keep stable
            for m in list(sh_ag_static_members.get(name, []))[::-1]:
                ordered.move_to_end(m, last=False)
            shared_emit_ag_s[name] = list(ordered.keys())
            for (dg, _) in dg_lst:
                rule_rename[(dg, name)] = name

# ----- Dynamic Address-Groups -----
for name, lst in ag_d_vars.items():
    dg_lst = [(dg, meta['filter']) for (dg, meta) in lst if dg != "shared"]
    if not dg_lst: continue
    nat_dgs = nat_refs_by_dg.get(name, set())
    filters = {normalize_space(f) for (_, f) in dg_lst}
    existing = sh_ag_dynamic.get(name)

    if len(filters) == 1:
        f = next(iter(filters))
        if existing != f:
            shared_emit_ag_d[name] = f
        for (dg, _) in dg_lst:
            rule_rename[(dg, name)] = name
    else:
        canon_dg = next(iter(nat_dgs)) if nat_dgs else dg_lst[0][0]
        canon = next((normalize_space(f) for (dg, f) in dg_lst if dg == canon_dg), normalize_space(dg_lst[0][1]))
        if existing != canon:
            shared_emit_ag_d[name] = canon
        taken = {name}
        alt_for = {}
        for (dg, f) in dg_lst:
            key = normalize_space(f)
            if key == canon:
                rule_rename[(dg, name)] = name
            else:
                if key not in alt_for:
                    alt = alloc_alt(f"{name}_obj", taken); taken.add(alt)
                    alt_for[key] = alt
                    shared_emit_ag_d[alt] = key
                rule_rename[(dg, name)] = alt_for[key]

# ----- EDLs -----
for name, lst in edl_vars.items():
    dg_lst = [(dg, meta['tail']) for (dg, meta) in lst if dg != "shared"]
    if not dg_lst: continue
    nat_dgs = nat_refs_by_dg.get(name, set())
    tails = {t for (_, t) in dg_lst}
    existing = sh_edl_tail.get(name)

    if len(tails) == 1:
        t = next(iter(tails))
        if existing != t:
            shared_emit_edl[name] = t
        for (dg, _) in dg_lst:
            rule_rename[(dg, name)] = name
    else:
        canon_dg = next(iter(nat_dgs)) if nat_dgs else dg_lst[0][0]
        canon = next((t for (dg, t) in dg_lst if dg == canon_dg), dg_lst[0][1])
        if existing != canon:
            shared_emit_edl[name] = canon
        taken = {name}
        alt_for = {}
        for (dg, t) in dg_lst:
            if t == canon:
                rule_rename[(dg, name)] = name
            else:
                if t not in alt_for:
                    alt = alloc_alt(f"{name}_obj", taken); taken.add(alt)
                    alt_for[t] = alt
                    shared_emit_edl[alt] = t
                rule_rename[(dg, name)] = alt_for[t]

# ----- Service objects -----
for name, lst in svc_vars.items():
    dg_lst = [(dg, meta['sig'], meta['emit']) for (dg, meta) in lst if dg != "shared"]
    if not dg_lst: continue
    sigs = {sig for (_, sig, _) in dg_lst}
    nat_dgs = nat_refs_by_dg.get(name, set())
    existing_sig = sh_svc_sig.get(name)

    if len(sigs) == 1:
        sig = next(iter(sigs))
        emit = next(e for (_, s, e) in dg_lst if s == sig)
        if existing_sig != sig:
            shared_emit_svc[name] = emit
        for (dg, _, _) in dg_lst:
            rule_rename[(dg, name)] = name
    else:
        canon_dg = next(iter(nat_dgs)) if nat_dgs else dg_lst[0][0]
        canon_sig, canon_emit = next((s, e) for (dg, s, e) in dg_lst if dg == canon_dg)
        if existing_sig != canon_sig:
            shared_emit_svc[name] = canon_emit
        taken = {name}
        alt_for_sig = {}
        for (dg, s, e) in dg_lst:
            if s == canon_sig:
                rule_rename[(dg, name)] = name
            else:
                if s not in alt_for_sig:
                    alt = alloc_alt(f"{name}_obj", taken); taken.add(alt)
                    alt_for_sig[s] = (alt, e)
                    shared_emit_svc[alt] = e
                rule_rename[(dg, name)] = alt_for_sig[s][0]

# ----- Service groups -----
for name, lst in svcgrp_vars.items():
    dg_lst = [(dg, members) for (dg, members) in lst if dg != "shared"]
    if not dg_lst: continue
    nat_dgs = nat_refs_by_dg.get(name, set())
    sets = [frozenset(m) for (_, m) in dg_lst]
    all_equal = len(set(sets)) == 1

    if all_equal:
        members = list(OrderedDict.fromkeys(dg_lst[0][1]))
        # include any existing shared members first
        for m in list(sh_svcgrp_members.get(name, []))[::-1]:
            if m not in members:
                members.insert(0, m)
        shared_emit_svcg[name] = members
        for (dg, _) in dg_lst:
            rule_rename[(dg, name)] = name
    else:
        if nat_dgs:
            canon_dg = next(iter(nat_dgs))
            canon_members = next((m for (dg, m) in dg_lst if dg == canon_dg), dg_lst[0][1])
            shared_emit_svcg[name] = list(OrderedDict.fromkeys(canon_members))
            taken = {name}
            alt_for = {}
            for (dg, members) in dg_lst:
                key = ag_members_signature(members)
                if key == ag_members_signature(canon_members):
                    rule_rename[(dg, name)] = name
                else:
                    if key not in alt_for:
                        alt = alloc_alt(f"{name}_obj", taken); taken.add(alt)
                        alt_for[key] = alt
                        shared_emit_svcg[alt] = list(OrderedDict.fromkeys(members))
                    rule_rename[(dg, name)] = alt_for[key]
        else:
            # union
            ordered = OrderedDict()
            for _, members in dg_lst:
                for m in members: ordered[m] = True
            for m in list(sh_svcgrp_members.get(name, []))[::-1]:
                ordered.move_to_end(m, last=False)
            shared_emit_svcg[name] = list(ordered.keys())
            for (dg, _) in dg_lst:
                rule_rename[(dg, name)] = name

# ---------------- Rewrite: insert shared after first original, drop DG originals ----------------
emitted_for_base = set()  # names we've emitted for (to avoid re-emitting alts per base)
alt_emitted = set()       # (kind, alt_name) pairs to dedup emissions
out_lines = []
i = 0

def emit_shared_for_name(base_name):
    """Emit all shared items related to a base name (canonical + *_obj variants). Returns list of lines."""
    new = []

    # Addresses
    if base_name in shared_emit_addr or any(k.startswith(base_name + "_obj") for k in shared_emit_addr):
        if base_name in shared_emit_addr:
            new.append(f"set shared address {base_name} {shared_emit_addr[base_name]}")
        for alt, tail in shared_emit_addr.items():
            if alt != base_name and alt.startswith(base_name + "_obj") and ("addr", alt) not in alt_emitted:
                new.append(f"set shared address {alt} {tail}"); alt_emitted.add(("addr", alt))

    # Address-groups (static)
    if base_name in shared_emit_ag_s or any(k.startswith(base_name + "_obj") for k in shared_emit_ag_s):
        if base_name in shared_emit_ag_s:
            for m in shared_emit_ag_s[base_name]:
                if m not in sh_ag_static_members.get(base_name, set()):
                    new.append(f"set shared address-group {base_name} static {m}")
        for alt, members in shared_emit_ag_s.items():
            if alt != base_name and alt.startswith(base_name + "_obj") and ("ags", alt) not in alt_emitted:
                for m in members:
                    if m not in sh_ag_static_members.get(alt, set()):
                        new.append(f"set shared address-group {alt} static {m}")
                alt_emitted.add(("ags", alt))

    # Address-groups (dynamic)
    if base_name in shared_emit_ag_d or any(k.startswith(base_name + "_obj") for k in shared_emit_ag_d):
        if base_name in shared_emit_ag_d:
            new.append(f"set shared address-group {base_name} dynamic filter {shared_emit_ag_d[base_name]}")
        for alt, filt in shared_emit_ag_d.items():
            if alt != base_name and alt.startswith(base_name + "_obj") and ("agd", alt) not in alt_emitted:
                new.append(f"set shared address-group {alt} dynamic filter {filt}")
                alt_emitted.add(("agd", alt))

    # EDLs
    if base_name in shared_emit_edl or any(k.startswith(base_name + "_obj") for k in shared_emit_edl):
        if base_name in shared_emit_edl:
            new.append(f"set shared external-list {base_name} {shared_emit_edl[base_name]}")
        for alt, t in shared_emit_edl.items():
            if alt != base_name and alt.startswith(base_name + "_obj") and ("edl", alt) not in alt_emitted:
                new.append(f"set shared external-list {alt} {t}")
                alt_emitted.add(("edl", alt))

    # Services
    if base_name in shared_emit_svc or any(k.startswith(base_name + "_obj") for k in shared_emit_svc):
        if base_name in shared_emit_svc:
            new.append(f"set shared service {base_name} {shared_emit_svc[base_name]}")
        for alt, tail in shared_emit_svc.items():
            if alt != base_name and alt.startswith(base_name + "_obj") and ("svc", alt) not in alt_emitted:
                new.append(f"set shared service {alt} {tail}")
                alt_emitted.add(("svc", alt))

    # Service-groups
    if base_name in shared_emit_svcg or any(k.startswith(base_name + "_obj") for k in shared_emit_svcg):
        if base_name in shared_emit_svcg:
            members = shared_emit_svcg[base_name]
            # Emit full list (idempotency handled by identical lines check in reruns via presence)
            new.append(f"set shared service-group {base_name} members [ {' '.join(members)} ]")
        for alt, members in shared_emit_svcg.items():
            if alt != base_name and alt.startswith(base_name + "_obj") and ("svcg", alt) not in alt_emitted:
                new.append(f"set shared service-group {alt} members [ {' '.join(members)} ]")
                alt_emitted.add(("svcg", alt))

    return new

def is_dg_object_line(ln: str) -> str:
    """Returns base object name if line is a DG object; else ''."""
    for rx in (RE_DG_ADDR, RE_DG_AG_STATIC, RE_DG_AG_DYNAMIC, RE_DG_EDL, RE_DG_SERVICE, RE_DG_SVC_GROUP):
        m = rx.match(ln)
        if m:
            # DG, name, ...
            return m.group(2)
    return ""

while i < len(lines):
    ln = lines[i]

    # If a DG object line, emit shared once and skip DG lines for that object (we skip one-by-one; simpler & safe)
    base = is_dg_object_line(ln)
    if base:
        if base not in emitted_for_base:
            out_lines.extend(emit_shared_for_name(base))
            emitted_for_base.add(base)
        # Skip this DG object line (do not copy)
        i += 1
        continue

    # Rules: rewrite per (dg,name)->new_name
    msec = RE_RULE_SECURITY.match(ln)
    mnat = RE_RULE_NAT.match(ln)
    if msec or mnat:
        dg = (msec or mnat).group(1)
        toks = tokenize(ln)
        if dg is not None:
            for j, t in enumerate(toks):
                new_t = rule_rename.get((dg, t))
                if new_t and new_t != t:
                    toks[j] = new_t
            out_lines.append(" ".join(toks))
        else:
            # shared rulebase: keep as-is (or switch to canonical-only mapping if you prefer)
            out_lines.append(ln)
        i += 1
        continue

    # Pass through non-object, non-rule lines
    out_lines.append(ln)
    i += 1

# ---------------- Write back & log ----------------
with open(SET_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(out_lines).rstrip() + "\n")

def count_emitted(prefix):
    return sum(1 for l in out_lines if l.startswith(prefix))

addr_cnt   = count_emitted("set shared address ")
ag_s_lines = count_emitted("set shared address-group ")
ag_d_cnt   = sum(1 for l in out_lines if l.startswith("set shared address-group ") and " dynamic filter " in l)
# For static AGs we can’t easily separate line count from group count; summarize by unique names:
ag_s_names = set()
for l in out_lines:
    m = RE_SH_AG_STATIC.match(l)
    if m: ag_s_names.add(m.group(1))
ag_s_cnt = len(ag_s_names)

edl_cnt   = count_emitted("set shared external-list ")
svc_cnt   = count_emitted("set shared service ")
# service-group:
svcg_names = set()
for l in out_lines:
    m = RE_SH_SVC_GROUP.match(l)
    if m: svcg_names.add(m.group(1))
svcg_cnt = len(svcg_names)

with open(LOG_FILE, "w", encoding="utf-8") as log:
    log.write("=== Migration Summary ===\n")
    log.write(f"Shared address objects (lines): {addr_cnt}\n")
    log.write(f"Shared address-groups (static, unique names): {ag_s_cnt}\n")
    log.write(f"Shared address-groups (dynamic): {ag_d_cnt}\n")
    log.write(f"Shared EDLs: {edl_cnt}\n")
    log.write(f"Shared service objects (lines): {svc_cnt}\n")
    log.write(f"Shared service-groups (unique names): {svcg_cnt}\n")
    log.write("\n--- Rule Renames (per DG) ---\n")
    for (dg, name), new_name in sorted(rule_rename.items()):
        if new_name != name:
            log.write(f"{dg}: {name} -> {new_name}\n")

print("✅ Migration complete.")
print(f"   - Shared address objects (lines): {addr_cnt}")
print(f"   - Shared address-groups: {ag_s_cnt} static, {ag_d_cnt} dynamic")
print(f"   - Shared EDLs: {edl_cnt}")
print(f"   - Shared service objects (lines): {svc_cnt}")
print(f"   - Shared service-groups: {svcg_cnt}")
print(f"   - Log written to {LOG_FILE}")
