#!/usr/bin/env python3
"""
panorama_xml_dedupe_addresses_auto.py

Deduplicate Panorama XML address objects by identical value, automatically choose
the preferred keeper, rewrite references, clean up duplicate member entries,
validate rule member arrays, and optionally repair empty source/destination
arrays by restoring the original members from a pre-change snapshot.

Keeper preference order:
1. "<value>_<hostname>"         e.g. 10.1.1.1_mysystemhostname.dev.domain
2. "SVB_<value>"                e.g. SVB_10.1.1.1
3. everything else
4. lowest preference: names starting with svb_host_

Fallback tie-breakers:
- shared preferred over device-group
- more references preferred
- shorter name preferred
- alphabetical

Supports duplicate detection for address objects of type:
- ip-netmask
- ip-range
- fqdn

Reference updates:
- address-group static members
- security rule source/destination members
- NAT rule source/destination members
- NAT singleton leaf elements whose text exactly matches an address object name
  and whose tag is one of: member, translated-address, ip, address

Optional outputs:
- duplicate/reference CSV
- decision CSV
- validation CSV
- repair CSV
"""

import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set


@dataclass
class AddressObject:
    name: str
    obj_type: str
    value: str
    scope_type: str          # shared or device-group
    scope_name: str
    entry_elem: ET.Element
    parent_elem: ET.Element

    def scope_label(self) -> str:
        return "shared" if self.scope_type == "shared" else f"device-group:{self.scope_name}"

    def key(self) -> Tuple[str, str]:
        return (self.obj_type, self.value)


@dataclass
class Reference:
    ref_type: str            # address-group, security-rule, nat-rule
    scope_type: str
    scope_name: str
    container_name: str
    field_name: str
    elem: ET.Element
    xml_path: str

    def scope_label(self) -> str:
        return "shared" if self.scope_type == "shared" else f"device-group:{self.scope_name}"


def indent(elem: ET.Element, level: int = 0) -> None:
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        last = None
        for child in elem:
            indent(child, level + 1)
            last = child
        if last is not None and (not last.tail or not last.tail.strip()):
            last.tail = i
    if level and (not elem.tail or not elem.tail.strip()):
        elem.tail = i


def build_parent_map(root: ET.Element) -> Dict[ET.Element, ET.Element]:
    return {child: parent for parent in root.iter() for child in parent}


def entry_name(elem: ET.Element) -> str:
    return elem.get("name", "<unnamed>")


def get_xml_path(elem: ET.Element, parent_map: Dict[ET.Element, ET.Element]) -> str:
    parts = []
    cur = elem
    while cur is not None:
        name_attr = cur.get("name")
        if name_attr is not None:
            parts.append(f"{cur.tag}[@name='{name_attr}']")
        else:
            parts.append(cur.tag)
        cur = parent_map.get(cur)
    return "/" + "/".join(reversed(parts))


def extract_address_value(addr_entry: ET.Element) -> Optional[Tuple[str, str]]:
    for tag in ("ip-netmask", "ip-range", "fqdn"):
        child = addr_entry.find(tag)
        if child is not None and child.text and child.text.strip():
            return tag, child.text.strip()
    return None


def find_shared_address_objects(root: ET.Element) -> List[AddressObject]:
    objs: List[AddressObject] = []
    for shared in root.findall(".//shared"):
        addr_parent = shared.find("address")
        if addr_parent is None:
            continue
        for entry in addr_parent.findall("entry"):
            result = extract_address_value(entry)
            if not result:
                continue
            obj_type, value = result
            objs.append(AddressObject(
                name=entry_name(entry),
                obj_type=obj_type,
                value=value,
                scope_type="shared",
                scope_name="shared",
                entry_elem=entry,
                parent_elem=addr_parent,
            ))
    return objs


def find_dg_address_objects(root: ET.Element) -> List[AddressObject]:
    objs: List[AddressObject] = []
    for dg in root.findall(".//devices/entry/device-group/entry"):
        dg_name = entry_name(dg)
        addr_parent = dg.find("address")
        if addr_parent is None:
            continue
        for entry in addr_parent.findall("entry"):
            result = extract_address_value(entry)
            if not result:
                continue
            obj_type, value = result
            objs.append(AddressObject(
                name=entry_name(entry),
                obj_type=obj_type,
                value=value,
                scope_type="device-group",
                scope_name=dg_name,
                entry_elem=entry,
                parent_elem=addr_parent,
            ))
    return objs


def collect_address_objects(root: ET.Element) -> List[AddressObject]:
    return find_shared_address_objects(root) + find_dg_address_objects(root)


def get_scope_from_ancestor(elem: ET.Element, parent_map: Dict[ET.Element, ET.Element]) -> Tuple[str, str]:
    cur = elem
    while cur is not None:
        if cur.tag == "shared":
            return ("shared", "shared")
        if cur.tag == "entry":
            parent = parent_map.get(cur)
            if parent is not None and parent.tag == "device-group":
                return ("device-group", entry_name(cur))
        cur = parent_map.get(cur)
    return ("unknown", "unknown")


def collect_address_group_references(
    root: ET.Element,
    parent_map: Dict[ET.Element, ET.Element]
) -> Dict[str, List[Reference]]:
    refs: Dict[str, List[Reference]] = defaultdict(list)

    for ag_entry in root.findall(".//address-group/entry"):
        ag_name = entry_name(ag_entry)
        scope_type, scope_name = get_scope_from_ancestor(ag_entry, parent_map)
        static = ag_entry.find("static")
        if static is None:
            continue

        for member in static.findall("member"):
            if member.text and member.text.strip():
                refs[member.text.strip()].append(Reference(
                    ref_type="address-group",
                    scope_type=scope_type,
                    scope_name=scope_name,
                    container_name=ag_name,
                    field_name="member",
                    elem=member,
                    xml_path=get_xml_path(member, parent_map),
                ))
    return refs


def collect_security_rule_references(
    root: ET.Element,
    parent_map: Dict[ET.Element, ET.Element]
) -> Dict[str, List[Reference]]:
    refs: Dict[str, List[Reference]] = defaultdict(list)

    for path in (
        ".//pre-rulebase/security/rules/entry",
        ".//post-rulebase/security/rules/entry",
        ".//rulebase/security/rules/entry",
    ):
        for rule_entry in root.findall(path):
            rule_name = entry_name(rule_entry)
            scope_type, scope_name = get_scope_from_ancestor(rule_entry, parent_map)

            for field in ("source", "destination"):
                field_elem = rule_entry.find(field)
                if field_elem is None:
                    continue
                for member in field_elem.findall("member"):
                    if member.text and member.text.strip():
                        refs[member.text.strip()].append(Reference(
                            ref_type="security-rule",
                            scope_type=scope_type,
                            scope_name=scope_name,
                            container_name=rule_name,
                            field_name=field,
                            elem=member,
                            xml_path=get_xml_path(member, parent_map),
                        ))
    return refs


def nat_reference_candidate_tags() -> Set[str]:
    return {"member", "translated-address", "ip", "address"}


def collect_nat_rule_references(
    root: ET.Element,
    parent_map: Dict[ET.Element, ET.Element],
    known_object_names: Set[str]
) -> Dict[str, List[Reference]]:
    refs: Dict[str, List[Reference]] = defaultdict(list)

    nat_rule_paths = (
        ".//pre-rulebase/nat/rules/entry",
        ".//post-rulebase/nat/rules/entry",
        ".//rulebase/nat/rules/entry",
    )

    for path in nat_rule_paths:
        for rule_entry in root.findall(path):
            rule_name = entry_name(rule_entry)
            scope_type, scope_name = get_scope_from_ancestor(rule_entry, parent_map)

            for field in ("source", "destination"):
                field_elem = rule_entry.find(field)
                if field_elem is None:
                    continue
                for member in field_elem.findall("member"):
                    txt = (member.text or "").strip()
                    if txt in known_object_names:
                        refs[txt].append(Reference(
                            ref_type="nat-rule",
                            scope_type=scope_type,
                            scope_name=scope_name,
                            container_name=rule_name,
                            field_name=field,
                            elem=member,
                            xml_path=get_xml_path(member, parent_map),
                        ))

            for elem in rule_entry.iter():
                if elem is rule_entry:
                    continue
                if len(list(elem)) > 0:
                    continue
                txt = (elem.text or "").strip()
                if not txt:
                    continue
                if txt not in known_object_names:
                    continue
                if elem.tag not in nat_reference_candidate_tags():
                    continue

                refs[txt].append(Reference(
                    ref_type="nat-rule",
                    scope_type=scope_type,
                    scope_name=scope_name,
                    container_name=rule_name,
                    field_name=elem.tag,
                    elem=elem,
                    xml_path=get_xml_path(elem, parent_map),
                ))

    return refs


def merge_reference_maps(*maps: Dict[str, List[Reference]]) -> Dict[str, List[Reference]]:
    merged: Dict[str, List[Reference]] = defaultdict(list)
    for m in maps:
        for k, v in m.items():
            merged[k].extend(v)
    return merged


def can_replace_reference_with_target(ref: Reference, target_obj: AddressObject) -> bool:
    if target_obj.scope_type == "shared":
        return True
    if ref.scope_type == "device-group" and target_obj.scope_type == "device-group":
        return ref.scope_name == target_obj.scope_name
    if ref.scope_type == "shared" and target_obj.scope_type == "device-group":
        return False
    return False


def is_ip_value_name(name: str, value: str) -> bool:
    return name.startswith(value + "_") and len(name) > len(value) + 1


def is_svb_exact_name(name: str, value: str) -> bool:
    return name == f"SVB_{value}"


def is_svb_host_name(name: str) -> bool:
    return name.startswith("svb_host_")


def name_preference_rank(obj: AddressObject) -> int:
    if is_ip_value_name(obj.name, obj.value):
        return 0
    if is_svb_exact_name(obj.name, obj.value):
        return 1
    if is_svb_host_name(obj.name):
        return 3
    return 2


def scope_rank(obj: AddressObject) -> int:
    return 0 if obj.scope_type == "shared" else 1


def choose_keeper_auto(
    dup_group: List[AddressObject],
    refs_by_name: Dict[str, List[Reference]]
) -> AddressObject:
    def sort_key(obj: AddressObject):
        ref_count = len(refs_by_name.get(obj.name, []))
        return (
            name_preference_rank(obj),
            scope_rank(obj),
            -ref_count,
            len(obj.name),
            obj.name.lower(),
        )
    return sorted(dup_group, key=sort_key)[0]


def describe_keeper_reason(obj: AddressObject, refs_by_name: Dict[str, List[Reference]]) -> str:
    rank = name_preference_rank(obj)
    ref_count = len(refs_by_name.get(obj.name, []))
    if rank == 0:
        return f"preferred <value>_<hostname>; refs={ref_count}; scope={obj.scope_label()}"
    if rank == 1:
        return f"preferred SVB_<value>; refs={ref_count}; scope={obj.scope_label()}"
    if rank == 3:
        return f"svb_host_ object kept by tie-breakers; refs={ref_count}; scope={obj.scope_label()}"
    return f"fallback selection; refs={ref_count}; scope={obj.scope_label()}"


def write_csv_report(
    csv_path: str,
    dup_groups: List[List[AddressObject]],
    refs_by_name: Dict[str, List[Reference]]
) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "duplicate_group_id",
            "object_type",
            "object_value",
            "object_name",
            "object_scope",
            "object_scope_type",
            "object_scope_name",
            "object_reference_count",
            "reference_type",
            "reference_scope",
            "reference_scope_type",
            "reference_scope_name",
            "reference_container_name",
            "reference_field_name",
            "reference_xml_path",
        ])

        group_id = 1
        for group in sorted(dup_groups, key=lambda g: (g[0].obj_type, g[0].value)):
            for obj in sorted(group, key=lambda x: (x.scope_type, x.scope_name, x.name)):
                refs = refs_by_name.get(obj.name, [])
                if refs:
                    for ref in refs:
                        writer.writerow([
                            group_id,
                            group[0].obj_type,
                            group[0].value,
                            obj.name,
                            obj.scope_label(),
                            obj.scope_type,
                            obj.scope_name,
                            len(refs),
                            ref.ref_type,
                            ref.scope_label(),
                            ref.scope_type,
                            ref.scope_name,
                            ref.container_name,
                            ref.field_name,
                            ref.xml_path,
                        ])
                else:
                    writer.writerow([
                        group_id,
                        group[0].obj_type,
                        group[0].value,
                        obj.name,
                        obj.scope_label(),
                        obj.scope_type,
                        obj.scope_name,
                        0,
                        "", "", "", "", "", "", ""
                    ])
            group_id += 1


def write_decision_csv(csv_path: str, decisions: List[Dict[str, str]]) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "object_type",
            "object_value",
            "kept_name",
            "kept_scope",
            "kept_reason",
            "replaced_name",
            "replaced_scope",
            "replaced_refs_rewritten",
            "replaced_refs_skipped",
            "dedupe_members_removed",
            "deleted",
        ])
        writer.writeheader()
        for row in decisions:
            writer.writerow(row)


def replace_refs(old_name: str, target_obj: AddressObject, refs: List[Reference]) -> Tuple[int, int]:
    replaced = 0
    skipped = 0

    for ref in refs:
        if can_replace_reference_with_target(ref, target_obj):
            if (ref.elem.text or "").strip() == old_name:
                ref.elem.text = target_obj.name
                replaced += 1
            else:
                skipped += 1
        else:
            skipped += 1

    return replaced, skipped


def dedupe_member_children(parent_elem: Optional[ET.Element]) -> int:
    if parent_elem is None:
        return 0

    seen = set()
    removed = 0
    to_remove = []

    for child in list(parent_elem):
        if child.tag != "member":
            continue
        text = (child.text or "").strip()
        if text in seen:
            to_remove.append(child)
        else:
            seen.add(text)

    for child in to_remove:
        parent_elem.remove(child)
        removed += 1

    return removed


def cleanup_duplicate_members(root: ET.Element) -> int:
    removed = 0

    for ag_entry in root.findall(".//address-group/entry"):
        static = ag_entry.find("static")
        if static is not None:
            removed += dedupe_member_children(static)

    for path in (
        ".//pre-rulebase/security/rules/entry",
        ".//post-rulebase/security/rules/entry",
        ".//rulebase/security/rules/entry",
        ".//pre-rulebase/nat/rules/entry",
        ".//post-rulebase/nat/rules/entry",
        ".//rulebase/nat/rules/entry",
    ):
        for rule_entry in root.findall(path):
            for field in ("source", "destination"):
                field_elem = rule_entry.find(field)
                if field_elem is not None:
                    removed += dedupe_member_children(field_elem)

    return removed


def delete_object_if_safe(obj: AddressObject, refs_by_name: Dict[str, List[Reference]]) -> bool:
    remaining_refs = refs_by_name.get(obj.name, [])
    if remaining_refs:
        return False
    try:
        obj.parent_elem.remove(obj.entry_elem)
        return True
    except Exception:
        return False


def rebuild_refs(
    root: ET.Element,
    parent_map: Dict[ET.Element, ET.Element],
    known_object_names: Set[str]
) -> Dict[str, List[Reference]]:
    return merge_reference_maps(
        collect_address_group_references(root, parent_map),
        collect_security_rule_references(root, parent_map),
        collect_nat_rule_references(root, parent_map, known_object_names),
    )


def collect_address_group_names(root: ET.Element) -> List[Tuple[str, str, str]]:
    groups = []

    for shared in root.findall(".//shared"):
        ag_parent = shared.find("address-group")
        if ag_parent is not None:
            for entry in ag_parent.findall("entry"):
                groups.append(("shared", "shared", entry_name(entry)))

    for dg in root.findall(".//devices/entry/device-group/entry"):
        dg_name = entry_name(dg)
        ag_parent = dg.find("address-group")
        if ag_parent is not None:
            for entry in ag_parent.findall("entry"):
                groups.append(("device-group", dg_name, entry_name(entry)))

    return groups


def build_visible_name_sets(root: ET.Element) -> Dict[Tuple[str, str], Set[str]]:
    shared_names: Set[str] = set()

    for shared in root.findall(".//shared"):
        addr_parent = shared.find("address")
        if addr_parent is not None:
            for entry in addr_parent.findall("entry"):
                shared_names.add(entry_name(entry))

    for shared in root.findall(".//shared"):
        ag_parent = shared.find("address-group")
        if ag_parent is not None:
            for entry in ag_parent.findall("entry"):
                shared_names.add(entry_name(entry))

    visible: Dict[Tuple[str, str], Set[str]] = {
        ("shared", "shared"): set(shared_names)
    }

    for dg in root.findall(".//devices/entry/device-group/entry"):
        dg_name = entry_name(dg)
        names = set(shared_names)

        addr_parent = dg.find("address")
        if addr_parent is not None:
            for entry in addr_parent.findall("entry"):
                names.add(entry_name(entry))

        ag_parent = dg.find("address-group")
        if ag_parent is not None:
            for entry in ag_parent.findall("entry"):
                names.add(entry_name(entry))

        visible[("device-group", dg_name)] = names

    return visible


def extract_member_values(field_elem: Optional[ET.Element]) -> List[str]:
    if field_elem is None:
        return []
    values = []
    for member in field_elem.findall("member"):
        txt = (member.text or "").strip()
        if txt:
            values.append(txt)
    return values


def validate_member_field(
    field_elem: Optional[ET.Element],
    allowed_names: Set[str],
    allow_any: bool = True,
) -> Tuple[bool, bool, List[str]]:
    values = extract_member_values(field_elem)

    if not values:
        return True, False, []

    if allow_any and "any" in values:
        return False, False, []

    missing = [v for v in values if v not in allowed_names]
    return False, bool(missing), missing


def validate_final_config(
    root: ET.Element,
    parent_map: Dict[ET.Element, ET.Element]
) -> List[Dict[str, str]]:
    issues: List[Dict[str, str]] = []
    visible_names = build_visible_name_sets(root)

    rule_specs = [
        ("security-rule", ".//pre-rulebase/security/rules/entry"),
        ("security-rule", ".//post-rulebase/security/rules/entry"),
        ("security-rule", ".//rulebase/security/rules/entry"),
        ("nat-rule", ".//pre-rulebase/nat/rules/entry"),
        ("nat-rule", ".//post-rulebase/nat/rules/entry"),
        ("nat-rule", ".//rulebase/nat/rules/entry"),
    ]

    for ref_type, path in rule_specs:
        for rule_entry in root.findall(path):
            rule_name = entry_name(rule_entry)
            scope_type, scope_name = get_scope_from_ancestor(rule_entry, parent_map)
            allowed_names = visible_names.get((scope_type, scope_name), set())

            for field_name in ("source", "destination"):
                field_elem = rule_entry.find(field_name)
                is_empty, has_missing, missing_names = validate_member_field(
                    field_elem=field_elem,
                    allowed_names=allowed_names,
                    allow_any=True,
                )

                if is_empty:
                    issues.append({
                        "issue_type": "empty-member-array",
                        "ref_type": ref_type,
                        "scope_type": scope_type,
                        "scope_name": scope_name,
                        "scope_label": "shared" if scope_type == "shared" else f"device-group:{scope_name}",
                        "container_name": rule_name,
                        "field_name": field_name,
                        "xml_path": get_xml_path(field_elem if field_elem is not None else rule_entry, parent_map),
                        "details": f"{field_name} has no members",
                    })

                if has_missing:
                    issues.append({
                        "issue_type": "missing-reference",
                        "ref_type": ref_type,
                        "scope_type": scope_type,
                        "scope_name": scope_name,
                        "scope_label": "shared" if scope_type == "shared" else f"device-group:{scope_name}",
                        "container_name": rule_name,
                        "field_name": field_name,
                        "xml_path": get_xml_path(field_elem if field_elem is not None else rule_entry, parent_map),
                        "details": ", ".join(missing_names),
                    })

    return issues


def write_validation_csv(csv_path: str, issues: List[Dict[str, str]]) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "issue_type",
                "ref_type",
                "scope_type",
                "scope_name",
                "scope_label",
                "container_name",
                "field_name",
                "xml_path",
                "details",
            ],
        )
        writer.writeheader()
        for row in issues:
            writer.writerow(row)


def get_rule_key(
    rule_entry: ET.Element,
    parent_map: Dict[ET.Element, ET.Element],
    ref_type: str
) -> Tuple[str, str, str, str]:
    scope_type, scope_name = get_scope_from_ancestor(rule_entry, parent_map)
    return (ref_type, scope_type, scope_name, entry_name(rule_entry))


def snapshot_rule_member_fields(
    root: ET.Element,
    parent_map: Dict[ET.Element, ET.Element]
) -> Dict[Tuple[str, str, str, str, str], List[str]]:
    snapshots: Dict[Tuple[str, str, str, str, str], List[str]] = {}

    rule_specs = [
        ("security-rule", ".//pre-rulebase/security/rules/entry"),
        ("security-rule", ".//post-rulebase/security/rules/entry"),
        ("security-rule", ".//rulebase/security/rules/entry"),
        ("nat-rule", ".//pre-rulebase/nat/rules/entry"),
        ("nat-rule", ".//post-rulebase/nat/rules/entry"),
        ("nat-rule", ".//rulebase/nat/rules/entry"),
    ]

    for ref_type, path in rule_specs:
        for rule_entry in root.findall(path):
            rule_key = get_rule_key(rule_entry, parent_map, ref_type)
            for field_name in ("source", "destination"):
                field_elem = rule_entry.find(field_name)
                values = extract_member_values(field_elem)
                snapshots[rule_key + (field_name,)] = list(values)

    return snapshots


def find_rule_by_key(
    root: ET.Element,
    parent_map: Dict[ET.Element, ET.Element],
    ref_type: str,
    scope_type: str,
    scope_name: str,
    rule_name: str,
) -> Optional[ET.Element]:
    if ref_type == "security-rule":
        rule_specs = [
            ".//pre-rulebase/security/rules/entry",
            ".//post-rulebase/security/rules/entry",
            ".//rulebase/security/rules/entry",
        ]
    elif ref_type == "nat-rule":
        rule_specs = [
            ".//pre-rulebase/nat/rules/entry",
            ".//post-rulebase/nat/rules/entry",
            ".//rulebase/nat/rules/entry",
        ]
    else:
        rule_specs = []

    for path in rule_specs:
        for rule_entry in root.findall(path):
            if entry_name(rule_entry) != rule_name:
                continue
            s_type, s_name = get_scope_from_ancestor(rule_entry, parent_map)
            if s_type == scope_type and s_name == scope_name:
                return rule_entry
    return None


def ensure_field_elem(rule_entry: ET.Element, field_name: str) -> ET.Element:
    field_elem = rule_entry.find(field_name)
    if field_elem is None:
        field_elem = ET.SubElement(rule_entry, field_name)
    return field_elem


def replace_member_list(field_elem: ET.Element, values: List[str]) -> None:
    for child in list(field_elem):
        field_elem.remove(child)

    field_elem.text = None

    for value in values:
        member = ET.SubElement(field_elem, "member")
        member.text = value


def repair_empty_rule_fields(
    root: ET.Element,
    parent_map: Dict[ET.Element, ET.Element],
    snapshots: Dict[Tuple[str, str, str, str, str], List[str]],
    validation_issues: List[Dict[str, str]],
) -> List[Dict[str, str]]:
    repairs: List[Dict[str, str]] = []

    for issue in validation_issues:
        if issue.get("issue_type") != "empty-member-array":
            continue

        ref_type = issue["ref_type"]
        scope_type = issue["scope_type"]
        scope_name = issue["scope_name"]
        rule_name = issue["container_name"]
        field_name = issue["field_name"]

        snapshot_key = (ref_type, scope_type, scope_name, rule_name, field_name)
        original_values = snapshots.get(snapshot_key, [])

        if not original_values:
            repairs.append({
                "repair_type": "restore-failed-no-snapshot",
                "ref_type": ref_type,
                "scope_type": scope_type,
                "scope_name": scope_name,
                "scope_label": issue["scope_label"],
                "container_name": rule_name,
                "field_name": field_name,
                "restored_values": "",
            })
            continue

        rule_entry = find_rule_by_key(
            root=root,
            parent_map=parent_map,
            ref_type=ref_type,
            scope_type=scope_type,
            scope_name=scope_name,
            rule_name=rule_name,
        )

        if rule_entry is None:
            repairs.append({
                "repair_type": "restore-failed-rule-not-found",
                "ref_type": ref_type,
                "scope_type": scope_type,
                "scope_name": scope_name,
                "scope_label": issue["scope_label"],
                "container_name": rule_name,
                "field_name": field_name,
                "restored_values": ",".join(original_values),
            })
            continue

        field_elem = ensure_field_elem(rule_entry, field_name)
        replace_member_list(field_elem, original_values)

        repairs.append({
            "repair_type": "restored-original-members",
            "ref_type": ref_type,
            "scope_type": scope_type,
            "scope_name": scope_name,
            "scope_label": issue["scope_label"],
            "container_name": rule_name,
            "field_name": field_name,
            "restored_values": ",".join(original_values),
        })

    return repairs


def write_repair_csv(csv_path: str, repairs: List[Dict[str, str]]) -> None:
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "repair_type",
                "ref_type",
                "scope_type",
                "scope_name",
                "scope_label",
                "container_name",
                "field_name",
                "restored_values",
            ],
        )
        writer.writeheader()
        for row in repairs:
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Automatically deduplicate Panorama XML address objects.")
    parser.add_argument("-i", "--input", required=True, help="Input Panorama XML")
    parser.add_argument("-o", "--output", required=True, help="Output Panorama XML")
    parser.add_argument("--csv-report", help="Write duplicate/reference CSV")
    parser.add_argument("--decision-csv", help="Write replacement decisions CSV")
    parser.add_argument("--validation-csv", help="Write final validation issues to this CSV file")
    parser.add_argument("--repair-csv", help="Write repair actions to this CSV file")
    parser.add_argument("--delete-replaced", action="store_true", help="Delete replaced objects if no refs remain")
    parser.add_argument("--fail-on-validation", action="store_true", help="Exit non-zero if validation finds problems")
    parser.add_argument("--auto-repair-empty-arrays", action="store_true", help="Restore original source/destination members if a rule side becomes empty")
    args = parser.parse_args()

    try:
        tree = ET.parse(args.input)
    except Exception as e:
        print(f"ERROR: failed to parse XML: {e}", file=sys.stderr)
        return 1

    root = tree.getroot()
    parent_map = build_parent_map(root)

    original_rule_snapshots = snapshot_rule_member_fields(root, parent_map)

    objects = collect_address_objects(root)
    if not objects:
        print("No address objects found.")
        return 0

    known_object_names = {obj.name for obj in objects}
    refs_by_name = rebuild_refs(root, parent_map, known_object_names)

    by_value: Dict[Tuple[str, str], List[AddressObject]] = defaultdict(list)
    for obj in objects:
        by_value[obj.key()].append(obj)

    dup_groups = [group for group in by_value.values() if len(group) > 1]

    if args.csv_report:
        write_csv_report(args.csv_report, dup_groups, refs_by_name)
        print(f"Wrote CSV report: {args.csv_report}")

    if not dup_groups:
        parent_map = build_parent_map(root)
        validation_issues = validate_final_config(root, parent_map)

        repairs: List[Dict[str, str]] = []
        if args.auto_repair_empty_arrays and validation_issues:
            repairs = repair_empty_rule_fields(
                root=root,
                parent_map=parent_map,
                snapshots=original_rule_snapshots,
                validation_issues=validation_issues,
            )
            cleanup_duplicate_members(root)
            parent_map = build_parent_map(root)
            validation_issues = validate_final_config(root, parent_map)

        if args.validation_csv:
            write_validation_csv(args.validation_csv, validation_issues)
            print(f"Wrote validation CSV: {args.validation_csv}")

        if args.repair_csv and repairs:
            write_repair_csv(args.repair_csv, repairs)
            print(f"Wrote repair CSV: {args.repair_csv}")

        if args.fail_on_validation and validation_issues:
            print("ERROR: validation failed; output XML not written.", file=sys.stderr)
            return 2

        indent(root)
        tree.write(args.output, encoding="utf-8", xml_declaration=True)
        print("No duplicate address objects found by value.")
        print(f"Validation issues: {len(validation_issues)}")
        print(f"Wrote output: {args.output}")
        return 0

    total_replaced = 0
    total_skipped = 0
    total_deleted = 0
    total_member_dupes_removed = 0
    decisions: List[Dict[str, str]] = []

    print(f"Found {len(dup_groups)} duplicate value group(s).")

    for group in sorted(dup_groups, key=lambda g: (g[0].obj_type, g[0].value)):
        keeper = choose_keeper_auto(group, refs_by_name)
        reason = describe_keeper_reason(keeper, refs_by_name)

        print(f"\nDuplicate group: type={group[0].obj_type!r} value={group[0].value!r}")
        print(f"Keeping: {keeper.name} [{keeper.scope_label()}] -- {reason}")

        for obj in sorted(group, key=lambda x: (x is keeper, x.scope_type, x.scope_name, x.name)):
            print(f"  candidate: {obj.name} [{obj.scope_label()}] refs={len(refs_by_name.get(obj.name, []))}")

        for obj in group:
            if obj is keeper:
                continue

            old_refs = list(refs_by_name.get(obj.name, []))
            replaced, skipped = replace_refs(obj.name, keeper, old_refs)

            total_replaced += replaced
            total_skipped += skipped

            parent_map = build_parent_map(root)
            refs_by_name = rebuild_refs(root, parent_map, known_object_names | {keeper.name})

            removed_here = cleanup_duplicate_members(root)
            total_member_dupes_removed += removed_here

            parent_map = build_parent_map(root)
            refs_by_name = rebuild_refs(root, parent_map, known_object_names | {keeper.name})

            deleted = False
            if args.delete_replaced:
                deleted = delete_object_if_safe(obj, refs_by_name)
                if deleted:
                    total_deleted += 1

            decisions.append({
                "object_type": group[0].obj_type,
                "object_value": group[0].value,
                "kept_name": keeper.name,
                "kept_scope": keeper.scope_label(),
                "kept_reason": reason,
                "replaced_name": obj.name,
                "replaced_scope": obj.scope_label(),
                "replaced_refs_rewritten": str(replaced),
                "replaced_refs_skipped": str(skipped),
                "dedupe_members_removed": str(removed_here),
                "deleted": "yes" if deleted else "no",
            })

            print(
                f"  {obj.name} [{obj.scope_label()}] -> {keeper.name} "
                f"(replaced={replaced}, skipped={skipped}, "
                f"member_dupes_removed={removed_here}, deleted={'yes' if deleted else 'no'})"
            )

    final_removed = cleanup_duplicate_members(root)
    total_member_dupes_removed += final_removed

    parent_map = build_parent_map(root)
    validation_issues = validate_final_config(root, parent_map)

    repairs: List[Dict[str, str]] = []
    if args.auto_repair_empty_arrays and validation_issues:
        repairs = repair_empty_rule_fields(
            root=root,
            parent_map=parent_map,
            snapshots=original_rule_snapshots,
            validation_issues=validation_issues,
        )

        if repairs:
            print(f"\nApplied {len(repairs)} repair action(s).")
            for repair in repairs[:50]:
                print(
                    f"  [{repair['repair_type']}] "
                    f"{repair['ref_type']} {repair['scope_label']} "
                    f"{repair['container_name']} :: {repair['field_name']}"
                )
            if len(repairs) > 50:
                print(f"  ... {len(repairs) - 50} more")

        repaired_removed = cleanup_duplicate_members(root)
        total_member_dupes_removed += repaired_removed

        parent_map = build_parent_map(root)
        validation_issues = validate_final_config(root, parent_map)

    if args.validation_csv:
        write_validation_csv(args.validation_csv, validation_issues)
        print(f"Wrote validation CSV: {args.validation_csv}")

    if args.repair_csv and repairs:
        write_repair_csv(args.repair_csv, repairs)
        print(f"Wrote repair CSV: {args.repair_csv}")

    if validation_issues:
        print(f"\nValidation found {len(validation_issues)} issue(s):")
        for issue in validation_issues[:50]:
            print(
                f"  [{issue['issue_type']}] "
                f"{issue['ref_type']} {issue['scope_label']} "
                f"{issue['container_name']} :: {issue['field_name']} :: "
                f"{issue['details']}"
            )
        if len(validation_issues) > 50:
            print(f"  ... {len(validation_issues) - 50} more")

    if args.decision_csv:
        write_decision_csv(args.decision_csv, decisions)
        print(f"Wrote decision CSV: {args.decision_csv}")

    if args.fail_on_validation and validation_issues:
        print("\nERROR: validation failed; output XML not written.", file=sys.stderr)
        return 2

    indent(root)
    tree.write(args.output, encoding="utf-8", xml_declaration=True)

    print("\nDone.")
    print(f"Replaced references: {total_replaced}")
    print(f"Skipped replacements: {total_skipped}")
    print(f"Duplicate member entries removed: {total_member_dupes_removed}")
    print(f"Repairs applied: {len(repairs)}")
    print(f"Validation issues: {len(validation_issues)}")
    if args.delete_replaced:
        print(f"Deleted duplicate objects: {total_deleted}")
    print(f"Wrote output: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
