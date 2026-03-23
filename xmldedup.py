#!/usr/bin/env python3
"""
panorama_xml_dedupe_addresses.py

Parse a Panorama XML config export, find duplicate address objects with the same
value, find references in address-groups / security rules / NAT rules, and let
you choose which object to keep.

Also writes a CSV report of all duplicate groups and their references.

Supports:
- shared address objects
- device-group address objects
- duplicate detection by:
    * ip-netmask
    * ip-range
    * fqdn

References updated in:
- address-group static members
- security rules (source/destination)
- NAT rules (source/destination, translated-address fields when they reference objects)

Usage:
    python panorama_xml_dedupe_addresses.py -i panorama.xml -o panorama_deduped.xml
    python panorama_xml_dedupe_addresses.py -i panorama.xml -o panorama_deduped.xml --delete-replaced
    python panorama_xml_dedupe_addresses.py -i panorama.xml -o panorama_deduped.xml --csv-report duplicates_report.csv

Notes:
- This is for Panorama XML export, not "set" format.
- It writes a modified XML file; keep a backup.
- XML formatting may not match the original exactly after re-write.
"""

import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ----------------------------
# Data models
# ----------------------------

@dataclass
class AddressObject:
    name: str
    obj_type: str          # ip-netmask, ip-range, fqdn
    value: str
    scope_type: str        # shared or device-group
    scope_name: str        # shared or DG name
    entry_elem: ET.Element
    parent_elem: ET.Element

    def scope_label(self) -> str:
        if self.scope_type == "shared":
            return "shared"
        return f"device-group:{self.scope_name}"

    def key(self) -> Tuple[str, str]:
        return (self.obj_type, self.value)


@dataclass
class Reference:
    ref_type: str          # address-group, security-rule, nat-rule
    scope_type: str        # shared or device-group
    scope_name: str
    container_name: str    # group/rule name
    field_name: str        # source / destination / member / translated-address
    elem: ET.Element       # element whose text is the object name
    xml_path: str

    def scope_label(self) -> str:
        if self.scope_type == "shared":
            return "shared"
        return f"device-group:{self.scope_name}"


# ----------------------------
# XML helpers
# ----------------------------

def indent(elem: ET.Element, level: int = 0) -> None:
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        for child in elem:
            indent(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = i
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


# ----------------------------
# Address object discovery
# ----------------------------

def extract_address_value(addr_entry: ET.Element) -> Optional[Tuple[str, str]]:
    for tag in ("ip-netmask", "ip-range", "fqdn"):
        child = addr_entry.find(tag)
        if child is not None and child.text and child.text.strip():
            return tag, child.text.strip()
    return None


def find_shared_address_objects(root: ET.Element) -> List[AddressObject]:
    objs = []
    for shared in root.findall(".//shared"):
        addr_parent = shared.find("address")
        if addr_parent is None:
            continue
        for entry in addr_parent.findall("entry"):
            v = extract_address_value(entry)
            if not v:
                continue
            obj_type, value = v
            objs.append(
                AddressObject(
                    name=entry_name(entry),
                    obj_type=obj_type,
                    value=value,
                    scope_type="shared",
                    scope_name="shared",
                    entry_elem=entry,
                    parent_elem=addr_parent,
                )
            )
    return objs


def find_dg_address_objects(root: ET.Element) -> List[AddressObject]:
    objs = []
    for dg in root.findall(".//devices/entry/device-group/entry"):
        dg_name = entry_name(dg)
        addr_parent = dg.find("address")
        if addr_parent is None:
            continue
        for entry in addr_parent.findall("entry"):
            v = extract_address_value(entry)
            if not v:
                continue
            obj_type, value = v
            objs.append(
                AddressObject(
                    name=entry_name(entry),
                    obj_type=obj_type,
                    value=value,
                    scope_type="device-group",
                    scope_name=dg_name,
                    entry_elem=entry,
                    parent_elem=addr_parent,
                )
            )
    return objs


def collect_address_objects(root: ET.Element) -> List[AddressObject]:
    return find_shared_address_objects(root) + find_dg_address_objects(root)


# ----------------------------
# Reference discovery
# ----------------------------

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


def collect_address_group_references(root: ET.Element, parent_map: Dict[ET.Element, ET.Element]) -> Dict[str, List[Reference]]:
    refs = defaultdict(list)

    for ag_entry in root.findall(".//address-group/entry"):
        ag_name = entry_name(ag_entry)
        scope_type, scope_name = get_scope_from_ancestor(ag_entry, parent_map)

        static = ag_entry.find("static")
        if static is None:
            continue

        for member in static.findall("member"):
            if member.text and member.text.strip():
                obj_name = member.text.strip()
                refs[obj_name].append(
                    Reference(
                        ref_type="address-group",
                        scope_type=scope_type,
                        scope_name=scope_name,
                        container_name=ag_name,
                        field_name="member",
                        elem=member,
                        xml_path=get_xml_path(member, parent_map),
                    )
                )
    return refs


def collect_security_rule_references(root: ET.Element, parent_map: Dict[ET.Element, ET.Element]) -> Dict[str, List[Reference]]:
    refs = defaultdict(list)

    rule_paths = [
        ".//pre-rulebase/security/rules/entry",
        ".//post-rulebase/security/rules/entry",
        ".//rulebase/security/rules/entry",
    ]

    for path in rule_paths:
        for rule_entry in root.findall(path):
            rule_name = entry_name(rule_entry)
            scope_type, scope_name = get_scope_from_ancestor(rule_entry, parent_map)

            for field in ("source", "destination"):
                field_elem = rule_entry.find(field)
                if field_elem is None:
                    continue
                for member in field_elem.findall("member"):
                    if member.text and member.text.strip():
                        obj_name = member.text.strip()
                        refs[obj_name].append(
                            Reference(
                                ref_type="security-rule",
                                scope_type=scope_type,
                                scope_name=scope_name,
                                container_name=rule_name,
                                field_name=field,
                                elem=member,
                                xml_path=get_xml_path(member, parent_map),
                            )
                        )
    return refs


def collect_nat_rule_references(root: ET.Element, parent_map: Dict[ET.Element, ET.Element]) -> Dict[str, List[Reference]]:
    refs = defaultdict(list)

    rule_paths = [
        ".//pre-rulebase/nat/rules/entry",
        ".//post-rulebase/nat/rules/entry",
        ".//rulebase/nat/rules/entry",
    ]

    singleton_paths = [
        ("source-translation/static-ip/translated-address", "translated-address"),
        ("source-translation/dynamic-ip-and-port/translated-address", "translated-address"),
        ("destination-translation/translated-address", "translated-address"),
    ]

    for path in rule_paths:
        for rule_entry in root.findall(path):
            rule_name = entry_name(rule_entry)
            scope_type, scope_name = get_scope_from_ancestor(rule_entry, parent_map)

            for field in ("source", "destination"):
                field_elem = rule_entry.find(field)
                if field_elem is None:
                    continue
                for member in field_elem.findall("member"):
                    if member.text and member.text.strip():
                        obj_name = member.text.strip()
                        refs[obj_name].append(
                            Reference(
                                ref_type="nat-rule",
                                scope_type=scope_type,
                                scope_name=scope_name,
                                container_name=rule_name,
                                field_name=field,
                                elem=member,
                                xml_path=get_xml_path(member, parent_map),
                            )
                        )

            for rel_path, label in singleton_paths:
                single = rule_entry.find(rel_path)
                if single is not None and single.text and single.text.strip():
                    obj_name = single.text.strip()
                    refs[obj_name].append(
                        Reference(
                            ref_type="nat-rule",
                            scope_type=scope_type,
                            scope_name=scope_name,
                            container_name=rule_name,
                            field_name=label,
                            elem=single,
                            xml_path=get_xml_path(single, parent_map),
                        )
                    )

    return refs


def merge_reference_maps(*maps: Dict[str, List[Reference]]) -> Dict[str, List[Reference]]:
    merged = defaultdict(list)
    for m in maps:
        for k, v in m.items():
            merged[k].extend(v)
    return merged


# ----------------------------
# Visibility / safety rules
# ----------------------------

def can_replace_reference_with_target(ref: Reference, target_obj: AddressObject) -> bool:
    if target_obj.scope_type == "shared":
        return True

    if ref.scope_type == "device-group" and target_obj.scope_type == "device-group":
        return ref.scope_name == target_obj.scope_name

    if ref.scope_type == "shared" and target_obj.scope_type == "device-group":
        return False

    return False


# ----------------------------
# CSV reporting
# ----------------------------

def write_csv_report(
    csv_path: str,
    dup_groups: List[List[AddressObject]],
    refs_by_name: Dict[str, List[Reference]],
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
            obj_type = group[0].obj_type
            obj_value = group[0].value

            for obj in sorted(group, key=lambda x: (x.scope_type, x.scope_name, x.name)):
                refs = refs_by_name.get(obj.name, [])
                ref_count = len(refs)

                if refs:
                    for ref in refs:
                        writer.writerow([
                            group_id,
                            obj_type,
                            obj_value,
                            obj.name,
                            obj.scope_label(),
                            obj.scope_type,
                            obj.scope_name,
                            ref_count,
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
                        obj_type,
                        obj_value,
                        obj.name,
                        obj.scope_label(),
                        obj.scope_type,
                        obj.scope_name,
                        ref_count,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                    ])
            group_id += 1


# ----------------------------
# Interactive selection
# ----------------------------

def summarize_refs(refs: List[Reference]) -> Dict[str, int]:
    counts = defaultdict(int)
    for r in refs:
        counts[r.ref_type] += 1
    return dict(counts)


def print_reference_details(refs: List[Reference], max_show: int = 20) -> None:
    if not refs:
        print("      No references found.")
        return

    for idx, r in enumerate(refs[:max_show], 1):
        print(
            f"      {idx:2d}. [{r.ref_type}] {r.scope_label()} "
            f"{r.container_name} :: {r.field_name} :: {r.xml_path}"
        )
    if len(refs) > max_show:
        print(f"      ... {len(refs) - max_show} more")


def choose_keeper(
    dup_group: List[AddressObject],
    refs_by_name: Dict[str, List[Reference]],
) -> Optional[AddressObject]:
    print("\n" + "=" * 100)
    print(f"Duplicate value group: type={dup_group[0].obj_type!r} value={dup_group[0].value!r}")
    print("=" * 100)

    for i, obj in enumerate(dup_group, 1):
        refs = refs_by_name.get(obj.name, [])
        ref_summary = summarize_refs(refs)
        print(f"{i}. {obj.name}  [{obj.scope_label()}]")
        print(f"   refs={len(refs)} summary={ref_summary if ref_summary else '{}'}")
        print_reference_details(refs, max_show=10)
        print()

    print("Choose the object to KEEP for this duplicate group.")
    print("Options:")
    print("  number = keep that object and replace what can safely be replaced")
    print("  s      = skip this duplicate group")

    while True:
        choice = input("Selection: ").strip().lower()
        if choice == "s":
            return None
        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(dup_group):
                return dup_group[n - 1]
        print("Invalid selection.")


# ----------------------------
# Replacement / deletion
# ----------------------------

def replace_refs(old_name: str, target_obj: AddressObject, refs: List[Reference]) -> Tuple[int, int]:
    replaced = 0
    skipped = 0

    for ref in refs:
        if can_replace_reference_with_target(ref, target_obj):
            if ref.elem.text and ref.elem.text.strip() == old_name:
                ref.elem.text = target_obj.name
                replaced += 1
            else:
                skipped += 1
        else:
            skipped += 1

    return replaced, skipped


def delete_object_if_safe(obj: AddressObject, refs_by_name: Dict[str, List[Reference]]) -> bool:
    remaining_refs = refs_by_name.get(obj.name, [])
    if remaining_refs:
        return False
    try:
        obj.parent_elem.remove(obj.entry_elem)
        return True
    except Exception:
        return False


# ----------------------------
# Main workflow
# ----------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Deduplicate address objects in a Panorama XML export.")
    parser.add_argument("-i", "--input", required=True, help="Input Panorama XML file")
    parser.add_argument("-o", "--output", required=True, help="Output XML file")
    parser.add_argument("--delete-replaced", action="store_true", help="Delete duplicate address objects that are fully replaced and no longer referenced")
    parser.add_argument("--csv-report", help="Write duplicate/reference report to this CSV file")
    args = parser.parse_args()

    try:
        tree = ET.parse(args.input)
    except Exception as e:
        print(f"ERROR: failed to parse XML: {e}", file=sys.stderr)
        return 1

    root = tree.getroot()
    parent_map = build_parent_map(root)

    objects = collect_address_objects(root)
    if not objects:
        print("No address objects found.")
        return 0

    refs_by_name = merge_reference_maps(
        collect_address_group_references(root, parent_map),
        collect_security_rule_references(root, parent_map),
        collect_nat_rule_references(root, parent_map),
    )

    by_value = defaultdict(list)
    for obj in objects:
        by_value[obj.key()].append(obj)

    dup_groups = [group for group in by_value.values() if len(group) > 1]

    if args.csv_report:
        write_csv_report(args.csv_report, dup_groups, refs_by_name)
        print(f"Wrote CSV report: {args.csv_report}")

    if not dup_groups:
        print("No duplicate address objects found by value.")
        indent(root)
        tree.write(args.output, encoding="utf-8", xml_declaration=True)
        print(f"Wrote output: {args.output}")
        return 0

    print(f"Found {len(dup_groups)} duplicate value group(s).")

    total_replaced = 0
    total_skipped = 0
    total_deleted = 0

    for group in sorted(dup_groups, key=lambda g: (g[0].obj_type, g[0].value)):
        keeper = choose_keeper(group, refs_by_name)
        if keeper is None:
            print("Skipped.")
            continue

        print(f"Keeping: {keeper.name} [{keeper.scope_label()}]")

        for obj in group:
            if obj is keeper:
                continue

            old_refs = list(refs_by_name.get(obj.name, []))
            replaced, skipped = replace_refs(obj.name, keeper, old_refs)

            if replaced > 0:
                new_refs = []
                remaining_old_refs = []
                for ref in refs_by_name.get(obj.name, []):
                    if ref.elem.text and ref.elem.text.strip() == keeper.name:
                        new_refs.append(ref)
                    else:
                        remaining_old_refs.append(ref)
                refs_by_name[obj.name] = remaining_old_refs
                refs_by_name[keeper.name].extend(new_refs)

            total_replaced += replaced
            total_skipped += skipped

            print(
                f"  {obj.name} [{obj.scope_label()}] -> {keeper.name} "
                f"(replaced={replaced}, skipped={skipped})"
            )

            if args.delete_replaced:
                deleted = delete_object_if_safe(obj, refs_by_name)
                if deleted:
                    total_deleted += 1
                    print(f"    deleted duplicate object: {obj.name}")
                else:
                    print(f"    not deleted (still referenced, or delete failed): {obj.name}")

    indent(root)
    tree.write(args.output, encoding="utf-8", xml_declaration=True)

    print("\nDone.")
    print(f"Replaced references: {total_replaced}")
    print(f"Skipped replacements: {total_skipped}")
    if args.delete_replaced:
        print(f"Deleted duplicate objects: {total_deleted}")
    print(f"Wrote output: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
