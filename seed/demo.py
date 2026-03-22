"""
MITRE ATT&CK Python Client
Uses mitreattack-python with local STIX data for fast, offline queries.
"""

from mitreattack.stix20 import MitreAttackData


def load_attack_data(path: str = "data/enterprise-attack.json") -> MitreAttackData:
    """Load ATT&CK data from local STIX JSON file."""
    print(f"Loading ATT&CK data from {path}...")
    return MitreAttackData(path)


def demo_techniques(attack: MitreAttackData) -> None:
    """Show all techniques count and a sample."""
    techniques = attack.get_techniques(remove_revoked_deprecated=True)
    print(f"\n--- Techniques ---")
    print(f"Total: {len(techniques)}")
    for t in techniques[:5]:
        print(f"  [{t.external_references[0].external_id}] {t.name}")
    print(f"  ... and {len(techniques) - 5} more")


def demo_groups(attack: MitreAttackData) -> None:
    """Show all threat groups count and a sample."""
    groups = attack.get_groups(remove_revoked_deprecated=True)
    print(f"\n--- Threat Groups ---")
    print(f"Total: {len(groups)}")
    for g in groups[:5]:
        print(f"  [{g.external_references[0].external_id}] {g.name}")
    print(f"  ... and {len(groups) - 5} more")


def demo_tactics(attack: MitreAttackData) -> None:
    """Show all tactics."""
    tactics = attack.get_tactics(remove_revoked_deprecated=True)
    print(f"\n--- Tactics ---")
    print(f"Total: {len(tactics)}")
    for t in tactics:
        print(f"  [{t.external_references[0].external_id}] {t.name}")


def demo_software(attack: MitreAttackData) -> None:
    """Show malware and tools count."""
    software = attack.get_software(remove_revoked_deprecated=True)
    print(f"\n--- Software (Malware + Tools) ---")
    print(f"Total: {len(software)}")
    for s in software[:5]:
        print(f"  [{s.external_references[0].external_id}] {s.name}")
    print(f"  ... and {len(software) - 5} more")


def demo_group_techniques(attack: MitreAttackData, group_name: str = "APT29") -> None:
    """Show techniques used by a specific group."""
    groups = attack.get_groups(remove_revoked_deprecated=True)
    target = next((g for g in groups if g.name == group_name), None)
    if not target:
        print(f"\nGroup '{group_name}' not found.")
        return

    techniques = attack.get_techniques_used_by_group(target.id)
    print(f"\n--- Techniques used by {group_name} ---")
    print(f"Total: {len(techniques)}")
    for entry in techniques[:10]:
        tech = entry["object"]
        ext_id = tech.external_references[0].external_id if tech.external_references else "N/A"
        print(f"  [{ext_id}] {tech.name}")
    if len(techniques) > 10:
        print(f"  ... and {len(techniques) - 10} more")


def demo_mitigations(attack: MitreAttackData) -> None:
    """Show mitigations count and sample."""
    mitigations = attack.get_mitigations(remove_revoked_deprecated=True)
    print(f"\n--- Mitigations ---")
    print(f"Total: {len(mitigations)}")
    for m in mitigations[:5]:
        print(f"  [{m.external_references[0].external_id}] {m.name}")
    print(f"  ... and {len(mitigations) - 5} more")


if __name__ == "__main__":
    attack = load_attack_data()
    demo_tactics(attack)
    demo_techniques(attack)
    demo_groups(attack)
    demo_software(attack)
    demo_mitigations(attack)
    demo_group_techniques(attack)
    print("\nDone.")
