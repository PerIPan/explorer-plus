"""
STIX extraction module — normalises ATT&CK STIX bundle into plain Python dicts.

All entity types and relationships are returned by extract_all().
"""

from __future__ import annotations

from typing import Any

from mitreattack.stix20 import MitreAttackData


# Tactic sort order as defined by the ATT&CK kill-chain phase sequence.
_TACTIC_SORT_ORDER: dict[str, int] = {
    'reconnaissance': 1,
    'resource-development': 2,
    'initial-access': 3,
    'execution': 4,
    'persistence': 5,
    'privilege-escalation': 6,
    'defense-evasion': 7,
    'credential-access': 8,
    'discovery': 9,
    'lateral-movement': 10,
    'collection': 11,
    'command-and-control': 12,
    'exfiltration': 13,
    'impact': 14,
}


def _attack_id(obj: Any) -> str | None:
    """Return the first mitre-attack external_id, or None."""
    for ref in getattr(obj, 'external_references', []):
        if getattr(ref, 'source_name', '') == 'mitre-attack':
            return ref.external_id
    return None


def _url(obj: Any) -> str | None:
    """Return the mitre-attack URL from external_references, or None."""
    for ref in getattr(obj, 'external_references', []):
        if getattr(ref, 'source_name', '') == 'mitre-attack':
            return getattr(ref, 'url', None)
    return None


def _ts(value: Any) -> str | None:
    """Convert a STIX timestamp to ISO-8601 string, or None."""
    return value.isoformat() if value is not None else None


# ---------------------------------------------------------------------------
# Entity extractors
# ---------------------------------------------------------------------------

def _extract_tactics(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_tactics():
        aid = _attack_id(obj)
        shortname = obj.get('x_mitre_shortname', '')
        rows.append({
            'stix_id': obj.id,
            'attack_id': aid,
            'name': obj.name,
            'description': obj.get('description'),
            'url': _url(obj),
            'sort_order': _TACTIC_SORT_ORDER.get(shortname),
            'domain': 'enterprise-attack',
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_techniques(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_techniques(remove_revoked_deprecated=False):
        aid = _attack_id(obj)
        is_sub = bool(obj.get('x_mitre_is_subtechnique', False))
        parent_attack_id: str | None = None
        if is_sub and aid and '.' in aid:
            parent_attack_id = aid.split('.')[0]
        rows.append({
            'stix_id': obj.id,
            'attack_id': aid,
            'name': obj.name,
            'description': obj.get('description'),
            'url': _url(obj),
            'platforms': list(obj.get('x_mitre_platforms') or []),
            'is_subtechnique': is_sub,
            'parent_attack_id': parent_attack_id,
            'detection': obj.get('detection'),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'revoked_by_stix_id': None,
            'domain': 'enterprise-attack',
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_groups(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_groups(remove_revoked_deprecated=False):
        aid = _attack_id(obj)
        rows.append({
            'stix_id': obj.id,
            'attack_id': aid,
            'name': obj.name,
            'description': obj.get('description'),
            'url': _url(obj),
            'aliases': list(obj.get('aliases') or []),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': 'enterprise-attack',
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_software(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_software(remove_revoked_deprecated=False):
        aid = _attack_id(obj)
        sw_type = 'malware' if obj.type == 'malware' else 'tool'
        rows.append({
            'stix_id': obj.id,
            'attack_id': aid,
            'name': obj.name,
            'description': obj.get('description'),
            'url': _url(obj),
            'type': sw_type,
            'platforms': list(obj.get('x_mitre_platforms') or []),
            'aliases': list(obj.get('x_mitre_aliases') or []),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': 'enterprise-attack',
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_mitigations(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_mitigations(remove_revoked_deprecated=False):
        aid = _attack_id(obj)
        rows.append({
            'stix_id': obj.id,
            'attack_id': aid,
            'name': obj.name,
            'description': obj.get('description'),
            'url': _url(obj),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': 'enterprise-attack',
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_campaigns(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_campaigns(remove_revoked_deprecated=False):
        aid = _attack_id(obj)
        rows.append({
            'stix_id': obj.id,
            'attack_id': aid,
            'name': obj.name,
            'description': obj.get('description'),
            'url': _url(obj),
            'aliases': list(obj.get('aliases') or []),
            'first_seen': _ts(obj.get('first_seen')),
            'last_seen': _ts(obj.get('last_seen')),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': 'enterprise-attack',
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_data_sources(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_datasources(remove_revoked_deprecated=False):
        aid = _attack_id(obj)
        rows.append({
            'stix_id': obj.id,
            'attack_id': aid,
            'name': obj.name,
            'description': obj.get('description'),
            'url': _url(obj),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': 'enterprise-attack',
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_data_components(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_datacomponents():
        rows.append({
            'stix_id': obj.id,
            'name': obj.name,
            'description': obj.get('description'),
            'data_source_stix_id': obj.get('x_mitre_data_source_ref'),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': 'enterprise-attack',
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


# ---------------------------------------------------------------------------
# Relationship extractors
# ---------------------------------------------------------------------------

def _extract_group_techniques(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for group_stix_id, entries in attack.get_all_techniques_used_by_all_groups().items():
        for entry in entries:
            tech = entry['object']
            rows.append({
                'group_stix_id': group_stix_id,
                'technique_stix_id': tech.id,
                'description': entry.get('relationship', {}).get('description'),
            })
    return rows


def _extract_group_software(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for group_stix_id, entries in attack.get_all_software_used_by_all_groups().items():
        for entry in entries:
            sw = entry['object']
            rows.append({
                'group_stix_id': group_stix_id,
                'software_stix_id': sw.id,
                'description': entry.get('relationship', {}).get('description'),
            })
    return rows


def _extract_software_techniques(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sw_stix_id, entries in attack.get_all_techniques_used_by_all_software().items():
        for entry in entries:
            tech = entry['object']
            rows.append({
                'software_stix_id': sw_stix_id,
                'technique_stix_id': tech.id,
                'description': entry.get('relationship', {}).get('description'),
            })
    return rows


def _extract_mitigation_techniques(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for mit_stix_id, entries in attack.get_all_techniques_mitigated_by_all_mitigations().items():
        for entry in entries:
            tech = entry['object']
            rows.append({
                'mitigation_stix_id': mit_stix_id,
                'technique_stix_id': tech.id,
                'description': entry.get('relationship', {}).get('description'),
            })
    return rows


def _extract_technique_data_components(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for dc_stix_id, entries in attack.get_all_techniques_detected_by_all_datacomponents().items():
        for entry in entries:
            tech = entry['object']
            rows.append({
                'data_component_stix_id': dc_stix_id,
                'technique_stix_id': tech.id,
            })
    return rows


def _extract_campaign_techniques(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for camp_stix_id, entries in attack.get_all_techniques_used_by_all_campaigns().items():
        for entry in entries:
            tech = entry['object']
            rows.append({
                'campaign_stix_id': camp_stix_id,
                'technique_stix_id': tech.id,
                'description': entry.get('relationship', {}).get('description'),
            })
    return rows


def _extract_campaign_software(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for camp_stix_id, entries in attack.get_all_software_used_by_all_campaigns().items():
        for entry in entries:
            sw = entry['object']
            rows.append({
                'campaign_stix_id': camp_stix_id,
                'software_stix_id': sw.id,
                'description': entry.get('relationship', {}).get('description'),
            })
    return rows


def _extract_group_campaigns(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for group_stix_id, entries in attack.get_all_campaigns_attributed_to_all_groups().items():
        for entry in entries:
            camp = entry['object']
            rows.append({
                'group_stix_id': group_stix_id,
                'campaign_stix_id': camp.id,
                'description': entry.get('relationship', {}).get('description'),
            })
    return rows


def _extract_technique_tactics(attack: MitreAttackData) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    tactics = attack.get_tactics()
    tactic_by_shortname = {t.get('x_mitre_shortname'): t.id for t in tactics}
    for tech in attack.get_techniques(remove_revoked_deprecated=False):
        for kc in tech.get('kill_chain_phases') or []:
            if kc.get('kill_chain_name') == 'mitre-attack':
                tactic_stix_id = tactic_by_shortname.get(kc.get('phase_name'))
                if tactic_stix_id:
                    rows.append({
                        'technique_stix_id': tech.id,
                        'tactic_stix_id': tactic_stix_id,
                    })
    return rows


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_all(stix_path: str) -> dict[str, list[dict[str, Any]]]:
    """Load a STIX bundle and return normalized dicts for all entity types.

    Args:
        stix_path: Path to the enterprise-attack STIX JSON file.

    Returns:
        Dict with keys: tactics, techniques, groups, software, mitigations,
        campaigns, data_sources, data_components, group_techniques,
        group_software, software_techniques, mitigation_techniques,
        technique_data_components, campaign_techniques, campaign_software,
        group_campaigns, technique_tactics.
    """
    attack = MitreAttackData(stix_path)
    return {
        'tactics': _extract_tactics(attack),
        'techniques': _extract_techniques(attack),
        'groups': _extract_groups(attack),
        'software': _extract_software(attack),
        'mitigations': _extract_mitigations(attack),
        'campaigns': _extract_campaigns(attack),
        'data_sources': _extract_data_sources(attack),
        'data_components': _extract_data_components(attack),
        'group_techniques': _extract_group_techniques(attack),
        'group_software': _extract_group_software(attack),
        'software_techniques': _extract_software_techniques(attack),
        'mitigation_techniques': _extract_mitigation_techniques(attack),
        'technique_data_components': _extract_technique_data_components(attack),
        'campaign_techniques': _extract_campaign_techniques(attack),
        'campaign_software': _extract_campaign_software(attack),
        'group_campaigns': _extract_group_campaigns(attack),
        'technique_tactics': _extract_technique_tactics(attack),
    }
