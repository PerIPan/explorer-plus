"""
STIX extraction module — normalises ATT&CK STIX bundle into plain Python dicts.

All entity types and relationships are returned by extract_all().
"""

from __future__ import annotations

import json
from typing import Any

from mitreattack.stix20 import MitreAttackData


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Sort order keyed on x_mitre_shortname (kill-chain phase name).
_TACTIC_SORT_ORDER: dict[str, int] = {
    # Enterprise (1-14)
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
    # ICS unique tactics (101-112 range to avoid collisions)
    'evasion': 107,
    'inhibit-response-function': 111,
    'impair-process-control': 112,
    # Mobile unique tactics (201-214 range)
    'network-effects': 213,
    'remote-service-effects': 214,
}

# Fallback DC-name → DS-name lookup for components whose names are not a
# simple prefix of their parent data source name.
_DC_NAME_TO_DS_NAME: dict[str, str] = {
    'Active DNS': 'Domain Name',
    'Domain Registration': 'Domain Name',
    'Host Status': 'Sensor Health',
    'Malware Content': 'Malware Repository',
    'Malware Metadata': 'Malware Repository',
    'Network Connection Creation': 'Network Traffic',
    'OS API Execution': 'Process',
    'Passive DNS': 'Domain Name',
    'Response Content': 'Internet Scan',
    'Response Metadata': 'Internet Scan',
    'Social Media': 'Persona',
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_attack_id(obj: Any) -> str:
    """Return the first mitre-attack external_id, or empty string."""
    for ref in getattr(obj, 'external_references', []):
        src = getattr(ref, 'source_name', None) or ref.get('source_name', '')
        if src == 'mitre-attack':
            return getattr(ref, 'external_id', None) or ref.get('external_id', '') or ''
    return ''


def _get_url(obj: Any) -> str:
    """Return the mitre-attack URL from external_references, or empty string."""
    for ref in getattr(obj, 'external_references', []):
        src = getattr(ref, 'source_name', None) or ref.get('source_name', '')
        if src == 'mitre-attack':
            return getattr(ref, 'url', None) or ref.get('url', '') or ''
    return ''


def _ts(value: Any) -> str | None:
    """Convert a STIX timestamp to ISO-8601 string, or None."""
    if value is None:
        return None
    return value.isoformat() if hasattr(value, 'isoformat') else str(value)


def _rel_description(entry: dict[str, Any]) -> str:
    """Extract the procedure description from a RelationshipEntry dict.

    The mitreattack-python library returns entries with shape:
        {'object': <stix_obj>, 'relationships': [<Relationship>, ...]}
    The description lives on the first Relationship object.
    """
    rels = entry.get('relationships') or []
    if not rels:
        return ''
    return getattr(rels[0], 'description', '') or ''


def _build_dc_to_ds_id(
    attack: MitreAttackData,
    raw_objects: list[dict[str, Any]],
) -> dict[str, str]:
    """Build a mapping from data-component STIX ID to parent data-source STIX ID.

    Strategy (in order):
    1. Use x_mitre_data_source_ref if non-empty on the raw STIX object.
    2. Match data-component name as a prefix of a data-source name.
    3. Use the hardcoded _DC_NAME_TO_DS_NAME fallback table.
    Returns an empty string for any component that cannot be resolved.
    """
    ds_list = attack.get_datasources()
    # name → stix_id for data sources
    ds_name_to_id: dict[str, str] = {ds.name: ds.id for ds in ds_list}

    # raw map for x_mitre_data_source_ref fallback
    raw_dc_map: dict[str, dict[str, Any]] = {
        o['id']: o
        for o in raw_objects
        if o.get('type') == 'x-mitre-data-component'
    }

    dc_to_ds: dict[str, str] = {}
    for dc in attack.get_datacomponents():
        # 1. explicit ref in raw STIX
        raw = raw_dc_map.get(dc.id, {})
        ref = raw.get('x_mitre_data_source_ref', '')
        if ref:
            dc_to_ds[dc.id] = ref
            continue

        # 2. prefix match: DC name starts with DS name + ' '
        matched = ''
        for ds_name, ds_id in ds_name_to_id.items():
            if dc.name == ds_name or dc.name.startswith(ds_name + ' '):
                if not matched or len(ds_name) > len(
                    next(n for n, i in ds_name_to_id.items() if i == matched)
                ):
                    matched = ds_id
        if matched:
            dc_to_ds[dc.id] = matched
            continue

        # 3. hardcoded fallback
        fallback_ds_name = _DC_NAME_TO_DS_NAME.get(dc.name, '')
        dc_to_ds[dc.id] = ds_name_to_id.get(fallback_ds_name, '')

    return dc_to_ds


def _build_technique_dc_pairs(
    raw_objects: list[dict[str, Any]],
) -> list[tuple[str, str]]:
    """Build (technique_stix_id, data_component_stix_id) pairs.

    The ATT&CK STIX bundle (spec ≥ 3.2) models detection through:
      x-mitre-detection-strategy  --detects-->  attack-pattern
      x-mitre-detection-strategy  (x_mitre_analytic_refs)  x-mitre-analytic
      x-mitre-analytic  (x_mitre_log_source_references[].x_mitre_data_component_ref)
        --> x-mitre-data-component

    We walk that chain to derive the technique ↔ data-component relationships.
    """
    rels = [o for o in raw_objects if o.get('type') == 'relationship']
    det_strats: dict[str, dict[str, Any]] = {
        o['id']: o
        for o in raw_objects
        if o.get('type') == 'x-mitre-detection-strategy'
    }
    analytics: dict[str, dict[str, Any]] = {
        o['id']: o
        for o in raw_objects
        if o.get('type') == 'x-mitre-analytic'
    }

    # detection-strategy STIX ID → set of technique STIX IDs
    ds_to_techs: dict[str, set[str]] = {}
    for rel in rels:
        if rel.get('relationship_type') != 'detects':
            continue
        src = rel.get('source_ref', '')
        tgt = rel.get('target_ref', '')
        if 'detection-strategy' not in src or 'attack-pattern' not in tgt:
            continue
        ds_to_techs.setdefault(src, set()).add(tgt)

    pairs: set[tuple[str, str]] = set()
    for ds_id, ds_obj in det_strats.items():
        tech_ids = ds_to_techs.get(ds_id, set())
        if not tech_ids:
            continue
        for analytic_ref in ds_obj.get('x_mitre_analytic_refs') or []:
            analytic = analytics.get(analytic_ref)
            if not analytic:
                continue
            for log_src in analytic.get('x_mitre_log_source_references') or []:
                dc_ref = log_src.get('x_mitre_data_component_ref')
                if not dc_ref:
                    continue
                for tech_id in tech_ids:
                    pairs.add((tech_id, dc_ref))

    return list(pairs)


# ---------------------------------------------------------------------------
# Entity extractors
# ---------------------------------------------------------------------------

def _extract_tactics(attack: MitreAttackData, domain: str = 'enterprise-attack') -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_tactics():
        shortname: str = obj.get('x_mitre_shortname') or ''
        rows.append({
            'stix_id': obj.id,
            'attack_id': _get_attack_id(obj),
            'name': obj.name,
            'description': obj.get('description') or '',
            'url': _get_url(obj),
            'sort_order': _TACTIC_SORT_ORDER.get(shortname),
            'domain': domain,
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_techniques(attack: MitreAttackData, domain: str = 'enterprise-attack') -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_techniques(remove_revoked_deprecated=False):
        aid = _get_attack_id(obj)
        is_sub = bool(obj.get('x_mitre_is_subtechnique', False))
        parent_attack_id: str | None = None
        if is_sub and aid and '.' in aid:
            parent_attack_id = aid.split('.')[0]
        rows.append({
            'stix_id': obj.id,
            'attack_id': aid,
            'name': obj.name,
            'description': obj.get('description') or '',
            'url': _get_url(obj),
            'platforms': list(obj.get('x_mitre_platforms') or []),
            'is_subtechnique': is_sub,
            'parent_attack_id': parent_attack_id,
            'detection': obj.get('x_mitre_detection') or '',
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'revoked_by_stix_id': None,
            'domain': domain,
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_groups(attack: MitreAttackData, domain: str = 'enterprise-attack') -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_groups(remove_revoked_deprecated=False):
        rows.append({
            'stix_id': obj.id,
            'attack_id': _get_attack_id(obj),
            'name': obj.name,
            'description': obj.get('description') or '',
            'url': _get_url(obj),
            'aliases': list(obj.get('aliases') or []),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': domain,
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_software(attack: MitreAttackData, domain: str = 'enterprise-attack') -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_software(remove_revoked_deprecated=False):
        sw_type = 'malware' if getattr(obj, 'type', '') == 'malware' else 'tool'
        # standard STIX malware/tool objects use 'aliases'; ATT&CK also uses
        # 'x_mitre_aliases' on older objects — take whichever is populated.
        aliases: list[str] = list(
            obj.get('aliases') or obj.get('x_mitre_aliases') or []
        )
        rows.append({
            'stix_id': obj.id,
            'attack_id': _get_attack_id(obj),
            'name': obj.name,
            'description': obj.get('description') or '',
            'url': _get_url(obj),
            'type': sw_type,
            'platforms': list(obj.get('x_mitre_platforms') or []),
            'aliases': aliases,
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': domain,
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_mitigations(attack: MitreAttackData, domain: str = 'enterprise-attack') -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_mitigations(remove_revoked_deprecated=False):
        rows.append({
            'stix_id': obj.id,
            'attack_id': _get_attack_id(obj),
            'name': obj.name,
            'description': obj.get('description') or '',
            'url': _get_url(obj),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': domain,
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_campaigns(attack: MitreAttackData, domain: str = 'enterprise-attack') -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_campaigns(remove_revoked_deprecated=False):
        rows.append({
            'stix_id': obj.id,
            'attack_id': _get_attack_id(obj),
            'name': obj.name,
            'description': obj.get('description') or '',
            'url': _get_url(obj),
            'aliases': list(obj.get('aliases') or []),
            'first_seen': _ts(obj.get('first_seen')),
            'last_seen': _ts(obj.get('last_seen')),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': domain,
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_data_sources(attack: MitreAttackData, domain: str = 'enterprise-attack') -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_datasources():
        rows.append({
            'stix_id': obj.id,
            'attack_id': _get_attack_id(obj),
            'name': obj.name,
            'description': obj.get('description') or '',
            'url': _get_url(obj),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': domain,
            'stix_created': _ts(obj.get('created')),
            'stix_modified': _ts(obj.get('modified')),
        })
    return rows


def _extract_data_components(
    attack: MitreAttackData,
    dc_to_ds: dict[str, str],
    domain: str = 'enterprise-attack',
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for obj in attack.get_datacomponents():
        rows.append({
            'stix_id': obj.id,
            'name': obj.name,
            'description': obj.get('description') or '',
            'data_source_stix_id': dc_to_ds.get(obj.id, ''),
            'is_revoked': bool(obj.get('revoked', False)),
            'is_deprecated': bool(obj.get('x_mitre_deprecated', False)),
            'domain': domain,
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
                'description': _rel_description(entry),
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
                'description': _rel_description(entry),
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
                'description': _rel_description(entry),
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
                'description': _rel_description(entry),
            })
    return rows


def _extract_technique_tactics(attack: MitreAttackData) -> list[dict[str, Any]]:
    tactics = attack.get_tactics()
    # shortname (e.g. 'defense-evasion') → tactic STIX ID
    tactic_by_shortname: dict[str, str] = {
        t.get('x_mitre_shortname'): t.id
        for t in tactics
        if t.get('x_mitre_shortname')
    }
    rows: list[dict[str, Any]] = []
    for tech in attack.get_techniques(remove_revoked_deprecated=False):
        for kc in tech.get('kill_chain_phases') or []:
            kc_name = kc.get('kill_chain_name') if isinstance(kc, dict) else getattr(kc, 'kill_chain_name', '')
            phase_name = kc.get('phase_name') if isinstance(kc, dict) else getattr(kc, 'phase_name', '')
            if kc_name not in ('mitre-attack', 'mitre-ics-attack', 'mitre-mobile-attack'):
                continue
            tactic_stix_id = tactic_by_shortname.get(phase_name)
            if tactic_stix_id:
                rows.append({
                    'technique_stix_id': tech.id,
                    'tactic_stix_id': tactic_stix_id,
                })
    return rows


def _extract_technique_data_components(
    pairs: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Return deduplicated (technique_stix_id, data_component_stix_id) rows."""
    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for tech_id, dc_id in pairs:
        key = (tech_id, dc_id)
        if key not in seen:
            seen.add(key)
            rows.append({
                'technique_stix_id': tech_id,
                'data_component_stix_id': dc_id,
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
                'description': _rel_description(entry),
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
                'description': _rel_description(entry),
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
                'description': _rel_description(entry),
            })
    return rows


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_all(stix_path: str = 'data/enterprise-attack.json', domain: str = 'enterprise-attack') -> dict[str, list[dict[str, Any]]]:
    """Load a STIX bundle and return normalised dicts for all ATT&CK entity types.

    Args:
        stix_path: Path to a STIX 2.1 JSON bundle file.
        domain: ATT&CK domain identifier (enterprise-attack, ics-attack, mobile-attack).

    Returns:
        Dict with keys: tactics, techniques, threat_groups, attack_software,
        mitigations, campaigns, data_sources, data_components,
        group_techniques, group_software, software_techniques,
        mitigation_techniques, technique_tactics, technique_data_components,
        campaign_techniques, campaign_software, group_campaigns.
    """
    attack = MitreAttackData(stix_path)

    with open(stix_path, encoding='utf-8') as fh:
        raw_objects: list[dict[str, Any]] = json.load(fh)['objects']

    dc_to_ds = _build_dc_to_ds_id(attack, raw_objects)
    tech_dc_pairs = _build_technique_dc_pairs(raw_objects)

    return {
        'tactics': _extract_tactics(attack, domain),
        'techniques': _extract_techniques(attack, domain),
        'threat_groups': _extract_groups(attack, domain),
        'attack_software': _extract_software(attack, domain),
        'mitigations': _extract_mitigations(attack, domain),
        'campaigns': _extract_campaigns(attack, domain),
        'data_sources': _extract_data_sources(attack, domain),
        'data_components': _extract_data_components(attack, dc_to_ds, domain),
        'group_techniques': _extract_group_techniques(attack),
        'group_software': _extract_group_software(attack),
        'software_techniques': _extract_software_techniques(attack),
        'mitigation_techniques': _extract_mitigation_techniques(attack),
        'technique_tactics': _extract_technique_tactics(attack),
        'technique_data_components': _extract_technique_data_components(tech_dc_pairs),
        'campaign_techniques': _extract_campaign_techniques(attack),
        'campaign_software': _extract_campaign_software(attack),
        'group_campaigns': _extract_group_campaigns(attack),
    }
