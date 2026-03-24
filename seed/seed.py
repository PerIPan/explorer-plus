#!/usr/bin/env python3
"""
MITRE ATT&CK seed orchestrator.

Usage:
    python seed/seed.py                    # seed local DB
    python seed/seed.py --update           # download fresh STIX + seed
    python seed/seed.py --confirm-destructive  # required for production DBs
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import psycopg
import requests

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent
_SCHEMA_PATH = str(Path(__file__).parent / 'schema.sql')
_DEFAULT_DB_URL = 'postgresql://postgres@localhost:5432/mitre_attack'

_STIX_DOMAINS = {
    'enterprise-attack': {
        'url': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
        'path': str(_REPO_ROOT / 'data' / 'enterprise-attack.json'),
    },
    'ics-attack': {
        'url': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json',
        'path': str(_REPO_ROOT / 'data' / 'ics-attack.json'),
    },
    'mobile-attack': {
        'url': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json',
        'path': str(_REPO_ROOT / 'data' / 'mobile-attack.json'),
    },
}
# Backwards compat
_STIX_PATH = _STIX_DOMAINS['enterprise-attack']['path']
_STIX_URL = _STIX_DOMAINS['enterprise-attack']['url']


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        description='Seed the MITRE ATT&CK database.',
    )
    parser.add_argument(
        '--update',
        action='store_true',
        help='Download fresh STIX bundle before seeding.',
    )
    parser.add_argument(
        '--confirm-destructive',
        action='store_true',
        help='Required when DATABASE_URL points to a production database.',
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Safety check
# ---------------------------------------------------------------------------

def _safety_check(db_url: str, confirm_destructive: bool) -> None:
    """Refuse to truncate production databases without explicit confirmation.

    Args:
        db_url: Database connection URL.
        confirm_destructive: Whether --confirm-destructive was passed.

    Raises:
        SystemExit: If targeting a production DB without confirmation.
    """
    prod_indicators = ('neon', 'vercel')
    if any(indicator in db_url.lower() for indicator in prod_indicators):
        if not confirm_destructive:
            print(
                'ERROR: DATABASE_URL appears to point to a production database '
                f'({db_url[:60]}...).\n'
                'Pass --confirm-destructive to proceed.',
                file=sys.stderr,
            )
            sys.exit(1)
        print('WARNING: proceeding with destructive seed on production DB.')


# ---------------------------------------------------------------------------
# STIX download
# ---------------------------------------------------------------------------

def _download_stix(stix_path: str, url: str | None = None) -> str:
    """Download a STIX bundle and return its SHA-256 hash.

    Args:
        stix_path: Destination file path.
        url: URL to download from (defaults to enterprise-attack).

    Returns:
        Hex-encoded SHA-256 digest of the downloaded file.
    """
    src = url or _STIX_URL
    print(f'Downloading STIX bundle from {src} ...')
    response = requests.get(src, timeout=120)
    response.raise_for_status()
    dest = Path(stix_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(response.content)
    digest = hashlib.sha256(response.content).hexdigest()
    print(f'  Saved {len(response.content):,} bytes  sha256={digest[:16]}...')
    return digest


def _hash_file(path: str) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        path: Path to the file.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# ATT&CK version extraction
# ---------------------------------------------------------------------------

def _extract_attack_version(stix_path: str) -> str:
    """Read the ATT&CK version from the x-mitre-collection object.

    Args:
        stix_path: Path to the STIX bundle JSON file.

    Returns:
        Version string (e.g. '16.1') or 'unknown'.
    """
    with open(stix_path, encoding='utf-8') as fh:
        raw = json.load(fh)
    for obj in raw.get('objects', []):
        if obj.get('type') == 'x-mitre-collection':
            return obj.get('x_mitre_version', 'unknown')
    return 'unknown'


# ---------------------------------------------------------------------------
# Schema execution
# ---------------------------------------------------------------------------

def _run_schema(cur: psycopg.Cursor, schema_path: str) -> None:
    """Read and execute the schema SQL file.

    Args:
        cur: Active psycopg cursor (within a transaction).
        schema_path: Absolute path to schema.sql.
    """
    sql = Path(schema_path).read_text(encoding='utf-8')
    cur.execute(sql)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Entity insertion helpers
# ---------------------------------------------------------------------------

def _insert_entities(
    cur: psycopg.Cursor,
    table: str,
    entities: list[dict[str, Any]],
    columns: list[str],
    stix_id_to_uuid: dict[str, str],
) -> int:
    """Insert entities and populate the stix_id -> UUID mapping.

    Args:
        cur: Active database cursor.
        table: Target table name.
        entities: List of entity dicts.
        columns: Ordered list of column names to insert.
        stix_id_to_uuid: Mutable mapping that is updated in place.

    Returns:
        Number of rows inserted.
    """
    if not entities:
        return 0

    placeholders = ', '.join(['%s'] * len(columns))
    sql = (
        f'INSERT INTO {table} ({", ".join(columns)}) '
        f'VALUES ({placeholders}) '
        f'RETURNING id, stix_id'
    )
    count = 0
    for entity in entities:
        values = [entity.get(col) for col in columns]
        cur.execute(sql, values)  # type: ignore[arg-type]
        row = cur.fetchone()
        if row and entity.get('stix_id'):
            stix_id_to_uuid[entity['stix_id']] = str(row[0])
        count += 1
    return count


def _insert_relationships(
    cur: psycopg.Cursor,
    table: str,
    rels: list[dict[str, Any]],
    src_col: str,
    tgt_col: str,
    src_key: str,
    tgt_key: str,
    stix_id_to_uuid: dict[str, str],
    extra_cols: list[str] | None = None,
) -> int:
    """Insert relationship rows, resolving stix_ids to UUIDs.

    Args:
        cur: Active database cursor.
        table: Target junction table name.
        rels: List of relationship dicts.
        src_col: Column name for the source FK.
        tgt_col: Column name for the target FK.
        src_key: Dict key for the source stix_id.
        tgt_key: Dict key for the target stix_id.
        stix_id_to_uuid: Resolved stix_id -> UUID mapping.
        extra_cols: Additional column names to insert (e.g. 'description').

    Returns:
        Number of rows successfully inserted.
    """
    if not rels:
        return 0

    cols = [src_col, tgt_col]
    if extra_cols:
        cols.extend(extra_cols)

    placeholders = ', '.join(['%s'] * len(cols))
    sql = (
        f'INSERT INTO {table} ({", ".join(cols)}) '
        f'VALUES ({placeholders}) '
        f'ON CONFLICT DO NOTHING'
    )

    skipped = 0
    inserted = 0
    for rel in rels:
        src_uuid = stix_id_to_uuid.get(rel[src_key])
        tgt_uuid = stix_id_to_uuid.get(rel[tgt_key])
        if not src_uuid or not tgt_uuid:
            skipped += 1
            continue
        values: list[Any] = [src_uuid, tgt_uuid]
        if extra_cols:
            values.extend([rel.get(c) for c in extra_cols])
        cur.execute(sql, values)  # type: ignore[arg-type]
        inserted += 1

    if skipped:
        print(f'  Warning: skipped {skipped} {table} rows (unresolved stix_ids)')
    return inserted


# ---------------------------------------------------------------------------
# Technique insertion (special: parents before sub-techniques)
# ---------------------------------------------------------------------------

def _insert_techniques(
    cur: psycopg.Cursor,
    techniques: list[dict[str, Any]],
    stix_id_to_uuid: dict[str, str],
) -> int:
    """Insert techniques with parent-before-child ordering.

    Parent techniques (is_subtechnique=False) are inserted first. Then
    sub-techniques are inserted with their parent_technique_id resolved
    from the attack_id prefix (e.g. T1059.001 -> T1059).

    Args:
        cur: Active database cursor.
        techniques: All technique dicts from extract_all().
        stix_id_to_uuid: Mutable stix_id -> UUID mapping updated in place.

    Returns:
        Total number of rows inserted.
    """
    columns_base = [
        'stix_id', 'attack_id', 'name', 'description', 'url',
        'platforms', 'is_subtechnique', 'detection',
        'is_revoked', 'is_deprecated', 'revoked_by_stix_id',
        'domain', 'stix_created', 'stix_modified',
    ]
    columns_with_parent = columns_base + ['parent_technique_id']

    # Build attack_id -> stix_id for all parent techniques (used for FK lookup)
    attack_id_to_stix: dict[str, str] = {
        t['attack_id']: t['stix_id']
        for t in techniques
        if not t.get('is_subtechnique') and t.get('attack_id') and t.get('stix_id')
    }

    parents = [t for t in techniques if not t.get('is_subtechnique')]
    subtechs = [t for t in techniques if t.get('is_subtechnique')]

    # SQL for parent techniques (no parent_technique_id column)
    placeholders_base = ', '.join(['%s'] * len(columns_base))
    sql_parent = (
        f'INSERT INTO techniques ({", ".join(columns_base)}) '
        f'VALUES ({placeholders_base}) '
        f'RETURNING id, stix_id'
    )

    placeholders_sub = ', '.join(['%s'] * len(columns_with_parent))
    sql_sub = (
        f'INSERT INTO techniques ({", ".join(columns_with_parent)}) '
        f'VALUES ({placeholders_sub}) '
        f'RETURNING id, stix_id'
    )

    count = 0

    for tech in parents:
        values = [tech.get(col) for col in columns_base]
        cur.execute(sql_parent, values)  # type: ignore[arg-type]
        row = cur.fetchone()
        if row and tech.get('stix_id'):
            stix_id_to_uuid[tech['stix_id']] = str(row[0])
        count += 1

    # attack_id -> DB UUID (populated from parents just inserted)
    attack_id_to_uuid: dict[str, str] = {
        t['attack_id']: stix_id_to_uuid[t['stix_id']]
        for t in parents
        if t.get('attack_id') and t.get('stix_id') and t['stix_id'] in stix_id_to_uuid
    }

    for tech in subtechs:
        parent_attack_id = tech.get('parent_attack_id')
        parent_uuid: str | None = (
            attack_id_to_uuid.get(parent_attack_id) if parent_attack_id else None
        )
        values = [tech.get(col) for col in columns_base] + [parent_uuid]
        cur.execute(sql_sub, values)  # type: ignore[arg-type]
        row = cur.fetchone()
        if row and tech.get('stix_id'):
            stix_id_to_uuid[tech['stix_id']] = str(row[0])
        count += 1

    return count


# ---------------------------------------------------------------------------
# Data component insertion (needs data_source_id FK)
# ---------------------------------------------------------------------------

def _insert_data_components(
    cur: psycopg.Cursor,
    data_components: list[dict[str, Any]],
    stix_id_to_uuid: dict[str, str],
) -> int:
    """Insert data components, resolving data_source_id from stix_id mapping.

    Args:
        cur: Active database cursor.
        data_components: List of data component dicts.
        stix_id_to_uuid: stix_id -> UUID mapping (must include data sources).

    Returns:
        Number of rows inserted.
    """
    columns = [
        'stix_id', 'name', 'description', 'data_source_id',
        'is_revoked', 'is_deprecated', 'domain',
        'stix_created', 'stix_modified',
    ]
    placeholders = ', '.join(['%s'] * len(columns))
    sql = (
        f'INSERT INTO data_components ({", ".join(columns)}) '
        f'VALUES ({placeholders}) '
        f'RETURNING id, stix_id'
    )

    count = 0
    for dc in data_components:
        ds_stix_id = dc.get('data_source_stix_id', '')
        data_source_uuid = stix_id_to_uuid.get(ds_stix_id) if ds_stix_id else None
        values = [
            dc.get('stix_id'),
            dc.get('name'),
            dc.get('description'),
            data_source_uuid,
            dc.get('is_revoked'),
            dc.get('is_deprecated'),
            dc.get('domain'),
            dc.get('stix_created'),
            dc.get('stix_modified'),
        ]
        cur.execute(sql, values)  # type: ignore[arg-type]
        row = cur.fetchone()
        if row and dc.get('stix_id'):
            stix_id_to_uuid[dc['stix_id']] = str(row[0])
        count += 1
    return count


# ---------------------------------------------------------------------------
# Sector insertion
# ---------------------------------------------------------------------------

def _insert_sectors(
    cur: psycopg.Cursor,
    sector_list: list[dict[str, str]],
) -> dict[str, str]:
    """Insert sectors and return a name -> UUID mapping.

    Args:
        cur: Active database cursor.
        sector_list: List of {name, slug} dicts from get_sector_list().

    Returns:
        Dict mapping sector name to its database UUID.
    """
    sql = (
        'INSERT INTO sectors (name, slug) VALUES (%s, %s) '
        'RETURNING id, name'
    )
    sector_name_to_uuid: dict[str, str] = {}
    for sector in sector_list:
        cur.execute(sql, [sector['name'], sector['slug']])  # type: ignore[arg-type]
        row = cur.fetchone()
        if row:
            sector_name_to_uuid[sector['name']] = str(row[0])
    return sector_name_to_uuid


def _insert_group_sectors(
    cur: psycopg.Cursor,
    sector_assignments: list[dict[str, Any]],
    attack_id_to_uuid: dict[str, str],
    sector_name_to_uuid: dict[str, str],
) -> int:
    """Insert group_sectors junction rows.

    Args:
        cur: Active database cursor.
        sector_assignments: Output of extract_sectors() — each has
            group_attack_id, sector_name, matched_keywords, source.
        attack_id_to_uuid: Mapping from threat group attack_id to DB UUID.
        sector_name_to_uuid: Mapping from sector name to DB UUID.

    Returns:
        Number of rows inserted.
    """
    sql = (
        'INSERT INTO group_sectors (group_id, sector_id, source, matched_keywords) '
        'VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING'
    )
    skipped = 0
    inserted = 0
    for row in sector_assignments:
        group_uuid = attack_id_to_uuid.get(row['group_attack_id'])
        sector_uuid = sector_name_to_uuid.get(row['sector_name'])
        if not group_uuid or not sector_uuid:
            skipped += 1
            continue
        cur.execute(sql, [group_uuid, sector_uuid, row['source'], row['matched_keywords']])  # type: ignore[arg-type]
        inserted += 1
    if skipped:
        print(f'  Warning: skipped {skipped} group_sectors rows (unresolved ids)')
    return inserted


# ---------------------------------------------------------------------------
# seed_metadata
# ---------------------------------------------------------------------------

def _write_seed_metadata(
    cur: psycopg.Cursor,
    attack_version: str,
    stix_hashes: dict[str, str],
    entity_counts: dict[str, int],
    duration_ms: int,
) -> None:
    """Write one row per seeded domain to seed_metadata.

    Args:
        cur: Active database cursor.
        attack_version: ATT&CK version string.
        stix_hashes: Dict of domain -> SHA-256 hex digest.
        entity_counts: Dict of table -> row count.
        duration_ms: Total seed duration in milliseconds.
    """
    sql = """
        INSERT INTO seed_metadata
            (attack_version, domain, stix_bundle_hash, source_url,
             entity_counts, seed_duration_ms, seeded_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    for domain_key, hash_val in stix_hashes.items():
        cur.execute(sql, [  # type: ignore[arg-type]
            attack_version,
            domain_key,
            hash_val,
            _STIX_DOMAINS[domain_key]['url'],
            json.dumps(entity_counts),
            duration_ms,
            'seed.py',
        ])


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def _print_summary(
    entity_counts: dict[str, int],
    rel_counts: dict[str, int],
    duration_ms: int,
    attack_version: str,
) -> None:
    """Print a human-readable seeding summary.

    Args:
        entity_counts: Entity table -> row count.
        rel_counts: Relationship table -> row count.
        duration_ms: Total duration in milliseconds.
        attack_version: ATT&CK version string.
    """
    print()
    print(f'ATT&CK version : {attack_version}')
    print(f'Duration       : {duration_ms:,} ms')
    print()
    print('Entities:')
    for table, count in entity_counts.items():
        print(f'  {table:<25} {count:>6,}')
    print()
    print('Relationships:')
    for table, count in rel_counts.items():
        print(f'  {table:<35} {count:>6,}')
    print()
    total_entities = sum(entity_counts.values())
    total_rels = sum(rel_counts.values())
    print(f'Total entities : {total_entities:,}')
    print(f'Total rels     : {total_rels:,}')


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def main() -> None:
    """Orchestrate schema setup, data extraction, insertion, and verification."""
    args = _parse_args()

    db_url = os.environ.get('DATABASE_URL', _DEFAULT_DB_URL)

    _safety_check(db_url, args.confirm_destructive)

    # Import extraction modules — support both `python seed/seed.py` (script)
    # and `python -m seed.seed` (module) invocations.
    _seed_dir = str(Path(__file__).parent)
    if _seed_dir not in sys.path:
        sys.path.insert(0, _seed_dir)

    from extract import extract_all  # type: ignore[import-not-found]
    from sector_extractor import extract_sectors, get_sector_list  # type: ignore[import-not-found]

    # Download / verify STIX bundles for all domains
    stix_hashes: dict[str, str] = {}
    for domain_key, domain_cfg in _STIX_DOMAINS.items():
        stix_path = domain_cfg['path']
        if args.update:
            stix_hashes[domain_key] = _download_stix(stix_path, domain_cfg['url'])
        else:
            if not Path(stix_path).exists():
                print(f'WARNING: STIX file not found for {domain_key} at {stix_path}, skipping.')
                continue
            stix_hashes[domain_key] = _hash_file(stix_path)
            print(f'Using existing {domain_key} STIX  sha256={stix_hashes[domain_key][:16]}...')

    # Extract version from first available domain (all share the same ATT&CK release)
    first_domain = next(iter(stix_hashes))
    attack_version = _extract_attack_version(_STIX_DOMAINS[first_domain]['path'])
    print(f'ATT&CK version: {attack_version}')

    # Extract and merge data from all available domains
    print('Extracting ATT&CK data from all domains ...')
    t0 = time.monotonic()

    # Merge strategy: concatenate entity lists, deduplicate groups/software by stix_id
    merged_data: dict[str, list[dict[str, Any]]] = {}
    seen_stix_ids: dict[str, set[str]] = {}  # table -> set of stix_ids already seen

    for domain_key in stix_hashes:
        stix_path = _STIX_DOMAINS[domain_key]['path']
        print(f'  Extracting {domain_key} ...')
        data = extract_all(stix_path, domain=domain_key)
        for key, entities in data.items():
            if key not in merged_data:
                merged_data[key] = []
                seen_stix_ids[key] = set()
            # Deduplicate entities that span domains (groups, software, campaigns)
            # by stix_id — keep the first occurrence
            # Skip entities with empty attack_id (deprecated objects without external IDs)
            for entity in entities:
                if 'attack_id' in entity and not entity['attack_id']:
                    continue
                sid = entity.get('stix_id')
                if sid and sid in seen_stix_ids[key]:
                    continue
                if sid:
                    seen_stix_ids[key].add(sid)
                merged_data[key].append(entity)

    data = merged_data
    sector_assignments = extract_sectors(
        data['threat_groups'],
        sectors_path=str(Path(__file__).parent / 'sectors.json'),
    )
    sector_list = get_sector_list(
        sectors_path=str(Path(__file__).parent / 'sectors.json'),
    )

    print(
        f'  tactics={len(data["tactics"])}'
        f'  techniques={len(data["techniques"])}'
        f'  groups={len(data["threat_groups"])}'
        f'  software={len(data["attack_software"])}'
        f'  mitigations={len(data["mitigations"])}'
        f'  campaigns={len(data["campaigns"])}'
        f'  data_sources={len(data["data_sources"])}'
        f'  data_components={len(data["data_components"])}'
    )

    print('Connecting to database ...')
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            print('Running schema.sql ...')
            _run_schema(cur, _SCHEMA_PATH)

            print('Inserting entities ...')
            stix_id_to_uuid: dict[str, str] = {}

            # a. Tactics
            tactic_cols = [
                'stix_id', 'attack_id', 'name', 'description', 'url',
                'sort_order', 'domain', 'stix_created', 'stix_modified',
            ]
            n_tactics = _insert_entities(
                cur, 'tactics', data['tactics'], tactic_cols, stix_id_to_uuid,
            )
            print(f'  tactics           : {n_tactics:,}')

            # b. Techniques (parent first, then sub-techniques)
            n_techniques = _insert_techniques(
                cur, data['techniques'], stix_id_to_uuid,
            )
            print(f'  techniques        : {n_techniques:,}')

            # c. Threat groups
            group_cols = [
                'stix_id', 'attack_id', 'name', 'description', 'url',
                'aliases', 'is_revoked', 'is_deprecated', 'domain',
                'stix_created', 'stix_modified',
            ]
            n_groups = _insert_entities(
                cur, 'threat_groups', data['threat_groups'], group_cols, stix_id_to_uuid,
            )
            print(f'  threat_groups     : {n_groups:,}')

            # d. Attack software
            software_cols = [
                'stix_id', 'attack_id', 'name', 'description', 'url',
                'type', 'platforms', 'aliases', 'is_revoked', 'is_deprecated',
                'domain', 'stix_created', 'stix_modified',
            ]
            n_software = _insert_entities(
                cur, 'attack_software', data['attack_software'], software_cols, stix_id_to_uuid,
            )
            print(f'  attack_software   : {n_software:,}')

            # e. Mitigations
            mitigation_cols = [
                'stix_id', 'attack_id', 'name', 'description', 'url',
                'is_revoked', 'is_deprecated', 'domain',
                'stix_created', 'stix_modified',
            ]
            n_mitigations = _insert_entities(
                cur, 'mitigations', data['mitigations'], mitigation_cols, stix_id_to_uuid,
            )
            print(f'  mitigations       : {n_mitigations:,}')

            # f. Campaigns
            campaign_cols = [
                'stix_id', 'attack_id', 'name', 'description', 'url',
                'aliases', 'first_seen', 'last_seen',
                'is_revoked', 'is_deprecated', 'domain',
                'stix_created', 'stix_modified',
            ]
            n_campaigns = _insert_entities(
                cur, 'campaigns', data['campaigns'], campaign_cols, stix_id_to_uuid,
            )
            print(f'  campaigns         : {n_campaigns:,}')

            # g. Data sources
            ds_cols = [
                'stix_id', 'attack_id', 'name', 'description', 'url',
                'is_revoked', 'is_deprecated', 'domain',
                'stix_created', 'stix_modified',
            ]
            n_data_sources = _insert_entities(
                cur, 'data_sources', data['data_sources'], ds_cols, stix_id_to_uuid,
            )
            print(f'  data_sources      : {n_data_sources:,}')

            # h. Data components (resolves data_source_id via stix_id mapping)
            n_data_components = _insert_data_components(
                cur, data['data_components'], stix_id_to_uuid,
            )
            print(f'  data_components   : {n_data_components:,}')

            # i. Sectors
            sector_name_to_uuid = _insert_sectors(cur, sector_list)
            print(f'  sectors           : {len(sector_name_to_uuid):,}')

            # Build attack_id -> UUID for threat groups (needed for group_sectors)
            attack_id_to_uuid: dict[str, str] = {
                g['attack_id']: stix_id_to_uuid[g['stix_id']]
                for g in data['threat_groups']
                if g.get('attack_id') and g.get('stix_id') and g['stix_id'] in stix_id_to_uuid
            }

            print('Inserting relationships ...')

            # technique_tactics
            n_tt = _insert_relationships(
                cur, 'technique_tactics',
                data['technique_tactics'],
                'technique_id', 'tactic_id',
                'technique_stix_id', 'tactic_stix_id',
                stix_id_to_uuid,
            )
            print(f'  technique_tactics          : {n_tt:,}')

            # group_techniques
            n_gt = _insert_relationships(
                cur, 'group_techniques',
                data['group_techniques'],
                'group_id', 'technique_id',
                'group_stix_id', 'technique_stix_id',
                stix_id_to_uuid,
                extra_cols=['description'],
            )
            print(f'  group_techniques           : {n_gt:,}')

            # group_software
            n_gs = _insert_relationships(
                cur, 'group_software',
                data['group_software'],
                'group_id', 'software_id',
                'group_stix_id', 'software_stix_id',
                stix_id_to_uuid,
                extra_cols=['description'],
            )
            print(f'  group_software             : {n_gs:,}')

            # software_techniques
            n_st = _insert_relationships(
                cur, 'software_techniques',
                data['software_techniques'],
                'software_id', 'technique_id',
                'software_stix_id', 'technique_stix_id',
                stix_id_to_uuid,
                extra_cols=['description'],
            )
            print(f'  software_techniques        : {n_st:,}')

            # mitigation_techniques
            n_mt = _insert_relationships(
                cur, 'mitigation_techniques',
                data['mitigation_techniques'],
                'mitigation_id', 'technique_id',
                'mitigation_stix_id', 'technique_stix_id',
                stix_id_to_uuid,
                extra_cols=['description'],
            )
            print(f'  mitigation_techniques      : {n_mt:,}')

            # technique_data_components
            n_tdc = _insert_relationships(
                cur, 'technique_data_components',
                data['technique_data_components'],
                'technique_id', 'data_component_id',
                'technique_stix_id', 'data_component_stix_id',
                stix_id_to_uuid,
            )
            print(f'  technique_data_components  : {n_tdc:,}')

            # campaign_techniques
            n_ct = _insert_relationships(
                cur, 'campaign_techniques',
                data['campaign_techniques'],
                'campaign_id', 'technique_id',
                'campaign_stix_id', 'technique_stix_id',
                stix_id_to_uuid,
                extra_cols=['description'],
            )
            print(f'  campaign_techniques        : {n_ct:,}')

            # campaign_software
            n_cs = _insert_relationships(
                cur, 'campaign_software',
                data['campaign_software'],
                'campaign_id', 'software_id',
                'campaign_stix_id', 'software_stix_id',
                stix_id_to_uuid,
                extra_cols=['description'],
            )
            print(f'  campaign_software          : {n_cs:,}')

            # group_campaigns
            n_gc = _insert_relationships(
                cur, 'group_campaigns',
                data['group_campaigns'],
                'group_id', 'campaign_id',
                'group_stix_id', 'campaign_stix_id',
                stix_id_to_uuid,
                extra_cols=['description'],
            )
            print(f'  group_campaigns            : {n_gc:,}')

            # group_sectors
            n_group_sectors = _insert_group_sectors(
                cur, sector_assignments, attack_id_to_uuid, sector_name_to_uuid,
            )
            print(f'  group_sectors              : {n_group_sectors:,}')

            duration_ms = int((time.monotonic() - t0) * 1000)

            entity_counts = {
                'tactics': n_tactics,
                'techniques': n_techniques,
                'threat_groups': n_groups,
                'attack_software': n_software,
                'mitigations': n_mitigations,
                'campaigns': n_campaigns,
                'data_sources': n_data_sources,
                'data_components': n_data_components,
                'sectors': len(sector_name_to_uuid),
            }
            rel_counts = {
                'technique_tactics': n_tt,
                'group_techniques': n_gt,
                'group_software': n_gs,
                'software_techniques': n_st,
                'mitigation_techniques': n_mt,
                'technique_data_components': n_tdc,
                'campaign_techniques': n_ct,
                'campaign_software': n_cs,
                'group_campaigns': n_gc,
                'group_sectors': n_group_sectors,
            }

            _write_seed_metadata(
                cur, attack_version, stix_hashes, entity_counts, duration_ms,
            )

            conn.commit()

    _print_summary(entity_counts, rel_counts, duration_ms, attack_version)
    print('Seed complete.')


if __name__ == '__main__':
    main()
