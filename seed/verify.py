"""Post-seed verification — checks entity counts and referential integrity."""

import os
import psycopg


EXPECTED_RANGES = {
    'tactics': (10, 20),
    'techniques': (600, 1200),
    'threat_groups': (100, 300),
    'attack_software': (500, 1200),
    'mitigations': (30, 400),
    'campaigns': (10, 200),
    'data_sources': (20, 100),
    'data_components': (50, 300),
    'sectors': (5, 30),
}

RELATIONSHIP_TABLES = [
    'group_techniques', 'group_software', 'software_techniques',
    'mitigation_techniques', 'technique_tactics', 'technique_data_components',
    'campaign_techniques', 'campaign_software', 'group_campaigns', 'group_sectors',
]


def verify(database_url: str | None = None) -> bool:
    url = database_url or os.environ.get('DATABASE_URL', 'postgresql://postgres@localhost:5432/mitre_attack')
    ok = True

    with psycopg.connect(url) as conn:
        cur = conn.cursor()

        print('\n=== Post-seed verification ===\n')

        # Entity counts
        print('Entity counts:')
        for table, (lo, hi) in EXPECTED_RANGES.items():
            cur.execute(f'SELECT count(*) FROM {table}')
            count = cur.fetchone()[0]
            status = 'OK' if lo <= count <= hi else 'WARN'
            if status == 'WARN':
                ok = False
            print(f'  {table:25s} {count:>6d}  [{status}]  (expected {lo}-{hi})')

        # Relationship counts
        print('\nRelationship counts:')
        for table in RELATIONSHIP_TABLES:
            cur.execute(f'SELECT count(*) FROM {table}')
            count = cur.fetchone()[0]
            status = 'OK' if count > 0 else 'WARN'
            if count == 0:
                ok = False
            print(f'  {table:30s} {count:>6d}  [{status}]')

        # Seed metadata
        cur.execute('SELECT count(*) FROM seed_metadata')
        meta_count = cur.fetchone()[0]
        print(f'\nSeed metadata entries: {meta_count}  [{"OK" if meta_count > 0 else "WARN"}]')

        if meta_count > 0:
            cur.execute('SELECT attack_version, domain, seeded_at, seed_duration_ms FROM seed_metadata ORDER BY seeded_at DESC LIMIT 1')
            row = cur.fetchone()
            print(f'  Latest: v{row[0]} ({row[1]}) seeded at {row[2]} in {row[3]}ms')

        # Orphan check — relationships pointing to missing entities
        print('\nOrphan checks:')
        orphan_checks = [
            ('group_techniques', 'group_id', 'threat_groups'),
            ('group_techniques', 'technique_id', 'techniques'),
            ('software_techniques', 'software_id', 'attack_software'),
            ('software_techniques', 'technique_id', 'techniques'),
            ('campaign_techniques', 'campaign_id', 'campaigns'),
            ('technique_data_components', 'data_component_id', 'data_components'),
        ]
        for rel_table, fk_col, parent_table in orphan_checks:
            cur.execute(f'''
                SELECT count(*) FROM {rel_table} r
                LEFT JOIN {parent_table} p ON p.id = r.{fk_col}
                WHERE p.id IS NULL
            ''')
            orphans = cur.fetchone()[0]
            status = 'OK' if orphans == 0 else 'WARN'
            if orphans > 0:
                ok = False
            print(f'  {rel_table}.{fk_col} → {parent_table}: {orphans} orphans  [{status}]')

        print(f'\n{"PASSED" if ok else "FAILED"}\n')

    return ok


if __name__ == '__main__':
    import sys
    success = verify()
    sys.exit(0 if success else 1)
