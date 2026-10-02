"""Post-seed verification — checks entity counts and referential integrity."""

import os
import psycopg


# Ranges wide enough to catch a broken seed, tight enough to catch a partial
# one. `tactics` and `techniques` were written when this DB held enterprise
# ATT&CK alone; it now holds four domains (enterprise 15 tactics, ICS 12,
# mobile 14, ATLAS 16 = 57, and 1,295 techniques), so both bounds had been
# WARNing on every run since. A harness that always says FAILED reports
# nothing, which is why this is fixed here rather than left as noise.
# A regression to a single domain (15 tactics) still trips the lower bound,
# which is the case worth catching.
EXPECTED_RANGES = {
    'tactics': (40, 80),
    'techniques': (1000, 2000),
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

        # Curated-reference check — src/lib/cisa-ir-playbook.ts hard-codes ATT&CK
        # ids. It stores ids ONLY and resolves names at render time, so a rename
        # is harmless; a REVOKE, a DEPRECATE or a deletion is not — the page
        # would silently stop showing that technique. ATT&CK does all three:
        # the last ingest renamed TA0005 to "Stealth" and added TA0112.
        # Nothing else reads these ids, so without this they would drift
        # unnoticed until someone looked at a tactic page.
        print('\nCurated reference checks (CISA IR playbook):')
        cisa_tactics = ['TA0001', 'TA0002', 'TA0003', 'TA0006', 'TA0008', 'TA0010', 'TA0011']
        cisa_techniques = [
            'T1041', 'T1048', 'T1053', 'T1059', 'T1071', 'T1072', 'T1078',
            'T1098', 'T1110', 'T1133', 'T1189', 'T1190', 'T1203', 'T1210',
            'T1556', 'T1557', 'T1563', 'T1566', 'T1572',
        ]
        # `tactics` carries no is_revoked / is_deprecated columns — only
        # `techniques` does — so the predicate differs per table. Asking for
        # them on tactics raises UndefinedColumn and fails the whole harness.
        for label, table, ids, live_only in (
            ('tactics', 'tactics', cisa_tactics, False),
            ('techniques', 'techniques', cisa_techniques, True),
        ):
            predicate = (
                'AND NOT is_revoked AND NOT is_deprecated' if live_only else ''
            )
            cur.execute(
                f'SELECT attack_id FROM {table} '
                f'WHERE attack_id = ANY(%s) {predicate}',
                (ids,),
            )
            live = {r[0] for r in cur.fetchall()}
            missing = sorted(set(ids) - live)
            status = 'OK' if not missing else 'WARN'
            if missing:
                ok = False
            detail = f' missing/revoked: {", ".join(missing)}' if missing else ''
            print(f'  {label}: {len(live)}/{len(ids)} resolve  [{status}]{detail}')

        print(f'\n{"PASSED" if ok else "FAILED"}\n')

    return ok


if __name__ == '__main__':
    import sys
    success = verify()
    sys.exit(0 if success else 1)
