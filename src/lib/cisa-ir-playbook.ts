/**
 * CISA incident-response starting points, keyed by ATT&CK tactic.
 *
 * Source: CISA, *Cybersecurity Incident & Vulnerability Response Playbooks*
 * (November 2021), Table 1 — "Example Adversary Tactics, Techniques, and
 * Relevant Log and Event Data". A US federal government work: public domain,
 * marked TLP:CLEAR, distributable without restriction.
 *
 * WHY THIS IS HERE AND NOT DERIVED FROM OUR OWN DATA
 *
 * We can already roll a tactic up to its ATT&CK data sources
 * (tactic -> technique_tactics -> technique_data_components -> data_sources,
 * 3,333 link rows). The problem is that the answer is not useful: measured
 * 2026-10-02, TA0003 Persistence reaches 25 of the 42 data sources across 113
 * techniques, TA0002 21, TA0006 19. "Check 25 of 42 log sources" is not a
 * starting point.
 *
 * CISA prioritises to 3-6 and, more importantly, names INDICATOR TYPES —
 * LSASS reads, beaconing from hosts not meant to be internet-facing,
 * workstation-to-workstation traffic — which exist nowhere in our schema at
 * any level. The two vocabularies also barely overlap: CISA names where you GO
 * (products, vantage points), ATT&CK names what you COLLECT (telemetry
 * classes). For TA0001 CISA says email / web proxy / server application logs /
 * IDS-IPS where our rollup says Process / Network Traffic / File /
 * Application Log.
 *
 * WHY IDS AND NEVER NAMES
 *
 * This table stores technique IDs only. Names are resolved at render time from
 * the tactic page's own fetched technique list, so:
 *
 *   - a technique renamed upstream shows OUR current name, not a stale copy
 *   - a revoked or deprecated technique is already filtered out by the route,
 *     so it fails to resolve and is simply not rendered — rather than this
 *     strip becoming the last place on the site still advertising it
 *   - a technique re-mapped to other tactics cannot have this strip
 *     contradicting the technique list on the same page
 *   - a typo degrades to a lookup miss instead of a confidently wrong label
 *
 * That is not hypothetical caution. The last ATT&CK ingest renamed TA0005
 * "Defense Evasion" to "Stealth" and added TA0112 "Defense Impairment";
 * enterprise now has 15 tactics, 57 across all domains. An earlier draft of
 * this feature hard-coded "Defense Evasion" and was stale before it shipped.
 *
 * `scripts/../seed/verify.py` asserts every id below still resolves and is not
 * revoked, so an upstream change surfaces on the next ingest rather than never.
 *
 * Covers 7 of 57 tactic pages. Enterprise only — the ICS and mobile
 * "Lateral Movement" tactics have different attack_ids and get nothing, though
 * the advice largely applies.
 */

export interface CisaIrRow {
  /** ATT&CK tactic attack_id, e.g. TA0001. */
  readonly tacticId: string;
  /** Technique attack_ids CISA lists as common for this tactic. Names are NOT stored. */
  readonly techniqueIds: readonly string[];
  /** Log and event sources, as CISA words them. */
  readonly logSources: readonly string[];
  /** Indicator types to hunt for at this stage. */
  readonly indicators: readonly string[];
}

const ROWS = [
  {
    tacticId: 'TA0001',
    techniqueIds: ['T1566', 'T1189', 'T1190', 'T1133'],
    logSources: ['Email', 'Web proxy', 'Server application logs', 'IDS/IPS'],
    indicators: [
      'Phishing, redirect and payload servers (domains and IP addresses)',
      'Delivery mechanisms — lures, macros, downloaders, droppers',
      'Compromised credentials',
      'Web shells',
    ],
  },
  {
    tacticId: 'TA0002',
    techniqueIds: ['T1059', 'T1203'],
    logSources: [
      'Host event logs',
      'Windows event logs',
      'Sysmon',
      'Anti-malware',
      'EDR',
      'PowerShell logs',
    ],
    indicators: [
      'Invocation of a command or scripting interpreter',
      'Exploitation',
      'API calls',
      'Tools, malware, payloads',
    ],
  },
  {
    tacticId: 'TA0003',
    techniqueIds: ['T1098', 'T1053', 'T1078'],
    logSources: ['Host event logs', 'Authentication logs', 'Registry'],
    indicators: ['Scheduled tasks', 'Registry keys', 'Autoruns'],
  },
  {
    tacticId: 'TA0006',
    techniqueIds: ['T1110', 'T1556', 'T1557'],
    logSources: [
      'Authentication logs',
      'Domain controller logs',
      'Network traffic monitoring',
    ],
    indicators: [
      'LSASS reads',
      'Command or scripting interpreters accessing LSASS',
    ],
  },
  {
    tacticId: 'TA0008',
    techniqueIds: ['T1210', 'T1563', 'T1072'],
    logSources: ['Internal network logs', 'Host event logs', 'Application logs'],
    indicators: [
      'Mismatch of users and applications or credentials',
      'Workstation-to-workstation communication',
      'Beaconing from hosts not intended to be internet-accessible',
    ],
  },
  {
    tacticId: 'TA0010',
    techniqueIds: ['T1041', 'T1048'],
    logSources: [
      'Firewall',
      'Web proxy',
      'DNS',
      'Network traffic',
      'Cloud activity logs',
      'IDS/IPS',
    ],
    indicators: ['Domains', 'URLs', 'IP addresses', 'IDS/IPS signatures'],
  },
  {
    tacticId: 'TA0011',
    techniqueIds: ['T1071', 'T1572'],
    logSources: [
      'Firewall',
      'Web proxy',
      'DNS',
      'Network traffic',
      'Cloud activity logs',
      'IDS/IPS',
    ],
    indicators: ['C2 domains', 'IP addresses'],
  },
] as const satisfies readonly CisaIrRow[];

export const CISA_IR_PLAYBOOK: ReadonlyMap<string, CisaIrRow> = new Map(
  ROWS.map((r) => [r.tacticId, r]),
);

/** How many tactics CISA's table covers — rendered in the attribution line. */
export const CISA_IR_TACTIC_COUNT = ROWS.length;

/** Citation, kept beside the data so the two cannot drift apart. */
export const CISA_IR_SOURCE = {
  title: 'Cybersecurity Incident & Vulnerability Response Playbooks',
  publisher: 'CISA',
  published: 'November 2021',
  table: 'Table 1',
  url: 'https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf',
} as const;
