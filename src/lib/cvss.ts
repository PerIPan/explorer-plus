/**
 * CVSS v3.x vector decoder.
 *
 * Accepts CVSS:3.0/... or CVSS:3.1/... vectors and returns per-metric
 * labels + plain-English explanations. CVSS v4 is intentionally NOT
 * supported — v4 has a completely different metric set (AT, VC, VI, VA,
 * SC, SI, SA, MSI, MSA, …) and deserves its own decoder when we see
 * enough v4 traffic to justify one. For now, v4 vectors return null and
 * consumers should show the raw vector without a decoded breakdown.
 */

export interface CvssMetric {
  key: string;         // e.g. 'AV'
  label: string;       // e.g. 'Attack Vector'
  value: string;       // e.g. 'Network'
  code: string;        // e.g. 'N'
  plainEnglish: string;
}

export interface CvssDecoded {
  version: string;     // e.g. '3.1'
  raw: string;
  metrics: CvssMetric[];
}

const V3_METRICS: Record<string, { label: string; values: Record<string, { value: string; plain: string }> }> = {
  AV: {
    label: 'Attack Vector',
    values: {
      N: { value: 'Network',   plain: 'Exploitable remotely over the internet' },
      A: { value: 'Adjacent',  plain: 'Attacker must be on the local network segment' },
      L: { value: 'Local',     plain: 'Attacker needs local access (shell / console)' },
      P: { value: 'Physical',  plain: 'Attacker needs physical access to the device' },
    },
  },
  AC: {
    label: 'Attack Complexity',
    values: {
      L: { value: 'Low',  plain: 'Reliably exploitable; no special conditions' },
      H: { value: 'High', plain: 'Needs specific conditions outside attacker control' },
    },
  },
  PR: {
    label: 'Privileges Required',
    values: {
      N: { value: 'None', plain: 'No authentication needed' },
      L: { value: 'Low',  plain: 'Needs a regular user account' },
      H: { value: 'High', plain: 'Needs admin / root privileges' },
    },
  },
  UI: {
    label: 'User Interaction',
    values: {
      N: { value: 'None',     plain: 'No user click / action required' },
      R: { value: 'Required', plain: 'Victim must click or trigger an action' },
    },
  },
  S: {
    label: 'Scope',
    values: {
      U: { value: 'Unchanged', plain: 'Exploit stays inside the vulnerable component' },
      C: { value: 'Changed',   plain: 'Exploit escapes the component, affects other systems' },
    },
  },
  C: {
    label: 'Confidentiality',
    values: {
      N: { value: 'None', plain: 'No data disclosure' },
      L: { value: 'Low',  plain: 'Partial / restricted data disclosure' },
      H: { value: 'High', plain: 'Full disclosure of sensitive data' },
    },
  },
  I: {
    label: 'Integrity',
    values: {
      N: { value: 'None', plain: 'No data modification possible' },
      L: { value: 'Low',  plain: 'Some modification, limited scope' },
      H: { value: 'High', plain: 'Full data modification / corruption possible' },
    },
  },
  A: {
    label: 'Availability',
    values: {
      N: { value: 'None', plain: 'No downtime / service impact' },
      L: { value: 'Low',  plain: 'Reduced performance / partial outage' },
      H: { value: 'High', plain: 'Full denial of service' },
    },
  },
};

export function decodeCvssVector(vector: string | null | undefined): CvssDecoded | null {
  if (!vector) return null;
  const m = vector.match(/^CVSS:(3\.[01])\/(.+)$/);
  if (!m) return null;
  const [, version, rest] = m;
  const metrics: CvssMetric[] = [];
  for (const pair of rest.split('/')) {
    const [key, code] = pair.split(':');
    const spec = V3_METRICS[key];
    if (!spec) continue;
    const v = spec.values[code];
    if (!v) continue;
    metrics.push({ key, label: spec.label, value: v.value, code, plainEnglish: v.plain });
  }
  return { version, raw: vector, metrics };
}

export type CvssBadgeVariant = 'pink' | 'orange' | 'yellow' | 'blue' | 'neutral';

export function cvssSeverityFromScore(score: number | null | undefined): { label: string; variant: CvssBadgeVariant } {
  if (score == null) return { label: '—', variant: 'neutral' };
  if (score >= 9.0) return { label: 'CRITICAL', variant: 'pink' };
  if (score >= 7.0) return { label: 'HIGH', variant: 'orange' };
  if (score >= 4.0) return { label: 'MEDIUM', variant: 'yellow' };
  if (score > 0)    return { label: 'LOW', variant: 'blue' };
  return { label: 'NONE', variant: 'neutral' };
}
