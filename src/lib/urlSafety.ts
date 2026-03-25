export function isSafeUrl(url: string): boolean {
  try { const u = new URL(url); return ['http:', 'https:'].includes(u.protocol); }
  catch { return false; }
}

const CTID_BASE = 'https://center-for-threat-informed-defense.github.io/mappings-explorer/external';

const CLOUD_VERSIONS: Record<string, string> = {
  azure: 'azure-04.26.2025',
  gcp: 'gcp-03.06.2025',
};

export function ctidCloudUrl(provider: string, controlId: string): string {
  const version = CLOUD_VERSIONS[provider] ?? provider;
  return `${CTID_BASE}/${encodeURIComponent(provider)}/attack-16.1/domain-enterprise/${version}/capability-groups/${encodeURIComponent(controlId)}/`;
}

export function ctidVerisUrl(verisId: string): string {
  return `${CTID_BASE}/veris/attack-16.1/domain-enterprise/veris-1.4.0/capability-groups/${encodeURIComponent(verisId)}/`;
}
