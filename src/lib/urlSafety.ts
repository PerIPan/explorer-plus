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

export function ctidVerisUrl(_verisId: string): string {
  // CTID does not have per-category deep links for VERIS — link to overview
  return `${CTID_BASE}/veris/`;
}

export function sigmaRuleUrl(sigmaId: string): string {
  return `https://grep.app/search?q=${encodeURIComponent(sigmaId)}&filter[repo][0]=SigmaHQ/sigma`;
}

export function reactActionUrl(_actionId: string, title: string): string {
  // Title in DB is already the folder name (e.g. RA_1010_get_access_control_matrix)
  return `https://atc-project.github.io/atc-react/Response_Actions/${encodeURIComponent(title)}/`;
}
