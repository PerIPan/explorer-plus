import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import type {
  DashboardData,
  PaginatedResponse,
  Technique,
  Group,
  Software,
  Campaign,
  DataSource,
  Mitigation,
  Tactic,
  Sector,
  SearchResponse,
  MatrixData,
  GraphData,
  ThreatReport,
  IocEntry,
  SigmaRule,
  AtomicTest,
  FeedSyncStatus,
  TechniqueIntelligence,
  FrameworkData,
  NistControlSummary,
  EngageSummary,
  ReactAction,
  ExternalActor,
  CveEntry,
  CveDetail,
} from '../lib/types';

// ── List / paginated hooks ────────────────────────────────────────────────────

const EMPTY_PARAMS: Record<string, string> = {};

export function useDashboard(params: Record<string, string> = EMPTY_PARAMS) {
  return useQuery({
    queryKey: ['dashboard', params],
    queryFn: () => apiFetch<DashboardData>('/dashboard', params),
  });
}

export function useTechniques(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['techniques', params],
    queryFn: () => apiFetch<PaginatedResponse<Technique>>('/techniques', params),
  });
}

export function useGroups(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['groups', params],
    queryFn: () => apiFetch<PaginatedResponse<Group>>('/groups', params),
  });
}

export function useSoftware(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['software', params],
    queryFn: () => apiFetch<PaginatedResponse<Software>>('/software', params),
  });
}

export function useCampaigns(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['campaigns', params],
    queryFn: () => apiFetch<PaginatedResponse<Campaign>>('/campaigns', params),
  });
}

export function useDataSources(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['data-sources', params],
    queryFn: () =>
      apiFetch<PaginatedResponse<DataSource>>('/data-sources', params),
  });
}

export function useMitigations(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['mitigations', params],
    queryFn: () =>
      apiFetch<PaginatedResponse<Mitigation>>('/mitigations', params),
  });
}

export function useTactics(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['tactics', params],
    queryFn: () => apiFetch<PaginatedResponse<Tactic>>('/tactics', params),
  });
}

export function useSectors(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['sectors', params],
    queryFn: () => apiFetch<{ data: Sector[] }>('/sectors', params),
  });
}

// ── Detail hooks ──────────────────────────────────────────────────────────────

export function useTechnique(attackId: string, params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['technique', attackId, params],
    queryFn: () => apiFetch<Technique>(`/techniques/${attackId}`, params),
    enabled: Boolean(attackId),
  });
}

export function useGroup(attackId: string) {
  return useQuery({
    queryKey: ['group', attackId],
    queryFn: () => apiFetch<Group>(`/groups/${attackId}`),
    enabled: Boolean(attackId),
  });
}

export function useSoftwareDetail(attackId: string) {
  return useQuery({
    queryKey: ['software-detail', attackId],
    queryFn: () => apiFetch<Software>(`/software/${attackId}`),
    enabled: Boolean(attackId),
  });
}

export function useCampaign(attackId: string) {
  return useQuery({
    queryKey: ['campaign', attackId],
    queryFn: () => apiFetch<Campaign>(`/campaigns/${attackId}`),
    enabled: Boolean(attackId),
  });
}

export function useDataSource(attackId: string) {
  return useQuery({
    queryKey: ['data-source', attackId],
    queryFn: () => apiFetch<DataSource>(`/data-sources/${attackId}`),
    enabled: Boolean(attackId),
  });
}

export function useMitigation(attackId: string) {
  return useQuery({
    queryKey: ['mitigation', attackId],
    queryFn: () => apiFetch<Mitigation>(`/mitigations/${attackId}`),
    enabled: Boolean(attackId),
  });
}

export function useTactic(attackId: string) {
  return useQuery({
    queryKey: ['tactic', attackId],
    queryFn: () => apiFetch<Tactic>(`/tactics/${attackId}`),
    enabled: Boolean(attackId),
  });
}

// ── Special hooks ─────────────────────────────────────────────────────────────

export function useSearch(q: string) {
  return useQuery({
    queryKey: ['search', q],
    queryFn: () => apiFetch<SearchResponse>('/search', { q }),
    enabled: q.trim().length >= 3,
  });
}

export function useMatrix(params?: Record<string, string>) {
  return useQuery({
    queryKey: ['matrix', params],
    queryFn: async () => {
      const res = await apiFetch<{ data: MatrixData }>('/matrix', params);
      return res.data;
    },
  });
}

export function useRelationships(attackId: string) {
  return useQuery({
    queryKey: ['relationships', attackId],
    queryFn: () => apiFetch<GraphData>(`/relationships/${attackId}`),
    enabled: Boolean(attackId),
  });
}

// ── CTI Feed hooks ─────────────────────────────────────────────────────────────

export function useReports(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['feed-reports', params],
    queryFn: () => apiFetch<PaginatedResponse<ThreatReport>>('/feed/reports', params),
  });
}

export function useIocs(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['feed-iocs', params],
    queryFn: () => apiFetch<PaginatedResponse<IocEntry>>('/feed/iocs', params),
  });
}

export function useSigmaRules(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['feed-sigma', params],
    queryFn: () => apiFetch<PaginatedResponse<SigmaRule>>('/feed/sigma', params),
  });
}

export function useAtomicTests(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['feed-atomic', params],
    queryFn: () => apiFetch<PaginatedResponse<AtomicTest>>('/feed/atomic', params),
  });
}

export function useFeedStatus() {
  return useQuery({
    queryKey: ['feed-status'],
    queryFn: () => apiFetch<{ data: FeedSyncStatus[] }>('/feed/status'),
    refetchInterval: 30_000,
  });
}

export function useIntelligence(attackId: string) {
  return useQuery({
    queryKey: ['intelligence', attackId],
    queryFn: () => apiFetch<TechniqueIntelligence>(`/feed/intelligence/${attackId}`),
    enabled: Boolean(attackId),
  });
}

// ── Framework hooks ─────────────────────────────────────────────────────────────

export function useFrameworks(attackId: string) {
  return useQuery({
    queryKey: ['frameworks', attackId],
    queryFn: () => apiFetch<FrameworkData>(`/frameworks/technique/${attackId}`),
    enabled: Boolean(attackId),
  });
}

export function useNistControls(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['nist-controls', params],
    queryFn: () => apiFetch<PaginatedResponse<NistControlSummary>>('/frameworks/nist', params),
  });
}

export function useEngageActivities(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['engage-activities', params],
    queryFn: () => apiFetch<PaginatedResponse<EngageSummary>>('/frameworks/engage', params),
  });
}

export function useReactActions(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['react-actions', params],
    queryFn: () => apiFetch<PaginatedResponse<ReactAction>>('/frameworks/react', params),
  });
}

// ── CVE hooks ────────────────────────────────────────────────────────────────

export function useCves(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['cves', params],
    queryFn: () => apiFetch<PaginatedResponse<CveEntry>>('/cves', params),
  });
}

export function useCveDetail(cveId: string) {
  return useQuery({
    queryKey: ['cve-detail', cveId],
    queryFn: () => apiFetch<CveDetail>(`/cves/${cveId}`),
    enabled: Boolean(cveId),
  });
}

// ── Extended Intel hooks ───────────────────────────────────────────────────────

export function useExternalActors(params: Record<string, string> = {}) {
  return useQuery({
    queryKey: ['external-actors', params],
    queryFn: () => apiFetch<PaginatedResponse<ExternalActor>>('/external-actors', params),
  });
}

export function useExternalActorByGroup(mitreGroupId: string) {
  return useQuery({
    queryKey: ['external-actor-by-group', mitreGroupId],
    queryFn: () => apiFetch<{ data: ExternalActor[] }>(`/external-actors?mitre_group=${mitreGroupId}&limit=10`),
    enabled: Boolean(mitreGroupId),
  });
}

export function useExternalActorByName(name: string) {
  return useQuery({
    queryKey: ['external-actor-by-name', name],
    queryFn: () => apiFetch<ExternalActor>(`/external-actors/${encodeURIComponent(name)}`),
    enabled: Boolean(name),
  });
}
