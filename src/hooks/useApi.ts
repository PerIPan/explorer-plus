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
} from '../lib/types';

// ── List / paginated hooks ────────────────────────────────────────────────────

export function useDashboard() {
  return useQuery({
    queryKey: ['dashboard'],
    queryFn: () => apiFetch<DashboardData>('/dashboard'),
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
    queryFn: () => apiFetch<PaginatedResponse<Sector>>('/sectors', params),
  });
}

// ── Detail hooks ──────────────────────────────────────────────────────────────

export function useTechnique(attackId: string) {
  return useQuery({
    queryKey: ['technique', attackId],
    queryFn: () => apiFetch<Technique>(`/techniques/${attackId}`),
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
    queryKey: ['software', attackId],
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

export function useMatrix() {
  return useQuery({
    queryKey: ['matrix'],
    queryFn: () => apiFetch<MatrixData>('/matrix'),
  });
}

export function useRelationships(attackId: string) {
  return useQuery({
    queryKey: ['relationships', attackId],
    queryFn: () => apiFetch<GraphData>(`/relationships/${attackId}`),
    enabled: Boolean(attackId),
  });
}
