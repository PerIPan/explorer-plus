const BASE_URL = '/api/v1';

/**
 * Generic fetch wrapper for the MITRE ATT&CK Explorer API.
 * Constructs URL with query params, throws on non-OK responses.
 */
export async function apiFetch<T>(
  path: string,
  params?: Record<string, string>
): Promise<T> {
  const url = new URL(`${BASE_URL}${path}`, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== '') url.searchParams.set(k, v);
    });
  }
  const res = await fetch(url.toString());
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new Error((err as { error?: string }).error ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}
