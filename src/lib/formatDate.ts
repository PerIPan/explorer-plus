/** Format an ISO date string for display, handling timezone-safe parsing. */
export function formatDate(iso: string | null): string {
  if (!iso) return '—';
  // Append time to date-only strings to avoid UTC midnight → previous day in negative-UTC locales
  const safe = iso.includes('T') ? iso : `${iso}T00:00:00`;
  return new Date(safe).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}
