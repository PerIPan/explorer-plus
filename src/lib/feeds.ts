/**
 * The ingestion sources /cti/feed-status renders, in display order.
 *
 * Lifted out of the view because the sidebar quotes the COUNT: a number in the
 * nav that disagrees with the number of cards on the page is the same drift the
 * API catalogue guard exists to stop, and here it is avoidable outright by
 * having one array. `FeedStatus` maps over it; the sidebar takes `.length`.
 *
 * Its own module rather than `site.ts`: that one is imported by `middleware.ts`
 * and runs on the edge for every request, and it deliberately has no imports and
 * nothing in it but scalars.
 *
 * NOT derived from `feed_sync_log` on purpose — the page lists the feeds that are
 * SUPPOSED to run, so a source that has never logged a sync still shows up as
 * pending instead of silently vanishing from the list.
 */
export const FEED_SOURCES = [
  'otx', 'abuse_ch', 'cisa_kev', 'rss',
  'nvd', 'virustotal',
  'cve_delta', 'cve_products',
  'epss', 'osv', 'csf',
  'ghsa', 'ghsa_delta', 'sigma', 'atomic',
  'matview_refresh', 'd3fend',
  'site_health', 'scf', 'cti_heat_refresh',
] as const;
