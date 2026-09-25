import { z } from 'zod';
import { PLATFORMS, SECTOR_SLUGS } from '../../../../src/lib/profile-options';

export const VALID_DOMAINS = ['enterprise-attack', 'mobile-attack', 'ics-attack', 'atlas-attack'] as const;
export const domainSchema = z.enum(VALID_DOMAINS).optional();

export const attackIdSchema = z.string().regex(/^(AML\.)?(TA|T|G|S|M|C|DS)\d{4}(\.\d{3})?$/);
export const slugSchema = z.string().regex(/^[a-z0-9-]+$/);
export const searchSchema = z.string().min(3).max(200);

// Shared `version` filter param (substring/text match on free-text version
// ranges). Trims, then treats an empty string as absent (no filter) rather
// than a validation error — so `?version=` never 400s the whole request and
// all surfaces normalize identically.
export const versionParam = z.preprocess(
  (v) => {
    const s = typeof v === 'string' ? v.trim() : v;
    return s === '' ? undefined : s;
  },
  z.string().min(1).max(100).optional(),
);

// Public list endpoints. `limit` stays at 5000 because existing views
// (GroupsList, TechniquesList, CampaignsList, etc.) depend on loading the
// full collection for client-side Fuse.js filtering. `page` is tightened to
// 100 (was 1000) — there's no legitimate reason to ask for the 1000th page
// of anything in our datasets, and the combination `limit=5000&page=1000`
// was the real exfiltration vector the audit flagged.
export const paginationSchema = z.object({
  page: z.coerce.number().int().positive().max(100).default(1),
  limit: z.coerce.number().int().positive().max(5000).default(50),
  sort: z.string().optional(),
  order: z.enum(['asc', 'desc']).default('asc'),
});

// Built from the zod-free list in src/lib/profile-options.ts so the Threat
// Profile pickers can read the same values without pulling zod into the
// client bundle. That module is the single source of truth; this is the
// validator over it.
export const platformSchema = z.enum(PLATFORMS);

export const softwareTypeSchema = z.enum(['malware', 'tool']);

export const exportSchema = z.object({
  entityType: z.enum([
    'techniques',
    'groups',
    'software',
    'mitigations',
    'campaigns',
    'data_sources',
    'tactics',
    'sectors',
    'owasp',
  ]),
  format: z.enum(['csv', 'json']).default('json'),
});

export type PaginationParams = z.infer<typeof paginationSchema>;
export type { Platform } from '../../../../src/lib/profile-options';
export type SoftwareType = z.infer<typeof softwareTypeSchema>;
export type ExportParams = z.infer<typeof exportSchema>;

export const sortKeySchema = z.enum(['io', 'rp', 'kev', 'cv', 'lift']).default('kev');
export const sectorSlugSchema = z.enum(SECTOR_SLUGS);

/**
 * Comma-separated `?platforms=Windows,Linux`.
 *
 * The Threat Profile panel collects platforms as a MULTI-select (a binding
 * user requirement) and `submissionSchema.platforms` in
 * src/lib/profile-submit-schema.mjs is already an array — a single scalar
 * `platform` here could only ever have carried the first of the visitor's
 * answers. The bound is 24, the same `.max(24)` that module's `slugList`
 * uses, so the assembler and the telemetry sink agree on how many a
 * submission may carry.
 *
 * An empty value (`?platforms=`) preprocesses to `undefined` — absent, not a
 * 400 — matching `versionParam` above. An UNRECOGNISED member still 400s,
 * exactly as the old scalar `platform` did: `platformSchema` is applied to
 * every element.
 */
export const platformsParam = z.preprocess(
  (v) => {
    if (typeof v !== 'string') return v;
    const parts = v.split(',').map((s) => s.trim()).filter((s) => s !== '');
    return parts.length > 0 ? parts : undefined;
  },
  z.array(platformSchema).max(24).optional(),
);

export const profileQuerySchema = z.object({
  sector: sectorSlugSchema.optional(),
  platforms: platformsParam,
  sort: sortKeySchema,
});
