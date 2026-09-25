import { z } from 'zod';

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

export const platformSchema = z.enum([
  // Enterprise
  // Values verified against production 2026-09-25: every entry matches >=1 live
  // technique. 'Network', 'Google Workspace' and 'Azure AD' were removed (0 live
  // techniques each) and ESXi/Network Devices added (117/100) — they previously 400'd.
  'Windows',
  'Linux',
  'macOS',
  'IaaS',
  'SaaS',
  'Containers',
  'Office Suite',
  'Identity Provider',
  'PRE',
  'ESXi',
  'Network Devices',
  // ICS
  'Field Controller/RTU/PLC/IED',
  'Safety Instrumented System/Protection Relay',
  'Engineering Workstation',
  'Human-Machine Interface',
  'Control Server',
  'Data Historian',
  'Input/Output Server',
  // Mobile
  'Android',
  'iOS',
]);

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
export type Platform = z.infer<typeof platformSchema>;
export type SoftwareType = z.infer<typeof softwareTypeSchema>;
export type ExportParams = z.infer<typeof exportSchema>;

export const sortKeySchema = z.enum(['io', 'rp', 'kev', 'cv', 'lift']).default('kev');
export const sectorSlugSchema = z.enum([
  'defense','education','energy','financial','government','healthcare',
  'manufacturing','media','retail','technology','telecommunications','transportation',
]);
export const profileQuerySchema = z.object({
  sector: sectorSlugSchema.optional(),
  platform: platformSchema.optional(),
  sort: sortKeySchema,
});
