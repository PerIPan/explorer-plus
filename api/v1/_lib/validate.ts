import { z } from 'zod';

export const attackIdSchema = z.string().regex(/^(TA|T|G|S|M|C|DS)\d{4}(\.\d{3})?$/);
export const slugSchema = z.string().regex(/^[a-z0-9-]+$/);
export const searchSchema = z.string().min(3).max(200);

export const paginationSchema = z.object({
  page: z.coerce.number().int().positive().max(1000).default(1),
  limit: z.coerce.number().int().positive().max(200).default(50),
  sort: z.string().optional(),
  order: z.enum(['asc', 'desc']).default('asc'),
});

export const platformSchema = z.enum([
  'Windows',
  'Linux',
  'macOS',
  'IaaS',
  'SaaS',
  'Containers',
  'Network',
  'Office Suite',
  'Identity Provider',
  'Google Workspace',
  'Azure AD',
  'PRE',
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
  ]),
  format: z.enum(['csv', 'json']).default('json'),
});

export type PaginationParams = z.infer<typeof paginationSchema>;
export type Platform = z.infer<typeof platformSchema>;
export type SoftwareType = z.infer<typeof softwareTypeSchema>;
export type ExportParams = z.infer<typeof exportSchema>;
