/**
 * Shared CAPEC severity / likelihood → Badge variant maps.
 * Used by CapecList, CapecDetail, and any other surface rendering CAPEC
 * metadata — avoids drift between duplicated constants.
 */

type BadgeVariant = 'pink' | 'orange' | 'yellow' | 'blue' | 'neutral';

export const CAPEC_SEVERITY_VARIANTS: Record<string, BadgeVariant> = {
  'Very High': 'pink',
  'High': 'orange',
  'Medium': 'yellow',
  'Low': 'blue',
  'Very Low': 'neutral',
};

export const CAPEC_LIKELIHOOD_VARIANTS: Record<string, BadgeVariant> = {
  High: 'orange',
  Medium: 'yellow',
  Low: 'blue',
};
