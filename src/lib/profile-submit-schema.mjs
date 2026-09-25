import { z } from 'zod';

const slugList = z.array(z.string().min(1).max(64)).max(24).default([]);

export const submissionSchema = z.object({
  variant: z.enum(['v1-4q', 'v1-6q-ot']),
  action: z.enum(['apply', 'dismiss', 'auto_close']),
  sectors: slugList,
  platforms: slugList,
  roles: slugList,
  frameworks: slugList,
  assets: slugList,
  purdue_levels: slugList,
});
