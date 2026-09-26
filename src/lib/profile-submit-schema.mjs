import { z } from 'zod';
import {
  SECTOR_VALUES,
  PLATFORM_VALUES,
  ROLE_VALUES,
  FRAMEWORK_VALUES,
  ASSET_VALUES,
  PURDUE_LEVEL_VALUES,
} from './profile-submit-values.mjs';

/**
 * Per-dimension vocabulary at the edge.
 *
 * Every one of the six dimension columns was `z.array(z.string().min(1).max(64))`
 * — i.e. any 64-character string, 20 rows per IP per day, on the repo's ONLY
 * unauthenticated public write. The spec's Optionality table requires `z.enum`
 * here and says "never free-string", for two reasons that both bite:
 *
 *   1. The apply/dismiss ratio is the single metric this whole feature is judged
 *      on, and it is computed by grouping these columns. A column anyone can
 *      write arbitrary values into cannot be grouped by — one scripted client
 *      writing 20 junk slugs a day is enough to make every rollup lie.
 *   2. `text[]` columns with no CHECK are the last place in this repo where an
 *      attacker still chooses what gets stored. Bounding the vocabulary is the
 *      cheap half of that; `.max(24)` was already the other half.
 *
 * `.max(24)` is UNCHANGED, and matches `platformsParam`/`assetsParam`/
 * `levelsParam` in app/api/v1/lib/validate.ts so the assembler and the sink
 * agree on how many values a submission may carry.
 *
 * The values themselves live in ./profile-submit-values.mjs — a guarded mirror
 * of the authoring modules, which are `.ts` and therefore unreachable from a
 * `.mjs` imported by bare `node --test`. See that file's header, and the drift
 * tests in scripts/lib/profile-submit.test.mjs that hold it to its sources.
 */
const dimension = (values) => z.array(z.enum(values)).max(24).default([]);

export const submissionSchema = z.object({
  variant: z.enum(['v1-4q', 'v1-6q-ot']),
  action: z.enum(['apply', 'dismiss', 'auto_close']),
  sectors: dimension(SECTOR_VALUES),
  platforms: dimension(PLATFORM_VALUES),
  roles: dimension(ROLE_VALUES),
  frameworks: dimension(FRAMEWORK_VALUES),
  assets: dimension(ASSET_VALUES),
  purdue_levels: dimension(PURDUE_LEVEL_VALUES),
});
