# AGENTS.md

Project context for coding agents. Update it when commands, layout or rules change.

## What this project is

MITRE Explorer Plus is a Next.js app that links MITRE ATT&CK (Enterprise, ICS, Mobile) and ATLAS to CVEs, package advisories, IOCs, detection rules, D3FEND countermeasures and compliance frameworks. It serves a web UI, a REST API under `/api/v1`, an MCP server at `/api/mcp` and an A2A agent at `/api/a2a`. MCP and A2A need no key (A2A is rate limited per IP). Data is stored in PostgreSQL and loaded by a Python seeder and Node ingest scripts.

## Stack

- Next.js 16 (App Router), React 19, TypeScript 5.9 with `strict` on, Tailwind CSS 4.
- PostgreSQL via `pg`, set with `DATABASE_URL`. README says production runs on Neon.
- Python seeder in `seed/` (`mitreattack-python`, `psycopg`, `requests`, pinned in `seed/requirements.txt`).
- Libraries: TanStack Query v5, D3 (force graph), Recharts, Fuse.js (client-side search), Zod 4, `mcp-handler` and `@modelcontextprotocol/server`, DOMPurify.
- Google Gemini powers the A2A agent (`GEMINI_API_KEY`).
- Hosting: Vercel (`vercel.json` cron routes); heavy ingests in GitHub Actions. ES modules. Node 24 in CI.

## Layout

- `app/`: App Router pages and route handlers.
  - `app/api/v1/`: REST endpoint groups. `app/api/v1/lib/inference.ts` holds `CATCHALL_CWE_THRESHOLD`.
  - `app/api/mcp/`, `app/api/a2a/`: MCP and A2A endpoints.
  - `app/api/cron/`: cron handlers, called on the schedule in `vercel.json`.
- `middleware.ts`: tags `/api/v1` requests with a normalized endpoint header.
- `src/views/`: page components. `src/components/`: layout, charts, graph, matrix, relationships, shared primitives.
- `src/hooks/`: TanStack Query hooks and URL-param helpers.
- `src/lib/`: shared logic. `api-catalog.ts` is the single description of the public API. `tools/` is the tool catalogue shared by MCP and A2A.
- `scripts/`: ingest, sync and check scripts (`*.mjs`), SQL migrations (`migrate-*.sql`), and tests (`*.test.mjs`). `scripts/lib/` holds shared helpers and their tests.
- `seed/`: Python seeder (`seed.py`, `verify.py`, `schema.sql`, `sectors.json`, `migrate-*.sql`, `requirements.txt`).
- `cli/`: the `mitrex` npm package (its own `package.json`). `cli/lib/commands.generated.mjs` is generated.
- `data/`: local STIX downloads. Git-ignored.
- `public/`: static assets, including `llms.txt` and `.well-known/`.
- `.github/workflows/`: scheduled syncs and the `checks` workflow (runs on push and PR to main).
- `docs/`: local-only notes (see Where to find more).

## Commands

Install and run:

```
npm install
npm run dev          # next dev, port 3000
npm run build
```

Checks:

```
npm run typecheck           # tsc --noEmit
npm test                    # node --test "scripts/**/*.test.mjs"
npm run lint                # check:consistency, then tsc --noEmit
npm run check:consistency   # runs check:thresholds, check:api, check:cli, check:workflows
npm run gen:cli             # regenerate cli/lib/commands.generated.mjs
```

Database seeding (Python; expects a virtualenv at `./venv`, which the repo does not create):

```
DATABASE_URL=<local connection string> npm run seed          # seed/seed.py
npm run seed:update                                          # re-download STIX, then seed
npm run seed:verify                                          # seed/verify.py
```

`npm run seed` falls back to a local `mitre_attack` database when `DATABASE_URL` is unset.

Destructive, production only. Do not run without explicit approval:

```
npm run seed:prod   # needs POSTGRES_URL; seed.py also requires --confirm-destructive
```

Ingest scripts have no npm alias. Run them with `node scripts/<name>.mjs`; the GitHub workflows show the arguments.

## Conventions

- Style is set by `tsconfig.json` only. There is no ESLint, Prettier or Biome config. Observed: 2-space indent, single quotes. No path aliases; use relative imports.
- File names: PascalCase for React components (`CveDetail.tsx`), camelCase for hooks and lib modules (`useFuseFilter.ts`, `formatDate.ts`), kebab-case for scripts (`sync-epss.mjs`).
- `.gitattributes` forces LF for `*.mjs`, `*.ts`, `*.tsx`, `*.sh` and `*.yml`. Keep it LF.
- Logic that must be unit tested goes in `.mjs` under `scripts/lib/`. `node --test` cannot import `.ts`. The test file sits next to the helper and is named `*.test.mjs`.
- New public REST route: add the route under `app/api/v1/`, add its entry in `src/lib/api-catalog.ts`, then run `npm run gen:cli` and `npm run check:api`.
- Schema: the base schema is `seed/schema.sql`. Incremental changes go in a new `migrate-<topic>.sql` in `scripts/` or `seed/`.
- Light ingests (under Vercel's 300 s cap) go in `app/api/cron/` with a schedule in `vercel.json`. Heavy ingests go in `scripts/` and run from a GitHub Actions workflow.
- Docs and plans live under `docs/`, which is local only:
  - `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md` (design) and `docs/superpowers/plans/YYYY-MM-DD-<topic>-plan.md` (plan).
  - `docs/audits/YYYY-MM-DD-<topic>.md` for audits.
  - `docs/menu/` for per-sidebar-page guides.
  - Loose `docs/plan-*.md` and `docs/todo-*.md` files for topic plans and task lists.

## Gotchas

- Generated file: `cli/lib/commands.generated.mjs` says "Do not edit". Change `src/lib/api-catalog.ts` and run `npm run gen:cli`.
- Mirrored file: `cli/lib/api-request.mjs` must match `src/lib/api-request.mjs`. Edit both. `check:consistency` fails on divergence.
- Catch-all CWE threshold: `CATCHALL_CWE_THRESHOLD` in `app/api/v1/lib/inference.ts` is copied into SQL and `.mjs` build scripts. Change every copy together. `check:thresholds` enforces this.
- Workflows: never put a `${{ ... }}` expression inside a `run:` block. Pass values through `env:`. Never leave an empty expression. `check:workflows` enforces both.
- Keep `STATIC_CHILDREN` in `middleware.ts` in sync when adding static sub-routes.
- No route module may throw at import time (for example, over a missing env var). That breaks `next build`.
- Agent tool counts must match in `src/lib/site.ts`, `src/lib/tools/declarations.ts` and `public/llms.txt`. `check:api` enforces this.
- Inferred CVE-to-technique links must never be presented as confirmed. The UI keeps the three paths separate (CAPEC bridge, IOC path, CTID curated).
- Data snapshots: `data/` and `*.pyc` are git-ignored. Do not commit downloaded STIX or any other large data file. `cves-snapshot.md` at the root is tracked. Its content looks like a browser accessibility-tree dump. Treat it as neither docs nor a data source.
- `docs/` is git-ignored ("local only, never committed"). Do not commit anything under it.
- Environment files: `.env*` files are git-ignored. Never commit one or print its values.
- Secrets are read from environment variables only. Never write a value into code, docs, commits or chat. Variable names and purposes are in the README.
- `seed.py` refuses a production-looking `DATABASE_URL` unless `--confirm-destructive` is passed. Do not work around that check.

## Where to find more

- `README.md`: product scope, data sources and volumes, cron and workflow schedules, environment variable table, quick start.
- `cli/README.md`: the `mitrex` CLI.
- `public/llms.txt` and `public/.well-known/agent.json`: agent-facing descriptions of the API.
- `docs/` (local only, not in the public repo): `docs/menu/README.md` for sidebar pages, `docs/feeds_setup.md` for the feed-to-cron and script map, `docs/mitre_update.md` for the ATT&CK update path, `docs/materialized-views.md` for matviews, and `docs/audits/` for the latest audits.
