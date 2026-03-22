import express from 'express';
import { readdirSync, statSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const API_DIR = join(__dirname, '..', 'api');

/**
 * Recursively scans `dir` and registers Express routes that mirror Vercel's
 * filesystem routing conventions:
 *
 *   index.ts          → basePath          (e.g. /api/v1/techniques)
 *   [param].ts        → basePath/:param   (e.g. /api/v1/techniques/:attackId)
 *   name.ts           → basePath/name     (e.g. /api/v1/dashboard)
 *
 * Directories whose names start with `_` (e.g. `_lib`) are skipped — they
 * are helpers, not deployed endpoints.
 *
 * Dynamic path params are merged into `req.query` before the handler is
 * called so that handlers written for Vercel (which merges params into
 * req.query) work without modification.
 */
function registerRoutes(dir: string, basePath: string = '/api'): void {
  const entries = readdirSync(dir);

  for (const entry of entries) {
    // Skip underscore-prefixed dirs/files (_lib, _middleware, etc.)
    if (entry.startsWith('_')) continue;

    const fullPath = join(dir, entry);

    if (statSync(fullPath).isDirectory()) {
      registerRoutes(fullPath, `${basePath}/${entry}`);
      continue;
    }

    if (!entry.endsWith('.ts')) continue;

    let routePath: string;

    if (entry === 'index.ts') {
      routePath = basePath;
    } else if (entry.startsWith('[') && entry.endsWith('].ts')) {
      // [attackId].ts → :attackId
      const param = entry.slice(1, -4);
      routePath = `${basePath}/:${param}`;
    } else {
      routePath = `${basePath}/${entry.slice(0, -3)}`;
    }

    // Capture fullPath in closure — import() resolves it at call-time so we
    // must bind it now before the loop advances.
    const modulePath = fullPath;

    app.all(routePath, async (req, res) => {
      // Merge Express path params into req.query to replicate Vercel behaviour.
      // In Express 5, req.query is a read-only getter on the prototype, so we
      // shadow it with an own writable property on this specific request object.
      const mergedQuery = { ...(req.query as Record<string, unknown>), ...req.params };
      Object.defineProperty(req, 'query', {
        value: mergedQuery,
        writable: true,
        configurable: true,
        enumerable: true,
      });

      try {
        const mod = await import(modulePath);
        const handler = mod.default;

        if (typeof handler !== 'function') {
          console.error(`No default export function in ${modulePath}`);
          res.status(500).json({ error: 'Handler not found', code: 'HANDLER_NOT_FOUND' });
          return;
        }

        await handler(req, res);
      } catch (err) {
        console.error(`Error in ${routePath}:`, err);
        res.status(500).json({ error: 'Internal server error', code: 'INTERNAL_ERROR' });
      }
    });

    console.log(`  ${routePath}`);
  }
}

console.log('Registering routes:');
registerRoutes(API_DIR);

const PORT = Number(process.env.PORT ?? 3001);
app.listen(PORT, () => {
  console.log(`\nDev server running at http://localhost:${PORT}`);
});
