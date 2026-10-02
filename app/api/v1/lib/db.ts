import { Pool } from 'pg';
// `import type` for the three that are types, not values. A single value
// import of all four is what Next's compiler happily elides but Node's
// type-stripping cannot: `pg` is CJS and exports no runtime `PoolClient`, so a
// plain import makes this module unloadable outside the bundler — which is how
// it is reached from scripts/lib/*.test.mjs.
import type { PoolClient, QueryResult, QueryResultRow } from 'pg';

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * NEON DROPS STARTUP PARAMETERS. DO NOT SET TIMEOUTS ON THE POOL CONFIG.
 *
 * node-postgres sends `statement_timeout`, `lock_timeout` and
 * `idle_in_transaction_session_timeout` in the connection startup packet
 * (see getStartupConf in pg/lib/client.js). Neon's proxy discards them. This
 * pool used to pass `statement_timeout: 5000` and
 * `idle_in_transaction_session_timeout: 10000`; measured against production
 * 2026-10-02, the server reported:
 *
 *   statement_timeout                    0        source=default
 *   idle_in_transaction_session_timeout  300000   source=configuration file
 *   lock_timeout                         0        source=default
 *
 * `SELECT pg_sleep(9)` completed in 9.0s under a nominal 5s cap, on the pooled
 * AND the direct endpoint alike — so switching to DATABASE_URL_UNPOOLED does
 * not help. Every query here ran unbounded, and the config said otherwise.
 *
 * That mattered: a reader reasoning from this file wrote a helper whose
 * correctness argument was "RESET restores the pool's 5s". RESET restores 0.
 *
 * Three mechanisms DO work. Measured, not assumed:
 *
 *   `query_timeout` (pg, client-side)   fires reliably; pool stays usable.
 *                                       But it ORPHANS the server: client gave
 *                                       up at 2.1s while the backend was still
 *                                       `active` at t+11.3s. Bounds the Vercel
 *                                       function, not the database.
 *
 *   `SET LOCAL` inside an explicit      cancels the statement for real (killed
 *   transaction                         at 2.0s) and cannot leak — back to 0
 *                                       after ROLLBACK. Costs 3 extra round
 *                                       trips: 12.1ms -> 48.1ms on a cheap
 *                                       indexed query, so it is applied per
 *                                       call, never globally.
 *
 *   bare `SET` on connect               DOES apply, and is a trap. On PgBouncer
 *                                       the value persists on the server
 *                                       connection and the next client inherits
 *                                       it; a 25s value set by one script killed
 *                                       an unrelated CREATE INDEX CONCURRENTLY
 *                                       at exactly 25s. Never use it here.
 * ═══════════════════════════════════════════════════════════════════════════
 */

/**
 * Client-side ceiling for API requests. Deliberately loose: the slowest
 * LEGITIMATE request measured is `/api/v1/advisories?limit=5000` at 17.5s on a
 * CDN miss, and `max 5000` is a documented contract (src/lib/api-catalog.ts).
 * A tighter value would start 500ing requests the docs promise. It still cuts
 * the pathological case — `?q=<term>` with no narrowing filter measured >70s.
 *
 * Maintenance work does NOT get this: see getMaintenancePool().
 */
const API_QUERY_TIMEOUT_MS = 30_000;

let apiPool: Pool | null = null;
let maintenancePool: Pool | null = null;

function buildPool(queryTimeoutMs: number | undefined): Pool {
    const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL;
    if (!connectionString) {
      throw new Error('DATABASE_URL or POSTGRES_URL environment variable must be set');
    }
    // Prefer NODE_ENV for production detection; fall back to host heuristic so
    // tests / local prod-like setups still get strict SSL when they explicitly
    // point at a managed Postgres.
    const isProduction =
      process.env.NODE_ENV === 'production' ||
      connectionString.includes('neon') ||
      connectionString.includes('vercel');
    // Strip sslmode from connection string — we set ssl via config object to avoid pg deprecation warning.
    // Use URL parser to avoid edge-case orphan `?` when sslmode is the sole query param.
    let connStr = connectionString;
    try {
      const u = new URL(connectionString);
      u.searchParams.delete('sslmode');
      connStr = u.toString();
    } catch {
      // Non-URL form (unlikely) — leave as-is, pg will complain cleanly
    }
    const pool = new Pool({
      connectionString: connStr,
      // No statement_timeout / idle_in_transaction_session_timeout here. See
      // the block at the top of this file: Neon discards them, and setting
      // them is how this file came to assert a guarantee it did not provide.
      ...(queryTimeoutMs ? { query_timeout: queryTimeoutMs } : {}),
      connectionTimeoutMillis: isProduction ? 20000 : 3000,
      // Drop idle pooled connections quickly so Neon's compute autosuspend
      // timer (which only starts once all connections close) begins sooner —
      // less awake time = lower compute bill. Cold-start reconnect is retried
      // in query() below.
      idleTimeoutMillis: 3000,
      max: isProduction ? 3 : 10,
      ssl: isProduction ? { rejectUnauthorized: true } : undefined,
    });
    pool.on('error', (err) => {
      console.error('Unexpected PostgreSQL pool error:', err);
    });
    return pool;
}

/** The pool every API route uses. Bounded by API_QUERY_TIMEOUT_MS. */
export function getPool(): Pool {
  if (!apiPool) apiPool = buildPool(API_QUERY_TIMEOUT_MS);
  return apiPool;
}

/**
 * Unbounded pool for maintenance work — cron refreshes, migrations, anything
 * whose single statements legitimately run for tens of seconds.
 *
 * Measured durations that would die under the API ceiling:
 * `REFRESH MATERIALIZED VIEW CONCURRENTLY ecosystem_advisory_stats` 57.9s,
 * `osv_advisory_rank` 64s, `app_technique_groups` up to 30.2s.
 *
 * Three cron routes need it (refresh-matviews, sync-csf, sync-d3fend); the
 * other eleven only issue short batches and are fine on the API pool.
 *
 * Created lazily and separately, so an API lambda that never runs maintenance
 * work never opens a second set of Neon connections.
 */
export function getMaintenancePool(): Pool {
  if (!maintenancePool) maintenancePool = buildPool(undefined);
  return maintenancePool;
}

/** True for the Neon cold-start errors worth one retry. */
function isTransientConnectionError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : '';
  return msg.includes('Connection terminated') || msg.includes('connection timeout');
}

export interface QueryOptions {
  /**
   * Server-side `statement_timeout`, in milliseconds, for THIS query only.
   *
   * Unlike the pool's `query_timeout` — which merely stops Node waiting and
   * leaves the backend running (measured: still `active` 9s after the client
   * gave up) — this actually cancels the statement, so Neon stops spending
   * compute on it.
   *
   * It costs 3 extra round trips (BEGIN / set_config / COMMIT), measured at
   * +36ms on a cheap indexed query. That is why it is opt-in per call: it is
   * noise on a query that might run for seconds, and a 4x regression on one
   * that takes 12ms. Use it where a query reads a large table or accepts
   * free-text search; leave it off for indexed lookups.
   *
   * Runs on the maintenance pool, because the API pool's 30s client timeout
   * would otherwise pre-empt any server-side budget above it.
   */
  statementTimeoutMs?: number;
}

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params?: unknown[],
  opts?: QueryOptions,
): Promise<QueryResult<T>> {
  if (opts?.statementTimeoutMs !== undefined) {
    // Checked here, not just inside the helper: `0` is falsy, so a truthiness
    // test would have let an explicit `statementTimeoutMs: 0` fall through to
    // the UNBOUNDED path — the exact opposite of what a caller passing a
    // budget of zero is asking for. Omit the option to mean "no budget".
    const ms = opts.statementTimeoutMs;
    if (!Number.isInteger(ms) || ms <= 0) {
      throw new Error(
        `statementTimeoutMs must be a positive integer, got ${ms}. Omit it for no budget.`,
      );
    }
    return queryWithStatementTimeout<T>(text, params, ms);
  }
  const client = getPool();
  try {
    return await client.query<T>(text, params);
  } catch (err) {
    // Retry once on connection errors (Neon cold-start)
    if (isTransientConnectionError(err)) {
      await new Promise((r) => setTimeout(r, 2000));
      return client.query<T>(text, params);
    }
    throw err;
  }
}

/**
 * One query under a real, transaction-scoped server-side statement_timeout.
 *
 * `SET LOCAL` (here via set_config with is_local = true) is scoped to the
 * transaction, which is the whole point: a bare `SET` would persist on the
 * PgBouncer server connection and be inherited by the next unrelated client.
 * ROLLBACK/COMMIT restores the session, so nothing leaks even if the statement
 * is cancelled — verified: `0` again afterwards.
 *
 * The transaction is committed rather than rolled back so a caller could use
 * this for a write; today every caller reads.
 */
async function queryWithStatementTimeout<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] | undefined,
  timeoutMs: number,
): Promise<QueryResult<T>> {
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`statementTimeoutMs must be a positive integer, got ${timeoutMs}`);
  }
  const run = async (): Promise<QueryResult<T>> => {
    const client = await getMaintenancePool().connect();
    try {
      await client.query('BEGIN');
      // set_config, not `SET LOCAL`, because SET cannot bind a parameter.
      await client.query('SELECT set_config($1, $2, true)', [
        'statement_timeout',
        String(timeoutMs),
      ]);
      const result = await client.query<T>(text, params);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // The original error is the useful one.
      }
      throw err;
    } finally {
      client.release();
    }
  };
  try {
    return await run();
  } catch (err) {
    if (isTransientConnectionError(err)) {
      await new Promise((r) => setTimeout(r, 2000));
      return run();
    }
    throw err;
  }
}

/**
 * For maintenance work: no client-side ceiling, so a 58s REFRESH is not cut
 * off at 30s. Cron routes whose statements legitimately run that long use this
 * instead of query().
 */
export async function maintenanceQuery<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params?: unknown[],
): Promise<QueryResult<T>> {
  const pool = getMaintenancePool();
  try {
    return await pool.query<T>(text, params);
  } catch (err) {
    if (isTransientConnectionError(err)) {
      await new Promise((r) => setTimeout(r, 2000));
      return pool.query<T>(text, params);
    }
    throw err;
  }
}

/**
 * Run a callback inside a real Postgres transaction on a single dedicated client.
 * Use this instead of calling `query('BEGIN')` / `query('COMMIT')` — those run on
 * different pooled connections and provide ZERO atomicity.
 *
 * Automatically rolls back on error and releases the client in all paths.
 */
export async function withTransaction<T>(
  cb: (client: PoolClient) => Promise<T>,
): Promise<T> {
  // Maintenance pool: both callers are cron routes (sync-csf, ingest-cisa-kev)
  // and sync-csf's transaction is one of the long ones. A 30s client ceiling
  // mid-transaction would abandon a half-applied batch rather than fail
  // cleanly.
  const pool = getMaintenancePool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await cb(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // ignore rollback errors — original error is more important
    }
    throw err;
  } finally {
    client.release();
  }
}
