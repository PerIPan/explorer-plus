import { Pool, PoolClient, QueryResult, QueryResultRow } from 'pg';

let pool: Pool | null = null;

export function getPool(): Pool {
  if (!pool) {
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
    pool = new Pool({
      connectionString: connStr,
      statement_timeout: 5000,
      connectionTimeoutMillis: isProduction ? 20000 : 3000,
      idle_in_transaction_session_timeout: 10000,
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
  }
  return pool;
}

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params?: unknown[],
): Promise<QueryResult<T>> {
  const client = getPool();
  try {
    return await client.query<T>(text, params);
  } catch (err) {
    // Retry once on connection errors (Neon cold-start)
    const msg = err instanceof Error ? err.message : '';
    if (msg.includes('Connection terminated') || msg.includes('connection timeout')) {
      await new Promise((r) => setTimeout(r, 2000));
      return client.query<T>(text, params);
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
  const pool = getPool();
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
