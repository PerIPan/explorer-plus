import { Pool, QueryResult, QueryResultRow } from 'pg';

let pool: Pool | null = null;

function getPool(): Pool {
  if (!pool) {
    const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL;
    if (!connectionString) {
      throw new Error('DATABASE_URL or POSTGRES_URL environment variable must be set');
    }
    const isProduction = connectionString.includes('neon') || connectionString.includes('vercel');
    // Strip sslmode from connection string — we set ssl via config object to avoid pg deprecation warning
    const connStr = connectionString.replace(/[?&]sslmode=[^&]*/g, (m) => m.startsWith('?') ? '?' : '');
    pool = new Pool({
      connectionString: connStr,
      statement_timeout: 5000,
      connectionTimeoutMillis: isProduction ? 20000 : 3000,
      idle_in_transaction_session_timeout: 10000,
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
