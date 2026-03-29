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
      connectionTimeoutMillis: isProduction ? 10000 : 3000,
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
  return client.query<T>(text, params);
}
