import { Pool, QueryResult, QueryResultRow } from 'pg';

let pool: Pool | null = null;

function getPool(): Pool {
  if (!pool) {
    const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL;
    const isProduction = connectionString?.includes('neon') || connectionString?.includes('vercel');
    pool = new Pool({
      connectionString,
      statement_timeout: 5000,
      max: isProduction ? 1 : 10,
      ssl: isProduction ? { rejectUnauthorized: false } : undefined,
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
