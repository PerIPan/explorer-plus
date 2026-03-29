import { Pool, QueryResult, QueryResultRow } from 'pg';

let pool: Pool | null = null;

function getPool(): Pool {
  if (!pool) {
    const connectionString = process.env.DATABASE_URL || process.env.POSTGRES_URL;
    if (!connectionString) {
      throw new Error('DATABASE_URL or POSTGRES_URL environment variable must be set');
    }
    const isProduction = connectionString.includes('neon') || connectionString.includes('vercel');
    // Parse connection string with WHATWG URL to avoid pg's deprecated url.parse()
    let poolConfig: ConstructorParameters<typeof Pool>[0];
    if (isProduction) {
      const url = new URL(connectionString);
      poolConfig = {
        host: url.hostname,
        port: parseInt(url.port || '5432', 10),
        database: url.pathname.slice(1),
        user: url.username,
        password: decodeURIComponent(url.password),
        ssl: { rejectUnauthorized: true },
        statement_timeout: 5000,
        connectionTimeoutMillis: 3000,
        idle_in_transaction_session_timeout: 10000,
        max: 3,
      };
    } else {
      poolConfig = {
        connectionString,
        statement_timeout: 5000,
        connectionTimeoutMillis: 3000,
        idle_in_transaction_session_timeout: 10000,
        max: 10,
      };
    }
    pool = new Pool(poolConfig);
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
