// scripts/lib/db-session.mjs
//
// Session-scoped Postgres for batch scripts: the direct (unpooled) Neon
// endpoint, and an advisory lock held on ONE dedicated connection.
//
// WHY (2026-10-09, SCF 2026.3 ingest): DATABASE_URL is Neon's pooled endpoint,
// PgBouncer in transaction mode, so consecutive statements from one client can
// run on different server sessions. A job that relies on session state broke
// in two ways:
//   - its pg_advisory_unlock ran on a different session from the lock, so the
//     lock stayed held by a pooled server connection that API traffic keeps
//     busy, and the next run refused to start until that connection aged out
//     about an hour later;
//   - a statement_timeout another client had leaked onto a pooled session
//     cancelled a long rebuild, and the job's own SET would leak the same way
//     (app/api/v1/lib/db.ts documents the pooler behaviour).
// pool.query() for lock and unlock is wrong even on a direct connection: the
// pool may lend a different client for each call. scripts/check-scripts.mjs
// fails CI when a script takes a session lock or sets session state without
// going through this module.

/**
 * The direct-endpoint form of a Neon connection string: the same host without
 * "-pooler". DATABASE_URL_UNPOOLED wins when given. Anything that is not a
 * Neon pooler URL comes back unchanged.
 *
 * @param {string} url
 * @param {string | undefined} [unpooled]
 * @returns {{ url: string, switched: boolean, via: string | null }}
 */
export function directNeonUrl(url, unpooled = undefined) {
  if (unpooled) return { url: unpooled, switched: true, via: 'DATABASE_URL_UNPOOLED' };
  try {
    const u = new URL(url);
    if (/-pooler\./.test(u.hostname)) {
      u.hostname = u.hostname.replace('-pooler.', '.');
      return { url: u.toString(), switched: true, via: 'host without -pooler' };
    }
  } catch { /* not a URL we can parse — use as given */ }
  return { url, switched: false, via: null };
}

/**
 * The connection string a batch script should use, logged once. Reads
 * DATABASE_URL_UNPOOLED from the environment when set.
 *
 * @param {string} url
 * @param {string} tag  log prefix, e.g. 'sync-scf'
 */
export function batchDatabaseUrl(url, tag) {
  const d = directNeonUrl(url, process.env.DATABASE_URL_UNPOOLED);
  if (d.switched) console.log(`[${tag}] using the direct (unpooled) endpoint — ${d.via}`);
  return d.url;
}

/**
 * How pg_locks stores a bigint advisory key: high 32 bits in classid, low 32
 * in objid, objsubid = 1.
 *
 * @param {number | bigint} key
 */
export function advisoryKeyParts(key) {
  const k = BigInt(key);
  return { classid: Number((k >> 32n) & 0xffffffffn), objid: Number(k & 0xffffffffn) };
}

/**
 * Who holds an advisory lock, in one line, for the "already running" error.
 * Best effort: returns null when it cannot tell.
 *
 * @param {import('pg').PoolClient | import('pg').Pool} q
 * @param {number | bigint} key
 */
export async function describeLockHolder(q, key) {
  try {
    const { classid, objid } = advisoryKeyParts(key);
    const r = await q.query(
      `SELECT l.pid, a.application_name, a.state, a.backend_start, a.state_change
         FROM pg_locks l LEFT JOIN pg_stat_activity a USING (pid)
        WHERE l.locktype = 'advisory' AND l.granted AND l.classid = $1 AND l.objid = $2 AND l.objsubid = 1`,
      [classid, objid],
    );
    if (r.rowCount === 0) return null;
    return r.rows
      .map((h) => `pid ${h.pid} (${h.application_name || 'no application_name'}, ${h.state ?? 'unknown state'}, connected ${h.backend_start?.toISOString?.() ?? h.backend_start}, last activity ${h.state_change?.toISOString?.() ?? h.state_change})`)
      .join('; ');
  } catch {
    return null;
  }
}

/**
 * Take a session advisory lock on a dedicated client checked out of `pool`
 * and keep that client until release(), so lock and unlock run in the same
 * server session. Use with a direct (unpooled) connection — see the header.
 *
 * @param {import('pg').Pool} pool
 * @param {number | bigint} key
 * @param {string} tag  log prefix
 * @returns {Promise<{ locked: true, client: import('pg').PoolClient, release: () => Promise<void> } | { locked: false, holder: string | null }>}
 */
export async function takeSessionLock(pool, key, tag) {
  const client = await pool.connect();
  let r;
  try {
    r = await client.query('SELECT pg_try_advisory_lock($1) AS locked', [String(key)]);
  } catch (e) {
    client.release();
    throw e;
  }
  if (r.rows[0].locked !== true) {
    const holder = await describeLockHolder(client, key);
    client.release();
    return { locked: false, holder };
  }
  let released = false;
  return {
    locked: true,
    client,
    async release() {
      if (released) return;
      released = true;
      try {
        const u = await client.query('SELECT pg_advisory_unlock($1) AS released', [String(key)]);
        if (u.rows[0].released !== true) {
          console.warn(`[${tag}] pg_advisory_unlock returned false — this session did not hold the lock`);
        }
      } finally {
        client.release();
      }
    },
  };
}
