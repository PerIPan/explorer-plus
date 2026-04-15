/**
 * Soft timeout helper for cron routes.
 *
 * Every cron handler writes a `feed_sync_log` row with `status='running'` on
 * entry and a terminal row (success / error) at the end. When Vercel kills
 * the function at its `maxDuration` hard-limit, the terminal write never
 * happens and the row is stranded in `running` forever (the next invocation
 * sweeps it, but that can be 24h later).
 *
 * `withSoftTimeout` races the work against a timer that fires slightly
 * before the Vercel kill, so we always reach the caller's `catch` block and
 * can write an `error` row.
 *
 * Usage:
 *   return withSoftTimeout(async () => { ... }, 270_000);
 *
 * Callers still need a try/catch to persist the terminal status — this
 * helper only guarantees the catch runs.
 */
export async function withSoftTimeout<T>(
  work: () => Promise<T>,
  timeoutMs: number,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`Soft timeout: exceeded ${timeoutMs}ms budget before Vercel hard kill`)),
      timeoutMs,
    );
  });
  try {
    return await Promise.race([timeout, work()]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Default soft timeout: 270s, sits 30s below the standard Vercel cron
 * maxDuration of 300s. Gives the catch/UPDATE enough headroom to land
 * before the function is killed.
 */
export const DEFAULT_SOFT_TIMEOUT_MS = 270_000;
