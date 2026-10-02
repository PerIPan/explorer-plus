/**
 * The one network call the CLI makes.
 *
 * Deliberately thin: built-in `fetch`, an abort deadline, and an error shape
 * the caller can turn into an exit code. No retry — a read-only GET against a
 * CDN-fronted API either answers or it does not, and a CLI that silently
 * retries makes a slow endpoint look like a hung terminal.
 */

/** Never throw from inside the error path — that is how a bad base surfaced as a bare "Invalid URL". */
function host(base) {
  try {
    return new URL(base).host;
  } catch {
    return base;
  }
}

/** Error bodies are not reliably JSON: a CDN or platform error is HTML or text. */
async function readBody(res) {
  const text = await res.text();
  if (!text) return { json: null, text: '' };
  try {
    return { json: JSON.parse(text), text };
  } catch {
    return { json: null, text };
  }
}

/**
 * @param {string} baseUrl  e.g. https://mitre-explorer.org/api/v1
 * @param {string} relPath  a path composed by dispatch.buildPath()
 * @param {{ timeoutMs?: number, version?: string }} opts
 * @returns {Promise<{ ok: boolean, status: number, json: unknown, text: string }>}
 */
export async function request(baseUrl, relPath, { timeoutMs = 30000, version = '0.0.0' } = {}) {
  const url = `${baseUrl}${relPath}`;
  let res;
  let json = null;
  let text = '';
  let retryAfter = null;
  try {
    res = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        Accept: 'application/json',
        // Identifies CLI traffic in the API's own analytics. Counted, unlike the
        // docs page's Run button: this is real consumption, not someone reading
        // documentation, so it does not set the docs-probe header.
        'User-Agent': `mitrex/${version} (+https://mitre-explorer.org)`,
      },
    });
    retryAfter = res.headers.get('retry-after');
    /* Inside the try: the response can time out or be severed WHILE the body
       is being read, and with this below the catch that failure escaped with
       the raw "The operation was aborted due to timeout" and no exitCode. */
    ({ json, text } = await readBody(res));
  } catch (err) {
    const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
    throw Object.assign(
      new Error(
        timedOut
          ? `No response within ${timeoutMs}ms — raise it with --timeout <ms>`
          : `Could not reach ${host(baseUrl)}: ${err?.cause?.code ?? err?.cause?.message ?? err?.message ?? err}`,
      ),
      {
        // Built-in fetch ignores HTTP(S)_PROXY. Say so rather than letting a
        // corporate proxy look like the site being down.
        /* `node --use-env-proxy` is unusable once mitrex is installed as a shim,
           and the flag only exists from 22.21 / 24.5 anyway. The env var is the
           form that actually works for an installed binary. */
        hint: timedOut ? null : 'Behind a proxy? Node ignores HTTPS_PROXY unless you set NODE_USE_ENV_PROXY=1.',
        exitCode: 3,
      },
    );
  }

  return { ok: res.ok, status: res.status, json, text, url, retryAfter };
}
