# mitrex

[mitre-explorer.org](https://mitre-explorer.org) from the command line. ATT&CK techniques,
groups and campaigns; CVEs, GHSA and OSV advisories; CAPEC, Sigma, Atomic Red Team; NIST,
CSF, D3FEND, SCF and the rest of the compliance surface.

**No key, no account, no config file.** The API behind it is public and unauthenticated, so
this tool holds no credentials — there is nothing in it to steal, and nothing to leak into
your shell history or your CI logs.

**Read-only by construction.** Every command is generated from the site's own API catalogue,
and only its `GET` endpoints become commands. There is no write path to omit.

## Not published yet

Run it from a clone:

```sh
git clone https://github.com/PerIPan/explorer-plus.git
cd explorer-plus
node cli/mitrex.mjs techniques T1059
```

Or link it so `mitrex` is on your `PATH`:

```sh
cd explorer-plus/cli && npm link
mitrex techniques T1059
```

Requires Node 22.8 or newer (that is when `styleText` began honouring `NO_COLOR` and TTY detection). No dependencies to install — it uses only Node built-ins.

## Usage

```sh
mitrex                        # the resources, and some examples
mitrex help cves              # every command for one resource, with its flags
mitrex ls                     # all 85 commands, one per line

mitrex techniques T1059                      # one technique
mitrex techniques T1059 --expand groups      # the 125 groups that use it, as a table
mitrex groups -q lazarus                     # full-text search
mitrex cves --severity CRITICAL --limit 5    # filtered list
mitrex applications microsoft windows        # vendor names are slugged for you
```

Commands mirror the API's URLs, so `mitrex techniques T1059 packages` is
`GET /api/v1/techniques/T1059/packages`. If you know the endpoint you know the command.

### `-q` works everywhere

The API calls its full-text parameter `search` on 14 endpoints and `q` on 13, split along no
rule worth memorising. `-q` / `--query` works on all 27 and is sent under whichever name that
endpoint expects. The underlying name is still accepted if you have a `curl` line to copy.

### Piped output is the API's own JSON

```sh
mitrex cves --severity CRITICAL --limit 5 | jq '.data[].cveId'
```

When stdout is not a terminal the output is the API's own response bytes, unaltered (plus a
trailing newline). `--json` on a terminal re-indents and escapes control codepoints, because
a terminal is not a parser. The tables, colours and truncation only happen when a human is
looking, so nothing reformats data on its way into a script.

### Flags

| Flag | |
|---|---|
| `--json` | JSON even on a terminal |
| `--expand <field>` | render one array field of a detail response as a table |
| `--page`, `--limit` | paging, on every list endpoint |
| `--timeout <ms>` | default 30000 |
| `--base <url>` | point at another deployment |
| `--table` | keep the table when piping, e.g. into `less -R` |
| `--url` | print the URL it would call, and stop |
| `--no-color` | also honours `NO_COLOR` |

`--url` is worth knowing about: the command you type is not the URL that gets called. Vendor
and product names are slugged (`"Red Hat"` → `redhat`), `-q` is sent under whichever name the
endpoint declares, and empty values are dropped. `--url` shows you the result.

### Shell completion

```sh
eval "$(mitrex completion zsh)"      # or bash
mitrex completion fish > ~/.config/fish/completions/mitrex.fish
```

Completes resources, sub-commands and each command's own flags. Generated from the same table
as the commands, so it needs no network and cannot describe a flag that does not exist.

There is no `--all`. Most endpoints are not CDN-cached, so an auto-paginating flag is how a
well-meaning CLI becomes someone's top traffic source. Loop over `--page` if you mean it, or
ask for a bulk dump instead of crawling.

### Exit codes

| | |
|---|---|
| `0` | fine |
| `1` | the API returned an error status |
| `2` | your command or flags were wrong |
| `3` | the request never completed |

Behind a proxy, Node's built-in `fetch` ignores `HTTPS_PROXY` unless you run it with
`NODE_USE_ENV_PROXY=1`.

## Two things it will not do

**It never executes anything it receives.** The corpus contains Atomic Red Team entries whose
`executor_command` field is a literal attacker command, plus Sigma rules and IOC URLs. They
are data to display, so there is no `--exec`, no `eval`, and no example that pipes output into
a shell.

**It never writes raw control bytes to your terminal.** Response text comes from third parties
— IOC values from OTX and ThreatFox, advisory prose, upstream descriptions — and an `ESC` in a
description can repaint a screen or rewrite a prompt. The terminal renderer strips control
characters; the JSON path does not touch them, because a detection pipeline needs the real
string. For the same reason IOC values are defanged (`hxxp://`, `evil[.]com`) on a terminal
and left exact in JSON.

## Generated, not written

`lib/commands.generated.mjs` comes from `src/lib/api-catalog.ts` — the same file that draws
[/open-apis](https://mitre-explorer.org/open-apis). Regenerate with `npm run gen:cli`;
`npm run check:cli` fails CI if the committed table drifts from the catalogue, if the shared
URL-composer diverges from its source, or if the catalogue ever gains a path that would make a
command ambiguous.

Not affiliated with or endorsed by MITRE Corporation. Data attributions:
<https://mitre-explorer.org/about/attributions>.
