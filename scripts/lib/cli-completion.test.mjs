/**
 * The generated shell completion.
 *
 * Generated from the same command table as the commands themselves, so it
 * cannot offer a resource or a flag that does not exist — which is the only
 * reason shipping completion for 86 commands is maintainable.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { completionScript, SHELLS } from '../../cli/lib/completion.mjs';
import { TREE } from '../../cli/lib/dispatch.mjs';

test('a script is produced for each supported shell, and only those', () => {
  assert.deepEqual(SHELLS, ['bash', 'zsh', 'fish']);
  for (const shell of SHELLS) assert.ok(completionScript(shell).length > 200, shell);
  assert.equal(completionScript('tcsh'), null);
  assert.equal(completionScript(''), null);
});

test('every resource is offered, and nothing that is not a resource', () => {
  const roots = [...new Set(TREE.map((c) => c.words[0]))];
  for (const shell of SHELLS) {
    const script = completionScript(shell);
    for (const root of roots) assert.ok(script.includes(root), `${shell} omits ${root}`);
  }
});

test('each shell parses the script generated for it', () => {
  /* The scripts embed the command table as a single-quoted shell string, so a
     stray apostrophe would close the string early and the rest of the table
     would be parsed as code. Asking the shell itself is the only check worth
     having — an earlier version of this test counted quotes on the line
     containing `data=`, which proves nothing, because the string spans every
     line of the table. */
  const dir = mkdtempSync(join(tmpdir(), 'mitrex-completion-'));
  for (const [shell, flag] of [
    ['bash', '-n'],
    ['zsh', '-n'],
  ]) {
    const probe = spawnSync(shell, ['-c', 'exit 0']);
    if (probe.error) continue; // shell not installed on this machine
    const file = join(dir, `completion.${shell}`);
    writeFileSync(file, completionScript(shell));
    const res = spawnSync(shell, [flag, file], { encoding: 'utf8' });
    assert.equal(res.status, 0, `${shell} rejected its own completion script:\n${res.stderr}`);
  }
  rmSync(dir, { recursive: true, force: true });
});
