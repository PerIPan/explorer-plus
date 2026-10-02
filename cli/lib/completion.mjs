/**
 * Shell completion, generated from the same command table.
 *
 * Not cargo cult at this size: 83 commands over 30 resources, with closed
 * vocabularies on 64 parameters. Nobody memorises that, and the alternative is
 * `mitrex ls | grep`. It needs no network — everything it completes is already
 * compiled into the package.
 */
import { COMMANDS } from './commands.generated.mjs';

/** Every command as a space-joined word path, with its flags. */
function table() {
  return COMMANDS.map((cmd) => {
    const words = cmd.path
      .split('/')
      .filter(Boolean)
      .filter((seg) => !seg.startsWith('{'));
    const flags = cmd.params.map((p) => `--${p.name}`);
    if (cmd.fulltext) flags.push('-q', '--query');
    return { words, flags: [...new Set(flags)] };
  });
}

const GLOBAL = ['--json', '--table', '--url', '--expand', '--timeout', '--base', '--no-color', '--help'];

export function completionScript(shell) {
  const rows = table();
  const roots = [...new Set(rows.map((r) => r.words[0]))].sort();
  // One line per command: "word path<TAB>flags", read by the shell function.
  const data = rows
    .map((r) => `${r.words.join(' ')}\t${[...r.flags, ...GLOBAL].join(' ')}`)
    .sort()
    .join('\n');

  if (shell === 'bash') {
    return `# mitrex bash completion — eval "$(mitrex completion bash)"
_mitrex() {
  local data words cur prev
  data='${data.replace(/'/g, "'\\''")}'
  cur="\${COMP_WORDS[COMP_CWORD]}"
  if [[ "\$cur" == -* ]]; then
    local line
    line=\$(printf '%s\\n' "\$data" | grep -F "\${COMP_WORDS[*]:1:COMP_CWORD-1}	" | head -1)
    COMPREPLY=( \$(compgen -W "\${line#*	}" -- "\$cur") )
    return
  fi
  if (( COMP_CWORD == 1 )); then
    COMPREPLY=( \$(compgen -W "${roots.join(' ')} help ls version completion" -- "\$cur") )
    return
  fi
  local prefix="\${COMP_WORDS[*]:1:COMP_CWORD-1}"
  COMPREPLY=( \$(compgen -W "\$(printf '%s\\n' "\$data" | cut -f1 | grep "^\$prefix " | awk '{print \$(NF)}' | sort -u)" -- "\$cur") )
}
complete -F _mitrex mitrex
`;
  }

  if (shell === 'zsh') {
    return `#compdef mitrex
# mitrex zsh completion — eval "$(mitrex completion zsh)"
_mitrex() {
  local -a roots
  roots=(${roots.map((r) => `'${r}'`).join(' ')} 'help' 'ls' 'version' 'completion')
  if (( CURRENT == 2 )); then
    _describe 'resource' roots
    return
  fi
  local -a data
  data=(\${(f)"\$(printf '%s' '${data.replace(/'/g, "''")}')"} )
  local prefix="\${words[2,CURRENT-1]}"
  if [[ "\${words[CURRENT]}" == -* ]]; then
    local line="\${data[(r)\${prefix}	*]}"
    _values 'flag' \${=line#*	}
    return
  fi
  local -a next
  next=(\${(u)\${(f)"\$(printf '%s\\n' \$data | cut -f1 | grep "^\${prefix} " | awk '{print \$NF}')"}})
  _describe 'command' next
}
_mitrex "\$@"
`;
  }

  if (shell === 'fish') {
    const lines = [`# mitrex fish completion — mitrex completion fish > ~/.config/fish/completions/mitrex.fish`];
    for (const root of roots) {
      lines.push(`complete -c mitrex -n '__fish_use_subcommand' -a '${root}'`);
    }
    for (const r of rows) {
      for (const flag of r.flags) {
        lines.push(
          `complete -c mitrex -n '__fish_seen_subcommand_from ${r.words[0]}' -l '${flag.replace(/^-+/, '')}'`,
        );
      }
    }
    return `${[...new Set(lines)].join('\n')}\n`;
  }

  return null;
}

export const SHELLS = ['bash', 'zsh', 'fish'];
