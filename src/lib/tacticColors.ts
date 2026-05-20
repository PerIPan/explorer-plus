// Tactic signature colors — applied wherever a tactic name is rendered so
// users can recognise the kill-chain phase by hue alone.
//
// Listed as literal Tailwind class strings (text-*/bg-*/border-*) so the
// Tailwind content scanner picks them up at build time.

export const TACTIC_COLOR_CLASS: Record<
  string,
  { text: string; dot: string; tint: string; border: string }
> = {
  'Reconnaissance':        { text: 'text-sky-400',    dot: 'bg-sky-400',    tint: 'bg-sky-400/10',    border: 'border-sky-400/40' },
  'Resource Development':  { text: 'text-teal-400',   dot: 'bg-teal-400',   tint: 'bg-teal-400/10',   border: 'border-teal-400/40' },
  'Initial Access':        { text: 'text-blue-500',   dot: 'bg-blue-500',   tint: 'bg-blue-500/10',   border: 'border-blue-500/40' },
  'Execution':             { text: 'text-purple-500', dot: 'bg-purple-500', tint: 'bg-purple-500/10', border: 'border-purple-500/40' },
  'Persistence':           { text: 'text-indigo-500', dot: 'bg-indigo-500', tint: 'bg-indigo-500/10', border: 'border-indigo-500/40' },
  'Privilege Escalation':  { text: 'text-violet-500', dot: 'bg-violet-500', tint: 'bg-violet-500/10', border: 'border-violet-500/40' },
  'Defense Evasion':       { text: 'text-slate-400',  dot: 'bg-slate-400',  tint: 'bg-slate-400/10',  border: 'border-slate-400/40' },
  'Credential Access':     { text: 'text-yellow-500', dot: 'bg-yellow-500', tint: 'bg-yellow-500/10', border: 'border-yellow-500/40' },
  'Discovery':             { text: 'text-lime-500',   dot: 'bg-lime-500',   tint: 'bg-lime-500/10',   border: 'border-lime-500/40' },
  'Lateral Movement':      { text: 'text-green-500',  dot: 'bg-green-500',  tint: 'bg-green-500/10',  border: 'border-green-500/40' },
  'Collection':            { text: 'text-amber-500',  dot: 'bg-amber-500',  tint: 'bg-amber-500/10',  border: 'border-amber-500/40' },
  'Command and Control':   { text: 'text-orange-500', dot: 'bg-orange-500', tint: 'bg-orange-500/10', border: 'border-orange-500/40' },
  'Exfiltration':          { text: 'text-red-400',    dot: 'bg-red-400',    tint: 'bg-red-400/10',    border: 'border-red-400/40' },
  'Impact':                { text: 'text-rose-500',   dot: 'bg-rose-500',   tint: 'bg-rose-500/10',   border: 'border-rose-500/40' },
};

const FALLBACK = {
  text: 'text-[var(--text-secondary)]',
  dot: 'bg-[var(--text-secondary)]',
  tint: 'bg-[var(--hover-overlay)]',
  border: 'border-[var(--border-color)]',
};

export function tacticColors(name: string | null | undefined) {
  if (!name) return FALLBACK;
  return TACTIC_COLOR_CLASS[name] ?? FALLBACK;
}

// Enterprise ATT&CK kill-chain order. Unknown tactics sort at the end.
export const TACTIC_ORDER: Record<string, number> = {
  'Reconnaissance':        1,
  'Resource Development':  2,
  'Initial Access':        3,
  'Execution':             4,
  'Persistence':           5,
  'Privilege Escalation':  6,
  'Defense Evasion':       7,
  'Credential Access':     8,
  'Discovery':             9,
  'Lateral Movement':     10,
  'Collection':           11,
  'Command and Control':  12,
  'Exfiltration':         13,
  'Impact':               14,
};

export function tacticOrder(name: string | null | undefined): number {
  if (!name) return 99;
  return TACTIC_ORDER[name] ?? 50;
}
