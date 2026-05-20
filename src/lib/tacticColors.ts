// Tactic signature colors — applied wherever a tactic name is rendered so
// users can recognise the kill-chain phase by hue alone.
//
// Listed as literal Tailwind class strings (text-*/bg-*/border-*) so the
// Tailwind content scanner picks them up at build time.

// Single signature color for ALL tactics — they share the orange identity
// across Enterprise, ICS, ATLAS, and Mobile domains. Heat badges (KEV/HOT/WIDE)
// next to the tactic header carry the per-tactic severity signal.
const TACTIC_COLORS = {
  text: 'text-orange-500',
  dot: 'bg-orange-500',
  tint: 'bg-orange-500/10',
  border: 'border-orange-500/40',
};

// Kept as a Record for compatibility with any earlier callers; every key
// returns the same object.
export const TACTIC_COLOR_CLASS = new Proxy({} as Record<string, typeof TACTIC_COLORS>, {
  get() { return TACTIC_COLORS; },
});

export function tacticColors(_name: string | null | undefined) {
  return TACTIC_COLORS;
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
