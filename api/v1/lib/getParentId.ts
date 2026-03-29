/**
 * Extract the parent technique ID from an ATT&CK or ATLAS ID.
 * Strips only the 3-digit sub-technique suffix.
 *
 * T1059.001  → T1059
 * AML.T0051.001 → AML.T0051
 * AML.T0051 → AML.T0051 (no change)
 * T1059 → T1059 (no change)
 */
export function getParentId(attackId: string): string {
  return attackId.replace(/\.\d{3}$/, '');
}
