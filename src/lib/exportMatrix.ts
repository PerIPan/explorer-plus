import type { MatrixData } from './types';

interface ExportOptions {
  domain: string;
  sector?: string;
  actors?: { name: string; color: string }[];
  actorLookup?: Map<string, Set<number>>;
  actorColors?: string[];
  theme?: 'dark' | 'light';
  /** Entity filter — only include these technique IDs */
  highlightIds?: Set<string>;
  /** Label for the entity filter badge */
  highlightLabel?: string;
}

/**
 * Generate a standalone HTML file from the current matrix state.
 * Preserves grid layout, cell colors, heatmap, and actor overlay.
 */
export function exportMatrixHtml(data: MatrixData, options: ExportOptions): string {
  const { domain, sector, actors, actorLookup, actorColors, theme = 'dark', highlightIds, highlightLabel } = options;
  const isDark = theme === 'dark';

  const bg = isDark ? '#0f172a' : '#f8fafc';
  const textPrimary = isDark ? '#e2e8f0' : '#1e293b';
  const textSecondary = isDark ? '#94a3b8' : '#64748b';
  const border = isDark ? '#334155' : '#e2e8f0';
  const tealAccent = isDark ? '#64ffda' : '#0d9488';
  const heatR = isDark ? '100,255,218' : '13,148,136';

  const maxUsage = Math.max(...data.flatMap((col) => col.techniques.map((t) => t.subTechniques.length)), 1);

  const domainLabel = domain === 'all' ? 'All Domains' : domain.replace('-attack', '').toUpperCase();
  const title = `ATT&CK Matrix — ${domainLabel}${sector ? ` / ${sector}` : ''}`;
  const dateStr = new Date().toISOString().split('T')[0];

  /** Convert a hex color like #f97316 to rgba with given alpha */
  function hexToRgba(hex: string, alpha: number): string {
    const h = hex.replace('#', '');
    const r = parseInt(h.substring(0, 2), 16);
    const g = parseInt(h.substring(2, 4), 16);
    const b = parseInt(h.substring(4, 6), 16);
    if (isNaN(r) || isNaN(g) || isNaN(b)) return 'transparent';
    return `rgba(${r},${g},${b},${alpha})`;
  }

  function cellBg(attackId: string, subCount: number): string {
    if (actorLookup && actorColors && actorColors.length > 0) {
      const actorSet = actorLookup.get(attackId);
      if (!actorSet) return 'transparent';
      if (actorSet.size === 1) {
        const idx = actorSet.values().next().value!;
        const color = actorColors[idx] ?? tealAccent;
        return hexToRgba(color, 0.55);
      }
      // shared — use teal accent
      return hexToRgba(tealAccent, 0.45);
    }
    if (subCount === 0) return 'transparent';
    const ratio = subCount / maxUsage;
    const opacity = Math.round((0.12 + ratio * 0.63) * 100) / 100;
    return `rgba(${heatR},${opacity})`;
  }

  const filteredData = data.filter((col) => {
    if (highlightIds && highlightIds.size > 0) {
      return col.techniques.some((t) => highlightIds.has(t.attackId));
    }
    if (actorLookup && actorLookup.size > 0) {
      return col.techniques.some((t) => actorLookup.has(t.attackId));
    }
    return true;
  });

  const columns = filteredData.map((col) => {
    // Filter techniques by entity highlight or actor selection
    let visibleTechniques = col.techniques;
    if (highlightIds && highlightIds.size > 0) {
      visibleTechniques = visibleTechniques.filter((t) => highlightIds.has(t.attackId));
    } else if (actorLookup && actorLookup.size > 0) {
      visibleTechniques = visibleTechniques.filter((t) => actorLookup.has(t.attackId));
    }

    const cells = visibleTechniques.map((t) => {
      const background = cellBg(t.attackId, t.subTechniques.length);
      const safeId = escapeHtml(t.attackId);
      const techUrl = `https://mitre-explorer.org/techniques/${safeId}`;
      return `<a href="${techUrl}" target="_blank" style="display:block;padding:4px 6px;border-radius:4px;border:1px solid ${border};font-size:11px;line-height:1.3;background:${background};margin-bottom:3px;text-decoration:none;cursor:pointer;">
        <div style="font-family:monospace;font-size:10px;color:${textSecondary};margin-bottom:2px;">${safeId}</div>
        <div style="color:${textPrimary};overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;">${escapeHtml(t.name)}</div>
        ${t.subTechniques.length > 0 ? `<div style="font-size:10px;color:${textSecondary};margin-top:2px;">▸ ${t.subTechniques.length} sub</div>` : ''}
      </a>`;
    }).join('\n');

    const domainShort = (col.tactic as { domain?: string }).domain
      ? (col.tactic as { domain?: string }).domain!.replace('-attack', '').replace('enterprise', 'ENT').replace('ics', 'ICS').replace('mobile', 'MOBILE')
      : '';
    const domainPillColor = domainShort === 'ENT' ? textSecondary : isDark ? '#f97316' : '#ea580c';

    return `<div style="flex:1;min-width:140px;max-width:200px;">
      <div style="padding:8px 6px;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;color:${tealAccent};border-bottom:2px solid ${tealAccent};margin-bottom:6px;text-align:center;">
        ${domainShort ? `<div style="font-size:9px;font-weight:700;color:${domainPillColor};margin-bottom:2px;">${domainShort}</div>` : ''}
        <a href="https://mitre-explorer.org/?entity=${escapeHtml(col.tactic.attackId)}&tab=tactic-map" target="_blank" style="color:${tealAccent};text-decoration:none;">${escapeHtml(col.tactic.name)}</a><br/>
        <div style="font-size:9px;color:${textSecondary};font-weight:400;font-family:monospace;text-transform:none;margin-top:2px;">${escapeHtml(col.tactic.attackId)}</div>
      </div>
      ${cells}
    </div>`;
  }).join('\n');

  const actorLegend = actors && actors.length > 0
    ? `<div style="display:flex;gap:16px;margin-top:8px;font-size:12px;color:${textSecondary};">
        ${actors.map((a) => `<span style="display:inline-flex;align-items:center;gap:4px;"><span style="width:10px;height:10px;border-radius:50%;background:${escapeHtml(a.color)};display:inline-block;"></span> ${escapeHtml(a.name)}</span>`).join('')}
        <span style="display:inline-flex;align-items:center;gap:4px;"><span style="width:10px;height:10px;border-radius:50%;background:${tealAccent};display:inline-block;"></span> Shared</span>
      </div>`
    : '';

  const domainPill = `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:${isDark ? '#064e3b' : '#ccfbf1'};color:${tealAccent};border:1px solid ${tealAccent}40;margin-left:8px;">${escapeHtml(domainLabel)}</span>`;
  const sectorPill = sector
    ? `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:${isDark ? '#1e1b4b' : '#ede9fe'};color:${isDark ? '#a78bfa' : '#7c3aed'};border:1px solid ${isDark ? '#a78bfa' : '#7c3aed'}40;margin-left:4px;">${escapeHtml(sector)}</span>`
    : '';
  const actorPills = actors && actors.length > 0
    ? actors.map((a) => `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:${isDark ? '#1a1a2e' : '#f5f3ff'};color:${textPrimary};border:1px solid ${escapeHtml(a.color)}60;margin-left:4px;"><span style="width:8px;height:8px;border-radius:50%;background:${escapeHtml(a.color)};display:inline-block;"></span>${escapeHtml(a.name)}</span>`).join('')
    : '';
  const entityPill = highlightLabel
    ? `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:${isDark ? '#0c4a6e' : '#e0f2fe'};color:${isDark ? '#38bdf8' : '#0284c7'};border:1px solid ${isDark ? '#38bdf8' : '#0284c7'}40;margin-left:4px;">⬦ ${escapeHtml(highlightLabel)}</span>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: ${bg}; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 24px; }
  @media print { body { padding: 8px; } .no-print { display: none; } * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; } }
  a { text-decoration: none; }
  a:hover { opacity: 0.8; }
</style>
</head>
<body>
<div style="max-width:100%;overflow-x:auto;">
  <div style="margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
    <div>
      <div style="display:flex;align-items:center;flex-wrap:wrap;">
        <a href="https://mitre-explorer.org/matrix" target="_blank" style="font-size:18px;font-weight:700;color:${textPrimary};">ATT&amp;CK Matrix</a>
        ${domainPill}${sectorPill}${entityPill}${actorPills}
      </div>
      <p style="font-size:12px;color:${textSecondary};margin-top:4px;">Exported ${dateStr} from <a href="https://mitre-explorer.org" target="_blank" style="color:${tealAccent};">mitre-explorer.org</a></p>
    </div>
    <div style="font-size:13px;color:${textSecondary};">
      ${filteredData.reduce((sum, col) => sum + (highlightIds && highlightIds.size > 0 ? col.techniques.filter((t) => highlightIds.has(t.attackId)).length : actorLookup && actorLookup.size > 0 ? col.techniques.filter((t) => actorLookup.has(t.attackId)).length : col.techniques.length), 0)} techniques across ${filteredData.length} tactics
    </div>
  </div>
  ${actorLegend ? `<div style="margin-bottom:12px;">${actorLegend}</div>` : ''}
  <div style="display:flex;gap:4px;align-items:flex-start;">
    ${columns}
  </div>
</div>
<div style="position:fixed;bottom:12px;right:20px;display:flex;align-items:center;gap:6px;opacity:0.5;">
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="16" height="16">
    <g transform="translate(16,16) rotate(45) translate(-11,-11)">
      <rect x="0" y="0" width="10.8" height="10.8" fill="#0d9488" opacity="0.6"/>
      <rect x="11.2" y="0" width="10.8" height="10.8" fill="#0d9488" opacity="0.75"/>
      <rect x="11.2" y="11.2" width="10.8" height="10.8" fill="#0d9488" opacity="0.88"/>
      <rect x="0" y="11.2" width="10.8" height="10.8" fill="#0d9488" opacity="1"/>
    </g>
  </svg>
  <span style="font-size:10px;color:${textSecondary};font-weight:600;letter-spacing:0.03em;">mitre-explorer.org</span>
</div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
