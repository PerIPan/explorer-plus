import type { MatrixData } from './types';

interface ExportOptions {
  domain: string;
  sector?: string;
  actors?: { name: string; color: string }[];
  actorLookup?: Map<string, Set<number>>;
  actorColors?: string[];
  theme?: 'dark' | 'light';
}

/**
 * Generate a standalone HTML file from the current matrix state.
 * Preserves grid layout, cell colors, heatmap, and actor overlay.
 */
export function exportMatrixHtml(data: MatrixData, options: ExportOptions): string {
  const { domain, sector, actors, actorLookup, actorColors, theme = 'dark' } = options;
  const isDark = theme === 'dark';

  const bg = isDark ? '#0f172a' : '#f8fafc';
  const cardBg = isDark ? '#1e293b' : '#ffffff';
  const textPrimary = isDark ? '#e2e8f0' : '#1e293b';
  const textSecondary = isDark ? '#94a3b8' : '#64748b';
  const border = isDark ? '#334155' : '#e2e8f0';
  const tealAccent = isDark ? '#64ffda' : '#0d9488';
  const heatR = isDark ? '100,255,218' : '13,148,136';

  const maxUsage = Math.max(...data.flatMap((col) => col.techniques.map((t) => t.subTechniques.length)), 1);

  const domainLabel = domain === 'all' ? 'All Domains' : domain.replace('-attack', '').toUpperCase();
  const title = `ATT&CK Matrix — ${domainLabel}${sector ? ` / ${sector}` : ''}`;
  const dateStr = new Date().toISOString().split('T')[0];

  function cellBg(attackId: string, subCount: number): string {
    if (actorLookup && actorColors) {
      const actors = actorLookup.get(attackId);
      if (!actors) return 'transparent';
      if (actors.size === 1) {
        const idx = actors.values().next().value!;
        const color = actorColors[idx];
        return `color-mix(in srgb, ${color} 55%, transparent)`;
      }
      // shared
    }
    if (subCount === 0) return 'transparent';
    const ratio = subCount / maxUsage;
    const opacity = Math.round((0.12 + ratio * 0.63) * 100) / 100;
    return `rgba(${heatR},${opacity})`;
  }

  const columns = data.map((col) => {
    const cells = col.techniques.map((t) => {
      const bg = cellBg(t.attackId, t.subTechniques.length);
      return `<div style="padding:4px 6px;border-radius:4px;border:1px solid ${border};font-size:11px;line-height:1.3;background:${bg};margin-bottom:3px;">
        <div style="font-family:monospace;font-size:10px;color:${textSecondary};margin-bottom:2px;">${t.attackId}</div>
        <div style="color:${textPrimary};overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;">${escapeHtml(t.name)}</div>
        ${t.subTechniques.length > 0 ? `<div style="font-size:10px;color:${textSecondary};margin-top:2px;">▸ ${t.subTechniques.length} sub</div>` : ''}
      </div>`;
    }).join('\n');

    return `<div style="flex:1;min-width:140px;max-width:200px;">
      <div style="padding:8px 6px;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;color:${tealAccent};border-bottom:2px solid ${tealAccent};margin-bottom:6px;text-align:center;">
        ${escapeHtml(col.tactic.name)}<br/>
        <span style="font-size:10px;color:${textSecondary};font-weight:400;text-transform:none;">${col.techniques.length} techniques</span>
      </div>
      ${cells}
    </div>`;
  }).join('\n');

  const actorLegend = actors && actors.length > 0
    ? `<div style="display:flex;gap:16px;margin-top:8px;font-size:12px;color:${textSecondary};">
        ${actors.map((a) => `<span style="display:inline-flex;align-items:center;gap:4px;"><span style="width:10px;height:10px;border-radius:50%;background:${a.color};display:inline-block;"></span> ${escapeHtml(a.name)}</span>`).join('')}
        <span style="display:inline-flex;align-items:center;gap:4px;"><span style="width:10px;height:10px;border-radius:50%;background:${tealAccent};display:inline-block;"></span> Shared</span>
      </div>`
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
  @media print { body { padding: 8px; } .no-print { display: none; } }
</style>
</head>
<body>
<div style="max-width:100%;overflow-x:auto;">
  <div style="margin-bottom:16px;">
    <h1 style="font-size:18px;font-weight:700;color:${textPrimary};margin-bottom:4px;">${escapeHtml(title)}</h1>
    <p style="font-size:12px;color:${textSecondary};">Exported ${dateStr} from mitre-explorer.org</p>
    ${actorLegend}
  </div>
  <div style="display:flex;gap:4px;align-items:flex-start;">
    ${columns}
  </div>
  <div style="margin-top:16px;font-size:11px;color:${textSecondary};">
    ${data.reduce((sum, col) => sum + col.techniques.length, 0)} techniques across ${data.length} tactics
  </div>
</div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
