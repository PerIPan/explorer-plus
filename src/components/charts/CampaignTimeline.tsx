interface CampaignTimelineProps {
  firstSeen: string | null;
  lastSeen: string | null;
  name: string;
}

/**
 * Simple horizontal bar showing a campaign's time range.
 */
export function CampaignTimeline({ firstSeen, lastSeen, name }: CampaignTimelineProps) {
  if (!firstSeen && !lastSeen) return null;

  const start = firstSeen ? new Date(firstSeen) : null;
  const end = lastSeen ? new Date(lastSeen) : new Date();
  const now = new Date();

  /** Use a fixed reference window: 2010-01-01 to now */
  const windowStart = new Date('2010-01-01').getTime();
  const windowEnd = now.getTime();
  const windowRange = windowEnd - windowStart;

  const barStart = start
    ? Math.max(0, (start.getTime() - windowStart) / windowRange) * 100
    : 0;
  const barEnd = end
    ? Math.min(100, (end.getTime() - windowStart) / windowRange) * 100
    : 100;
  const barWidth = Math.max(0.5, barEnd - barStart);

  function fmt(d: Date) {
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short' });
  }

  return (
    <div className="mt-4">
      <div className="flex justify-between text-xs text-[#8892b0] mb-1">
        <span>{firstSeen ? fmt(new Date(firstSeen)) : 'Unknown start'}</span>
        <span>{lastSeen ? fmt(new Date(lastSeen)) : 'Ongoing'}</span>
      </div>

      <div
        className="relative h-6 rounded bg-[#16213e] border border-[#2a2a4a] overflow-hidden"
        role="img"
        aria-label={`Campaign ${name} timeline`}
      >
        {/* Background track labels */}
        <div className="absolute inset-0 flex items-center px-2">
          <span className="text-[10px] text-[#2a2a4a] font-mono select-none">2010</span>
          <span className="text-[10px] text-[#2a2a4a] font-mono select-none ml-auto">
            {now.getFullYear()}
          </span>
        </div>

        {/* Campaign bar */}
        <div
          className="absolute top-1 bottom-1 rounded bg-[#60a5fa] opacity-80"
          style={{ left: `${barStart}%`, width: `${barWidth}%` }}
        />
      </div>
    </div>
  );
}
