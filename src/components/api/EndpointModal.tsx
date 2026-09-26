'use client';

import type { RefObject } from 'react';
import { Dialog } from '../shared/Dialog';
import { Notice } from '../profile/BriefingPrimitives';
import { CopyButton, MethodPill, Section } from './primitives';
import { LiveRun } from './LiveRun';
import { RequestFields, useRequestBuilder } from './RequestBuilder';
import { API_FACTS, absoluteUrl } from '../../lib/api-catalog';
import type { ApiEntry } from '../../lib/api-catalog';

/** INPUT and OUTPUT for one endpoint: the URL, the parameters, and a real call. */
export function EndpointModal({
  entry,
  onClose,
  returnFocusTo,
}: {
  entry: ApiEntry | null;
  onClose: () => void;
  returnFocusTo?: RefObject<HTMLElement | null>;
}) {
  if (!entry) return null;
  return <EndpointBody entry={entry} onClose={onClose} returnFocusTo={returnFocusTo} />;
}

/**
 * Split from the exported component so the builder's hooks are never called
 * conditionally: `EndpointModal` returns null when nothing is selected, and a
 * hook above that early return would break the rules of hooks the moment the
 * modal closed.
 */
function EndpointBody({
  entry,
  onClose,
  returnFocusTo,
}: {
  entry: ApiEntry;
  onClose: () => void;
  returnFocusTo?: RefObject<HTMLElement | null>;
}) {
  const builder = useRequestBuilder(entry);
  const url = absoluteUrl(builder.composed);
  const takesVersion = (entry.params ?? []).some((p) => p.name === 'version');

  return (
    <Dialog
      open
      onClose={onClose}
      title={`${entry.method} ${entry.path}`}
      subtitle={entry.summary}
      returnFocusTo={returnFocusTo}
      maxWidth="760px"
      mono
    >
      <div className="space-y-5 px-4 py-4 md:px-6 md:py-5">
        <Section title="Input">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <MethodPill method={entry.method} />
              <code className="min-w-0 break-all font-mono text-xs text-[var(--text-primary)]">{url}</code>
              <CopyButton value={url} label="copy URL" />
            </div>
            <RequestFields entry={entry} builder={builder} />
          </div>
        </Section>

        {entry.paginated && (
          <Section title="Pagination">
            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
              Returns <code className="text-[var(--accent-teal)]">{API_FACTS.pagination.envelope}</code>.{' '}
              {API_FACTS.pagination.noOffset}
            </p>
          </Section>
        )}

        {takesVersion && (
          <Section title="The ?version= contract">
            <p className="text-xs leading-relaxed text-[var(--text-secondary)]">{API_FACTS.versionFilter}</p>
          </Section>
        )}

        <Section title="Output">
          {entry.executable && entry.example ? (
            <LiveRun path={builder.composed} />
          ) : (
            <Notice tone="info" title="No live call for this one">
              {entry.why}
            </Notice>
          )}
        </Section>
      </div>
    </Dialog>
  );
}
