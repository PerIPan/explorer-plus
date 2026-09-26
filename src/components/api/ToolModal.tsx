'use client';

import type { RefObject } from 'react';
import { Dialog } from '../shared/Dialog';
import { Section, ToolParamTable } from './primitives';
import { TOOL_ENDPOINTS } from '../../lib/api-catalog';
import type { ToolDeclaration } from '../../lib/tools/declarations';

/**
 * One agent tool in full. The description and the parameter schema are rendered
 * straight from `TOOL_DECLARATIONS` — the same bytes an MCP client receives —
 * so this page cannot describe a tool differently from how the server does.
 */
export function ToolModal({
  tool,
  onClose,
  returnFocusTo,
}: {
  tool: ToolDeclaration | null;
  onClose: () => void;
  returnFocusTo?: RefObject<HTMLElement | null>;
}) {
  if (!tool) return null;
  const endpoint = TOOL_ENDPOINTS[tool.name];

  return (
    <Dialog open onClose={onClose} title={tool.name} returnFocusTo={returnFocusTo} maxWidth="720px" mono>
      <div className="space-y-5 px-4 py-4 md:px-6 md:py-5">
        <Section title="What it does">
          <p className="text-sm leading-relaxed text-[var(--text-primary)]">{tool.description}</p>
          <p className="mt-2 text-[11px] text-[var(--text-secondary)]">
            Verbatim from the server&rsquo;s tool catalogue — this is the text that steers a model&rsquo;s tool choice,
            not a paraphrase written for this page.
          </p>
        </Section>

        <Section title="Arguments">
          <ToolParamTable parameters={tool.parameters} />
        </Section>

        {endpoint && (
          <Section title="REST route behind it">
            <code className="font-mono text-xs text-[var(--text-primary)]">
              {endpoint.startsWith('/') ? `/api/v1${endpoint}` : endpoint}
            </code>
            <p className="mt-1 text-[11px] leading-snug text-[var(--text-secondary)]">
              Every tool call is an HTTP hop to the same public REST API, which is why an MCP answer and a curl answer
              are identical — and why the REST tab is worth reading even if you only ever use MCP.
            </p>
          </Section>
        )}
      </div>
    </Dialog>
  );
}
