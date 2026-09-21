import Link from 'next/link';

/**
 * Cross-link from a /frameworks/* reference page to the same framework's
 * /compliance/[key] page.
 *
 * The two views answer different questions about one framework: /frameworks/*
 * renders the document's own structure (the CSF subcategory tree, the 800-53
 * control list), while /compliance/[key] shows the SCF-derived ATT&CK mapping
 * grouped by section. Readers who land on one usually want the other, and
 * nothing connected them.
 */
export function ComplianceLink({ frameworkKey, label = 'ATT&CK mapping' }: {
  frameworkKey: string;
  label?: string;
}) {
  return (
    <Link
      href={`/compliance/${frameworkKey}`}
      className="inline-flex items-center gap-1.5 rounded-md border border-[var(--border-color)] px-2.5 py-1 text-xs text-[var(--accent-teal)] hover:bg-[var(--hover-overlay)] transition-colors whitespace-nowrap"
      title={`Open this framework on the Compliance page, with its sections and mapped ATT&CK techniques`}
    >
      <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 010 5.656l-3 3a4 4 0 01-5.656-5.656l1.5-1.5M10.172 13.828a4 4 0 010-5.656l3-3a4 4 0 015.656 5.656l-1.5 1.5" />
      </svg>
      {label}
    </Link>
  );
}
