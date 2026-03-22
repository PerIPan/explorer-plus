interface PaginationProps {
  page: number;
  totalPages: number;
  total: number;
  limit: number;
  onPageChange: (page: number) => void;
}

/**
 * Page controls: prev, numbered pages, next, and item count summary.
 */
export function Pagination({
  page,
  totalPages,
  total,
  limit,
  onPageChange,
}: PaginationProps) {
  const from = (page - 1) * limit + 1;
  const to = Math.min(page * limit, total);

  /** Build a compact page-number array with ellipses */
  function buildPageNumbers(): Array<number | '...'> {
    if (totalPages <= 7) {
      return Array.from({ length: totalPages }, (_, i) => i + 1);
    }
    const pages: Array<number | '...'> = [1];
    if (page > 3) pages.push('...');
    for (let p = Math.max(2, page - 1); p <= Math.min(totalPages - 1, page + 1); p++) {
      pages.push(p);
    }
    if (page < totalPages - 2) pages.push('...');
    pages.push(totalPages);
    return pages;
  }

  const pages = buildPageNumbers();

  return (
    <div className="flex items-center justify-between gap-4 py-3">
      {/* Item count */}
      <div className="text-xs text-[#8892b0]">
        {total === 0 ? 'No results' : `${from}–${to} of ${total.toLocaleString()}`}
      </div>

      {/* Controls */}
      {totalPages > 1 && (
        <div className="flex items-center gap-1">
          {/* Prev */}
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            aria-label="Previous page"
            className="
              px-2 py-1 rounded text-sm text-[#8892b0]
              hover:text-[#ccd6f6] hover:bg-[#ffffff08]
              disabled:opacity-30 disabled:cursor-not-allowed
              transition-colors duration-150
            "
          >
            &lsaquo;
          </button>

          {/* Page numbers */}
          {pages.map((p, i) =>
            p === '...' ? (
              <span
                key={`ellipsis-${i}`}
                className="px-2 py-1 text-sm text-[#8892b0]"
                aria-hidden="true"
              >
                &hellip;
              </span>
            ) : (
              <button
                key={p}
                onClick={() => onPageChange(p)}
                aria-label={`Page ${p}`}
                aria-current={p === page ? 'page' : undefined}
                className={`
                  px-2.5 py-1 rounded text-sm transition-colors duration-150
                  ${
                    p === page
                      ? 'bg-[#64ffda18] text-[#64ffda] border border-[#64ffda33]'
                      : 'text-[#8892b0] hover:text-[#ccd6f6] hover:bg-[#ffffff08]'
                  }
                `}
              >
                {p}
              </button>
            )
          )}

          {/* Next */}
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            aria-label="Next page"
            className="
              px-2 py-1 rounded text-sm text-[#8892b0]
              hover:text-[#ccd6f6] hover:bg-[#ffffff08]
              disabled:opacity-30 disabled:cursor-not-allowed
              transition-colors duration-150
            "
          >
            &rsaquo;
          </button>
        </div>
      )}
    </div>
  );
}
