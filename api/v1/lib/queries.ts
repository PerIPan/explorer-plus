/**
 * Builds a full-text search WHERE condition using PostgreSQL tsvector.
 * Returns the clause template and the param value separately so the caller
 * can splice the param into their own positional-parameter array.
 */
export function buildSearchCondition(
  searchTerm: string,
): { clause: string; param: string } {
  return {
    clause: `to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')) @@ plainto_tsquery('english', $PARAM)`,
    param: searchTerm,
  };
}

/**
 * Builds LIMIT / OFFSET clause and returns the numeric offset value.
 */
export function buildPaginationClause(
  page: number,
  limit: number,
): { clause: string; offset: number } {
  const offset = (page - 1) * limit;
  return { clause: `LIMIT ${limit} OFFSET ${offset}`, offset };
}

/**
 * Builds an ORDER BY clause, whitelisting against allowedColumns to prevent
 * SQL injection from user-supplied sort parameters.
 */
export function buildSortClause(
  sort: string,
  order: string,
  allowedColumns: string[],
): string {
  const col = allowedColumns.includes(sort) ? sort : allowedColumns[0];
  const dir = order === 'desc' ? 'DESC' : 'ASC';
  return `ORDER BY ${col} ${dir}`;
}
