import DOMPurify from 'dompurify';

/**
 * Strip all HTML tags and attributes from a string.
 * Returns plain text only.
 */
export function sanitize(html: string): string {
  return DOMPurify.sanitize(html, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
}

/**
 * Strip markdown link syntax but keep the display text.
 * [text](url) becomes text
 */
export function sanitizeMarkdown(text: string): string {
  return text.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1');
}
