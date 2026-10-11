# Sentinel Security Journal

## 2025-10-09 - HTML Escaping in Locally Generated Snippets
**Vulnerability:** Inserting raw `sourceUrl`, `pageTitle`, and `date` variables directly into template strings when generating downloadable snippet HTML files could allow malicious page titles or URLs to execute HTML/JS injection when opened locally.
**Learning:** Even for local offline HTML documents, all external dynamic strings interpolated into template literals must be escaped via `escapeHtml` to guarantee safety.
**Prevention:** Always wrap page metadata strings in `escapeHtml(...)` before inserting into innerHTML or HTML file generation templates.
