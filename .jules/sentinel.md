## 2025-10-24 - HTML Attribute and Text Injection in Generated Local Snippet Files

**Vulnerability:** Unescaped `sourceUrl` and `date` variables were directly interpolated into HTML template strings inside `saveHtmlFile` (e.g. `<link rel="canonical" href="${sourceUrl}">`, `<base href="${sourceUrl}">`, `<a href="${sourceUrl}">${sourceUrl}</a>`, `<p>...${date}</p>`). A malicious page URL or title containing double quotes or HTML tags could break out of attribute quotes or inject HTML into the saved snippet file.

**Learning:** While `pageTitle` was escaped with `escapeHtml`, `sourceUrl` and `date` were assumed safe. Any untrusted string interpolated into HTML markup or attribute contexts must be properly entity-escaped using `escapeHtml`.

**Prevention:** Always run `escapeHtml` on all dynamic values (`sourceUrl`, `date`, `pageTitle`, etc.) before injecting them into HTML template strings or document markup.
