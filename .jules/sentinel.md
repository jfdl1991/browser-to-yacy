## 2025-10-08 - Include URL Fragments (#hash) in Sensitive Data Sanitization Checks
**Vulnerability:** `hasSensitiveData()` omitted `urlObj.hash` when constructing `fullPath`, allowing URLs with sensitive tokens in fragment identifiers (such as OAuth implicit grant `#access_token=...`, `#id_token=...`, `#session=...`) to bypass privacy filters.
**Learning:** URL fragments are frequently used in modern Single Page Applications (SPAs) and authentication flows to transmit sensitive tokens, but standard path/search evaluations do not inspect `urlObj.hash`.
**Prevention:** Always include `urlObj.hash` when evaluating URLs for sensitive parameters and credential patterns.
