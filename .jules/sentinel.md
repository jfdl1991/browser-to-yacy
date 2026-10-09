## 2025-10-09 - Stripping Embedded Credentials During URL Sanitization

**Vulnerability:** URLs containing embedded HTTP Basic authentication credentials (e.g. `http://user:pass@example.com/`) retain credentials when parsed into `URL` objects and serialized back via `.toString()`, risking exposure in logs or local P2P crawler API parameters.
**Learning:** Checking `urlObj.username || urlObj.password` in `hasSensitiveData` prevents auto-indexing, but if `sanitizeUrl` is invoked directly (e.g. in manual indexing or snippet canonical URL generation), embedded credentials are not removed unless `cleanUrl.username = ''` and `cleanUrl.password = ''` are explicitly set on the cloned `URL` instance.
**Prevention:** In URL sanitization utilities, explicitly clear `cleanUrl.username` and `cleanUrl.password` alongside stripping query tracking parameters and hashes.
