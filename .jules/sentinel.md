## 2025-10-08 - Use CrawlStart_p.html Endpoint for YaCy Crawl Security Policy Enforcement
**Vulnerability:** Submitting crawl requests to `Crawler_p.html` rather than `CrawlStart_p.html` causes YaCy to ignore security parameters like `ipMustnotmatch` and `mustnotmatch`.
**Learning:** `Crawler_p.html` is the status page UI for YaCy and ignores crawl initiation parameters, whereas `CrawlStart_p.html` is the CGI endpoint that parses and enforces `ipMustnotmatch` (private IP blocklist) and `mustnotmatch` (token/credential exclusion rules).
**Prevention:** Always verify that API requests targeting YaCy crawler endpoints use `CrawlStart_p.html` to guarantee that server-side crawl security restrictions are enforced.
