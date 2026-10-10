# Sentinel Security Log

## 2025-05-18 - YaCy Crawler API and Userscript Sanitization Verification

**Vulnerability:**
Calling raw crawler endpoints or omitting security parameter constraints (`ipMustnotmatch`, `mustnotmatch`, `noindexWhenCanonicalUnequalURL`) can leak private intranet URLs, dynamic session parameters, or unauthenticated local content into the search index.

**Learning:**
In YaCy, `/Crawler_p.html` is the primary backend crawl servlet API. Using `agentName = 'Custom Agent'` and `crawlingstart = 'on'` along with regex filters (`ipMustnotmatch`, `mustnotmatch`) ensures safe crawling while preventing accidental local resource exposure or peer distribution when `crawlOrder = 'off'`.

**Prevention:**
Always sanitize search parameters, validate protocols and hostnames before initiating external requests, and pass strict exclusion patterns (`ipMustnotmatch`, `mustnotmatch`, `noindexWhenCanonicalUnequalURL`) on API requests to local crawler engines.
