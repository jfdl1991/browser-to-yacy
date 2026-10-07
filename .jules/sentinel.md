## 2025-02-18 - Broken Regex in Intranet / Local Hostname Filtering
**Vulnerability:** A malformed `LOCALHOST_REGEX` containing literal `\vert{}` syntax instead of standard regex alternation (`|`) failed to match internal network hostnames (`intranet`, `internal`, `network`), creating a potential SSRF / privacy leak vector where internal URLs could be sent to external/peer indexers.
**Learning:** Syntax errors or copy-paste artifacts in regex filters silently break domain/hostname matching without throwing syntax errors.
**Prevention:** Unit test regex expressions explicitly against positive and negative hostnames (e.g. `localhost`, `intranet`, `internal`, `network`, `*.local`) to ensure validation filters fail-closed and correctly match intended target strings.
