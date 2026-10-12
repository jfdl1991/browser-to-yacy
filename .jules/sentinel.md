## 2025-05-18 - IPv6 Loopback Bypass in Hostname Verification

- **Vulnerability**: IPv6 addresses parsed via `new URL(url).hostname` include square brackets (e.g. `[::1]`), causing regexes like `/^::1$/` or `/^(127\.|::1)/` to fail matching and allow local network requests to bypass security checks.
- **Learning**: Always strip leading and trailing square brackets (`replace(/^\[|\]$/g, '')`) from URL hostnames before evaluating against IP filtering rules.
- **Prevention**: Use host normalization functions when applying IP access controls or blacklists to hostnames.
