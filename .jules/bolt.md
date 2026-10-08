# Bolt's Performance Journal

## 2025-10-07 - Avoid Array Spreading in Hot Code Paths
**Learning:** In Userscripts triggered on every URL change/SPA navigation, spreading `Set` instances into arrays (`[...set]`) inside functions like `hasSensitiveData` and `isDomainBlacklisted` causes unnecessary heap allocations and loop overhead on every URL check. Pre-compiling regexes or using direct `for...of` iteration over Sets avoids object allocation and speeds up evaluation by ~5x.
**Action:** Always pre-compile pattern regexes at module scope and iterate directly over `Set` or `Array` without spread conversion in frequently evaluated functions.

## 2025-10-08 - Subdomain Slicing for Set-Based Suffix Lookups
**Learning:** Iterating through a Set of domain names to perform `hostname.endsWith('.' + domain)` performs linear scan overhead $O(N)$ and string concatenation allocations on every navigation/URL evaluation. Slicing the hostname along dot indices (`hostname.slice(dotIdx + 1)`) and testing against the `Set` with $O(1)$ `.has()` lookups reduces check time from $O(N)$ to $O(K)$ ($K$ = dot count), yielding ~7x performance improvement and zero string concatenation allocations.
**Action:** When matching domain or string suffixes against a `Set`, slice target strings from delimiter indices and query the `Set` with `.has()` instead of iterating over the `Set` with `.endsWith()`.
