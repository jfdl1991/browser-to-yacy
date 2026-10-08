# Bolt's Performance Journal

## 2025-10-07 - Avoid Array Spreading in Hot Code Paths
**Learning:** In Userscripts triggered on every URL change/SPA navigation, spreading `Set` instances into arrays (`[...set]`) inside functions like `hasSensitiveData` and `isDomainBlacklisted` causes unnecessary heap allocations and loop overhead on every URL check. Pre-compiling regexes or using direct `for...of` iteration over Sets avoids object allocation and speeds up evaluation by ~5x.
**Action:** Always pre-compile pattern regexes at module scope and iterate directly over `Set` or `Array` without spread conversion in frequently evaluated functions.
