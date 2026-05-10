/**
 * Parse a scope string into its segments.
 * e.g., "appointments:read" → ["appointments", "read"]
 */
export function parseScope(scope: string): string[] {
  if (!scope) return [];
  return scope.split(':');
}

/**
 * Check if a scope pattern matches a requested scope.
 *
 * Rules:
 * 1. Empty pattern or empty requested string never matches (a vacuous match
 *    on `''` would let a token with `scopes: ['']` authorize an empty
 *    action, or vice versa).
 * 2. Root wildcard "*" matches everything (non-empty)
 * 3. Exact match: "appointments:read" matches "appointments:read"
 * 4. Wildcard at level: "appointments:*" matches "appointments:read"
 *    but NOT "appointments:read:summary" (wildcards don't cross levels)
 * 5. Segment-by-segment matching with wildcard support at each level
 */
export function matchScope(pattern: string, requested: string): boolean {
  if (!pattern || !requested) return false;

  // Root wildcard matches everything (non-empty, handled above).
  if (pattern === '*') return true;

  const patternParts = parseScope(pattern);
  const requestedParts = parseScope(requested);

  // Different number of segments — no match (wildcards don't cross levels)
  if (patternParts.length !== requestedParts.length) return false;

  // Match segment by segment. Empty segments (e.g. "foo::bar") never match.
  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i] === '*') continue;
    if (!patternParts[i] || !requestedParts[i]) return false;
    if (patternParts[i] !== requestedParts[i]) return false;
  }

  return true;
}
