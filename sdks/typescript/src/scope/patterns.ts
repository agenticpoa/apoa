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
 * 1. Root wildcard "*" matches everything
 * 2. Exact match: "appointments:read" matches "appointments:read"
 * 3. Wildcard at level: "appointments:*" matches "appointments:read"
 *    but NOT "appointments:read:summary" (wildcards don't cross levels)
 * 4. Segment-by-segment matching with wildcard support at each level
 */
export function matchScope(pattern: string, requested: string): boolean {
  // Root wildcard matches everything
  if (pattern === '*') return true;

  const patternParts = parseScope(pattern);
  const requestedParts = parseScope(requested);

  // Different number of segments — no match (wildcards don't cross levels)
  if (patternParts.length !== requestedParts.length) return false;

  // Match segment by segment
  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i] === '*') continue;
    if (patternParts[i] !== requestedParts[i]) return false;
  }

  return true;
}
