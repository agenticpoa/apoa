const DEFAULT_CLOCK_SKEW = 30;
const MAX_CLOCK_SKEW = 300;

/**
 * Normalize clock skew to a valid value in seconds.
 */
function normalizeSkew(clockSkew?: number): number {
  if (clockSkew === undefined) return DEFAULT_CLOCK_SKEW;
  if (clockSkew < 0) return 0;
  return Math.min(clockSkew, MAX_CLOCK_SKEW);
}

/**
 * Parse a date value (Date object or ISO string) into a Date.
 */
function toDate(value: Date | string): Date {
  return value instanceof Date ? value : new Date(value);
}

/**
 * Check if a token/date has expired, accounting for clock skew.
 * Returns true if the current time is past the expiration (plus tolerance).
 */
export function isExpired(
  expires: Date | string,
  clockSkew?: number,
  now?: Date
): boolean {
  const expiresDate = toDate(expires);
  const skew = normalizeSkew(clockSkew);
  const currentTime = now ?? new Date();
  return currentTime.getTime() > expiresDate.getTime() + skew * 1000;
}

/**
 * Check if the current time is before the notBefore date, accounting for clock skew.
 * Returns true if it's too early to use this token.
 */
export function isBeforeNotBefore(
  notBefore: Date | string,
  clockSkew?: number,
  now?: Date
): boolean {
  const notBeforeDate = toDate(notBefore);
  const skew = normalizeSkew(clockSkew);
  const currentTime = now ?? new Date();
  return currentTime.getTime() < notBeforeDate.getTime() - skew * 1000;
}
