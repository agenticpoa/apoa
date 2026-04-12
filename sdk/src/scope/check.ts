import type {
  APOAToken,
  AuthorizeOptions,
  AuthorizationResult,
  RuleViolation,
  ScopeCheckResult,
} from '../types.js';
import { matchScope } from './patterns.js';

/**
 * Check if an action is allowed under a token's scopes for a given service.
 * Synchronous — no rules, no revocation, just scope matching.
 */
export function checkScope(
  token: APOAToken,
  service: string,
  action: string
): ScopeCheckResult {
  const serviceAuth = token.definition.services.find(
    (s) => s.service === service
  );

  if (!serviceAuth) {
    return {
      allowed: false,
      reason: `service '${service}' not found in token`,
    };
  }

  for (const scope of serviceAuth.scopes) {
    if (matchScope(scope, action)) {
      return {
        allowed: true,
        reason: `matched scope '${scope}'`,
        matchedScope: scope,
      };
    }
  }

  return {
    allowed: false,
    reason: `scope '${action}' not in authorized scopes`,
  };
}

/**
 * Check a specific constraint on a service.
 * Returns allowed: false if the constraint is explicitly set to false.
 * Returns allowed: true if the constraint is not set or is truthy.
 */
export function checkConstraint(
  token: APOAToken,
  service: string,
  constraint: string
): ScopeCheckResult {
  const serviceAuth = token.definition.services.find(
    (s) => s.service === service
  );

  if (!serviceAuth) {
    return {
      allowed: false,
      reason: `service '${service}' not found in token`,
    };
  }

  if (!serviceAuth.constraints) {
    return {
      allowed: true,
      reason: `no constraints defined for service '${service}'`,
    };
  }

  const value = serviceAuth.constraints[constraint];

  if (value === undefined) {
    return {
      allowed: true,
      reason: `constraint '${constraint}' not defined`,
    };
  }

  if (value === false) {
    return {
      allowed: false,
      reason: `constraint '${constraint}' is set to false`,
      constraint,
    };
  }

  return {
    allowed: true,
    reason: `constraint '${constraint}' is set to ${JSON.stringify(value)}`,
  };
}

/**
 * One-stop authorization check: revocation + scope + constraints + rules.
 *
 * Enforcement order:
 * 1. Check revocation (is the token still alive?)
 * 2. Check scope (is the action in the authorized scope set?)
 * 3. Check constraints (only the action's top-level segment is checked
 *    against constraint keys — e.g. action "signing:submit" checks
 *    constraint "signing". Use checkConstraint() for explicit checks.)
 * 4. Check hard rules (hard rules whose id appears as a prefix of the
 *    action → deny. e.g. rule "no-messaging" blocks "messaging:send")
 * 5. Check soft rules (all soft rules → log violation + continue)
 */
export async function authorize(
  token: APOAToken,
  service: string,
  action: string,
  options?: AuthorizeOptions
): Promise<AuthorizationResult> {
  // 1. Check revocation
  if (options?.revocationStore) {
    const record = await options.revocationStore.check(token.jti);
    if (record) {
      return {
        authorized: false,
        reason: 'token has been revoked',
        checks: { revoked: true },
      };
    }
  }

  // 2. Check scope
  const scopeResult = checkScope(token, service, action);
  if (!scopeResult.allowed) {
    return {
      authorized: false,
      reason: scopeResult.reason,
      checks: { revoked: false, scopeAllowed: false },
    };
  }

  // 3. Check constraints — only deny if the action's top-level segment
  //    matches a constraint key that is set to false.
  //    e.g. action "signing:submit" is blocked by constraint { signing: false }
  //    but action "appointments:read" is NOT blocked by { signing: false }
  const serviceAuth = token.definition.services.find(
    (s) => s.service === service
  );
  if (serviceAuth?.constraints) {
    const actionSegments = action.split(':');
    for (const [key, value] of Object.entries(serviceAuth.constraints)) {
      if (value === false && actionSegments.includes(key)) {
        return {
          authorized: false,
          reason: `constraint '${key}' is set to false`,
          checks: { revoked: false, scopeAllowed: true, constraintsPassed: false },
        };
      }
    }
  }

  // 4 & 5. Check rules
  const rules = token.definition.rules;
  const violations: RuleViolation[] = [];

  if (rules && rules.length > 0) {
    // 4. Hard rules — deny if the action matches the rule.
    //    Matching: extract the key from the rule id (strip "no-" prefix if present)
    //    and check if it appears as a SEGMENT in the action (split on ':').
    //    e.g. rule "no-messaging" → key "messaging" → blocks "messaging:send"
    //    e.g. rule "no-signing"   → key "signing"   → blocks "signing:submit"
    //    e.g. rule "no-signing"   → key "signing"   → does NOT block "appointments:read"
    //    e.g. rule "no-read"      → key "read"      → does NOT block "threading:update"
    for (const rule of rules) {
      if (rule.enforcement === 'hard') {
        const ruleKey = rule.id.startsWith('no-') ? rule.id.slice(3) : rule.id;
        const actionSegments = action.toLowerCase().split(':');
        if (actionSegments.includes(ruleKey.toLowerCase())) {
          return {
            authorized: false,
            reason: `hard rule '${rule.id}' violated`,
            checks: {
              revoked: false,
              scopeAllowed: true,
              constraintsPassed: true,
              rulesPassed: false,
            },
          };
        }
      }
    }

    // 5. Soft rules — log violations, invoke callbacks, continue
    for (const rule of rules) {
      if (rule.enforcement === 'soft') {
        const violation: RuleViolation = {
          ruleId: rule.id,
          tokenId: token.jti,
          action,
          service,
          timestamp: new Date(),
          details: rule.description,
        };
        violations.push(violation);

        // Log to audit store if available
        if (options?.auditStore) {
          await options.auditStore.append({
            tokenId: token.jti,
            timestamp: violation.timestamp,
            action,
            service,
            result: 'escalated',
            details: { ruleId: rule.id, ruleDescription: rule.description },
          });
        }

        // Invoke onViolation callback if provided
        if (rule.onViolation) {
          await rule.onViolation(violation);
        }
      }
    }
  }

  return {
    authorized: true,
    checks: {
      revoked: false,
      scopeAllowed: true,
      constraintsPassed: true,
      rulesPassed: true,
    },
    violations: violations.length > 0 ? violations : undefined,
  };
}
