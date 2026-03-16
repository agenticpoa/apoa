import type { APOAToken, DelegationDefinition, ServiceAuthorization } from '../types.js';
import { AttenuationViolationError } from '../utils/errors.js';
import { matchScope } from './patterns.js';

/**
 * Verify that a delegation definition is a valid attenuation of a parent token.
 * Throws AttenuationViolationError on any violation.
 *
 * Checks:
 * 1. Child scopes are a subset of parent scopes (per service)
 * 2. Child constraints do not relax parent constraints
 * 3. Child expiration <= parent expiration
 * 4. maxDelegationDepth is not exceeded
 * 5. Child does not add services the parent doesn't have
 * 6. Child rules only add, never remove parent rules
 */
export function verifyAttenuation(
  parent: APOAToken,
  child: DelegationDefinition,
  currentDepth: number = 0
): void {
  const parentDef = parent.definition;

  // Check delegation is allowed
  if (parentDef.delegatable === false) {
    throw new AttenuationViolationError(
      'Parent token does not allow delegation',
      parentDef.services.flatMap((s) => s.scopes),
      child.services.flatMap((s) => s.scopes)
    );
  }

  // Check delegation depth
  if (parentDef.maxDelegationDepth !== undefined) {
    if (currentDepth >= parentDef.maxDelegationDepth) {
      throw new AttenuationViolationError(
        `Delegation depth ${currentDepth + 1} exceeds maxDelegationDepth ${parentDef.maxDelegationDepth}`,
        parentDef.services.flatMap((s) => s.scopes),
        child.services.flatMap((s) => s.scopes)
      );
    }
  }

  // Check expiration: child must expire at or before parent
  if (child.expires !== undefined) {
    const childExp = child.expires instanceof Date
      ? child.expires.getTime()
      : new Date(child.expires).getTime();
    const parentExp = parentDef.expires instanceof Date
      ? parentDef.expires.getTime()
      : new Date(parentDef.expires as string).getTime();

    if (childExp > parentExp) {
      throw new AttenuationViolationError(
        'Child token expiration exceeds parent expiration',
        parentDef.services.flatMap((s) => s.scopes),
        child.services.flatMap((s) => s.scopes)
      );
    }
  }

  // Check each child service against parent
  for (const childService of child.services) {
    const parentService = parentDef.services.find(
      (s) => s.service === childService.service
    );

    if (!parentService) {
      throw new AttenuationViolationError(
        `Child requests service '${childService.service}' not in parent token`,
        parentDef.services.flatMap((s) => s.scopes),
        child.services.flatMap((s) => s.scopes)
      );
    }

    // Check scopes are a subset
    verifyScopeSubset(parentService, childService);

    // Check constraints are not relaxed
    verifyConstraintsNotRelaxed(parentService, childService);
  }

  // Check rules: child can only add, not remove
  if (parentDef.rules && parentDef.rules.length > 0) {
    verifyRulesNotRemoved(parentDef.rules.map((r) => r.id), child);
  }
}

/**
 * Verify every child scope is covered by at least one parent scope.
 */
function verifyScopeSubset(
  parent: ServiceAuthorization,
  child: ServiceAuthorization
): void {
  for (const childScope of child.scopes) {
    const matched = parent.scopes.some((parentScope) =>
      matchScope(parentScope, childScope)
    );
    if (!matched) {
      throw new AttenuationViolationError(
        `Child scope '${childScope}' on service '${child.service}' is not covered by parent scopes [${parent.scopes.join(', ')}]`,
        parent.scopes,
        child.scopes
      );
    }
  }
}

/**
 * Verify child constraints do not relax parent constraints.
 * A constraint set to false in the parent cannot be set to true in the child.
 * New constraints can be added by the child (they only restrict further).
 */
function verifyConstraintsNotRelaxed(
  parent: ServiceAuthorization,
  child: ServiceAuthorization
): void {
  if (!parent.constraints) return;

  for (const [key, parentValue] of Object.entries(parent.constraints)) {
    if (parentValue === false) {
      const childValue = child.constraints?.[key];
      if (childValue === true || childValue === undefined) {
        // If parent says "no signing" (false), child can't enable it (true)
        // or omit it (undefined means no restriction = relaxing)
        if (childValue === true) {
          throw new AttenuationViolationError(
            `Child relaxes constraint '${key}' on service '${child.service}' (parent: false, child: true)`,
            parent.scopes,
            child.scopes
          );
        }
      }
    }
  }
}

/**
 * Verify child does not remove parent rules.
 * Child can add new rules but must preserve all parent rule IDs.
 */
function verifyRulesNotRemoved(
  parentRuleIds: string[],
  child: DelegationDefinition
): void {
  const childRuleIds = new Set(child.rules?.map((r) => r.id) ?? []);
  for (const parentRuleId of parentRuleIds) {
    if (!childRuleIds.has(parentRuleId)) {
      throw new AttenuationViolationError(
        `Child removes parent rule '${parentRuleId}'. Rules can only be added, not removed.`,
        [],
        []
      );
    }
  }
}
