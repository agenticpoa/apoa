import type {
  APOAToken,
  APOADefinition,
  DelegationDefinition,
  SigningOptions,
} from '../types.js';
import { createToken } from '../token/create.js';
import { verifyAttenuation } from '../scope/attenuate.js';

/**
 * Create a delegated (attenuated) token from a parent token.
 *
 * - Inherits principal from parent (cannot be overridden)
 * - Sets parentToken on child to parent's jti
 * - Enforces attenuation rules
 * - Additional rules can only be added, not removed
 */
export async function delegate(
  parentToken: APOAToken,
  childDef: DelegationDefinition,
  options: SigningOptions
): Promise<APOAToken> {
  // Calculate current delegation depth
  // For now, depth is 0 for direct children of the root.
  // In a full chain, this would be tracked. The parent's depth context
  // is determined by counting parentToken links, but for single-level
  // delegation we pass 0 (first delegation).
  const currentDepth = countDepth(parentToken);

  // Verify attenuation rules
  verifyAttenuation(parentToken, childDef, currentDepth);

  // Build the child definition, inheriting principal from parent
  const parentDef = parentToken.definition;

  // Merge rules: start with parent rules, add child-specific ones
  const parentRules = parentDef.rules ?? [];
  const childExtraRules = (childDef.rules ?? []).filter(
    (cr) => !parentRules.some((pr) => pr.id === cr.id)
  );
  const mergedRules = [...parentRules, ...childExtraRules];

  // Track delegation depth in metadata so deep chains are properly limited
  const childDepth = currentDepth + 1;
  const childMetadata = {
    ...childDef.metadata,
    _delegationDepth: childDepth,
  };

  // Inherit parent's false constraints into child services.
  // If parent says { signing: false }, the child MUST carry that constraint
  // even if the delegation definition omits it. Otherwise the child's
  // authorize() would skip the constraint check entirely (privilege escalation).
  const inheritedServices = childDef.services.map((childSvc) => {
    const parentSvc = parentDef.services.find((s) => s.service === childSvc.service);
    if (!parentSvc?.constraints) return childSvc;

    const inherited: Record<string, import('../types.js').ConstraintValue> = {};
    for (const [key, value] of Object.entries(parentSvc.constraints)) {
      if (value === false) {
        inherited[key] = false;
      }
    }
    if (Object.keys(inherited).length === 0) return childSvc;

    return {
      ...childSvc,
      constraints: { ...inherited, ...childSvc.constraints },
    };
  });

  const fullDefinition: APOADefinition = {
    principal: parentDef.principal, // Inherited — cannot be overridden
    agent: childDef.agent,
    agentProvider: parentDef.agentProvider,
    services: inheritedServices,
    rules: mergedRules.length > 0 ? mergedRules : undefined,
    expires: childDef.expires ?? parentDef.expires,
    revocable: parentDef.revocable,
    delegatable: parentDef.delegatable,
    maxDelegationDepth: parentDef.maxDelegationDepth,
    metadata: childMetadata,
    legal: parentDef.legal,
  };

  // Pass parentTokenId so it's included in the signed JWT payload
  const childToken = await createToken(fullDefinition, options, parentToken.jti);

  return childToken;
}

/**
 * Count delegation depth from a token's definition.
 *
 * We track depth explicitly: when delegate() creates a child token,
 * it stores the current depth in metadata._delegationDepth.
 * A root token has no depth (0). A direct child has depth 1, etc.
 */
function countDepth(token: APOAToken): number {
  const stored = token.definition.metadata?._delegationDepth;
  if (typeof stored === 'number') return stored;
  // No stored depth — this is either a root token or a legacy token.
  // Fall back to checking parentToken as a heuristic.
  return token.parentToken ? 1 : 0;
}
