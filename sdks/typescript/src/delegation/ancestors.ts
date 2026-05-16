import type { APOAToken } from '../types.js';

type DelegationLink = {
  parentTokenId?: unknown;
};

type DefinitionLike = {
  parentToken?: unknown;
  delegationChain?: unknown;
};

type TokenLike = {
  parentToken?: unknown;
  definition?: DefinitionLike;
};

/**
 * Return ancestor token IDs referenced by a token-like object.
 *
 * Canonical SDK tokens use `parentToken` for the direct parent. Some transport
 * adapters also carry `definition.delegationChain` snapshots or message
 * metadata with ancestor IDs. This helper normalizes those forms so revocation
 * checks can consistently include every known ancestor.
 */
export function getDelegationAncestorIds(input: APOAToken | TokenLike | DefinitionLike): string[] {
  const ids: string[] = [];
  const seen = new Set<string>();

  const push = (value: unknown): void => {
    if (typeof value !== 'string' || value.length === 0 || seen.has(value)) {
      return;
    }
    seen.add(value);
    ids.push(value);
  };

  const token = input as TokenLike;
  const definition = hasDefinition(input) ? token.definition : (input as DefinitionLike);

  push(token.parentToken);
  push(definition?.parentToken);

  const chain = definition?.delegationChain;
  if (Array.isArray(chain)) {
    for (const link of chain) {
      if (typeof link === 'string') {
        push(link);
      } else if (link && typeof link === 'object') {
        push((link as DelegationLink).parentTokenId);
      }
    }
  }

  return ids;
}

function hasDefinition(input: unknown): input is TokenLike {
  return Boolean(input && typeof input === 'object' && 'definition' in input);
}
