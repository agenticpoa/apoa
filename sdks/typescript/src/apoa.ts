import { createClient } from './client.js';
import type {
  APOAClient,
  APOADefinition,
  APOAOptions,
  APOAToken,
  AuthorizationResult,
  AuthorizeOptions,
  Principal,
  Agent,
  ServiceAuthorization,
  SimpleGrantInput,
  SigningOptions,
  ValidationOptions,
  ValidationResult,
} from './types.js';

/**
 * Application-facing APOA facade.
 *
 * This keeps the protocol-level APIs intact while giving app developers a
 * smaller first path: configure once, then use namespaced resources.
 */
export class APOA {
  private readonly client: APOAClient;

  readonly tokens: {
    create: (definition: APOADefinition, options?: SigningOptions) => Promise<APOAToken>;
    createGrant: (input: SimpleGrantInput, options?: SigningOptions) => Promise<APOAToken>;
    validate: (
      token: string | APOAToken,
      options?: Omit<ValidationOptions, 'revocationStore'>
    ) => Promise<ValidationResult>;
    parse: (input: string, format?: 'yaml' | 'json') => APOADefinition;
  };

  readonly authorizations: {
    check: (
      token: APOAToken,
      service: string,
      action: string,
      options?: Omit<AuthorizeOptions, 'revocationStore' | 'auditStore'>
    ) => Promise<AuthorizationResult>;
  };

  constructor(options: APOAOptions = {}) {
    const { privateKey, algorithm, kid, ...clientOptions } = options;

    this.client = createClient({
      ...clientOptions,
      defaultSigningOptions: privateKey
        ? { privateKey, algorithm, kid }
        : undefined,
    });

    this.tokens = {
      create: (definition, signingOptions) =>
        this.client.createToken(definition, signingOptions),
      createGrant: async (input, signingOptions) =>
        this.client.createToken(normalizeGrantInput(input), signingOptions),
      validate: (token, validationOptions) =>
        this.client.validateToken(token, validationOptions),
      parse: (input, format) =>
        this.client.parseDefinition(input, format),
    };

    this.authorizations = {
      check: (token, service, action, authorizeOptions) =>
        this.client.authorize(token, service, action, authorizeOptions),
    };
  }

  async generateKeyPair(algorithm?: 'EdDSA' | 'ES256'): Promise<CryptoKeyPair> {
    return this.client.generateKeyPair(algorithm);
  }
}

function normalizeGrantInput(input: SimpleGrantInput): APOADefinition {
  const errors: string[] = [];

  if (!input || typeof input !== 'object') {
    throw invalidGrantInput(['input must be an object']);
  }

  const principal = normalizePrincipal(input.principal, errors);
  const agent = normalizeAgent(input.agent, errors);
  const services = normalizeServices(input, errors);
  const expires = normalizeExpires(input, errors);

  if (errors.length > 0 || !principal || !agent || services.length === 0 || !expires) {
    throw invalidGrantInput(errors);
  }

  return {
    principal,
    agent,
    services,
    expires,
    ...(input.rules ? { rules: input.rules } : {}),
    ...(input.revocable !== undefined ? { revocable: input.revocable } : {}),
    ...(input.delegatable !== undefined ? { delegatable: input.delegatable } : {}),
    ...(input.maxDelegationDepth !== undefined
      ? { maxDelegationDepth: input.maxDelegationDepth }
      : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
    ...(input.agentProvider ? { agentProvider: input.agentProvider } : {}),
    ...(input.legal ? { legal: input.legal } : {}),
  };
}

function normalizePrincipal(
  principal: SimpleGrantInput['principal'],
  errors: string[]
): Principal | undefined {
  if (typeof principal === 'string' && principal.trim()) {
    return { id: principal.trim() };
  }
  if (principal && typeof principal === 'object' && principal.id) {
    return principal;
  }
  errors.push('principal is required; pass a DID string or { id }');
  return undefined;
}

function normalizeAgent(
  agent: SimpleGrantInput['agent'],
  errors: string[]
): Agent | undefined {
  if (typeof agent === 'string' && agent.trim()) {
    return { id: agent.trim() };
  }
  if (agent && typeof agent === 'object' && agent.id) {
    return agent;
  }
  errors.push('agent is required; pass a DID string or { id }');
  return undefined;
}

function normalizeServices(
  input: SimpleGrantInput,
  errors: string[]
): ServiceAuthorization[] {
  if (input.services) {
    if (!Array.isArray(input.services) || input.services.length === 0) {
      errors.push('services must be a non-empty array when provided');
      return [];
    }
    return input.services;
  }

  if (!input.service) {
    errors.push('service is required unless services is provided');
    return [];
  }
  if (!input.scopes || !Array.isArray(input.scopes) || input.scopes.length === 0) {
    errors.push('scopes must be a non-empty array unless services is provided');
    return [];
  }

  return [{
    service: input.service,
    scopes: input.scopes,
    ...(input.constraints ? { constraints: input.constraints } : {}),
    ...(input.accessMode ? { accessMode: input.accessMode } : {}),
    ...(input.browserConfig ? { browserConfig: input.browserConfig } : {}),
    ...(input.apiConfig ? { apiConfig: input.apiConfig } : {}),
  }];
}

function normalizeExpires(
  input: SimpleGrantInput,
  errors: string[]
): Date | string | undefined {
  if (input.expires && input.expiresIn) {
    errors.push('pass either expires or expiresIn, not both');
    return undefined;
  }
  if (input.expires) {
    return input.expires;
  }
  if (input.expiresIn) {
    return parseDurationFromNow(input.expiresIn);
  }
  errors.push('expires or expiresIn is required');
  return undefined;
}

function parseDurationFromNow(duration: string): Date {
  const match = /^(\d+)([smhd])$/.exec(duration);
  if (!match) {
    throw invalidGrantInput([
      `expiresIn must use a clear duration like '15m', '2h', or '30d'`,
    ]);
  }

  const amount = Number(match[1]);
  if (!Number.isSafeInteger(amount) || amount <= 0) {
    throw invalidGrantInput(['expiresIn duration must be a positive integer']);
  }

  const unitMs: Record<string, number> = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };

  return new Date(Date.now() + amount * unitMs[match[2]]);
}

function invalidGrantInput(errors: string[]): Error {
  return new Error(
    [
      'Invalid APOA grant input.',
      ...errors.map((error) => `- ${error}`),
      'Minimal shape: { principal, agent, service, scopes, expiresIn }',
    ].join('\n')
  );
}
