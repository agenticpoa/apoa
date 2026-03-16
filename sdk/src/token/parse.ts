import type { APOADefinition } from '../types.js';
import { DefinitionValidationError } from '../utils/errors.js';

/**
 * Parse a YAML or JSON definition string into an APOADefinition.
 * Auto-detects format: starts with '{' = JSON, otherwise YAML.
 * Validates required fields, metadata constraints, browser mode config,
 * and legal framework fields. Throws DefinitionValidationError with all
 * problems found.
 */
export function parseDefinition(
  input: string,
  format?: 'yaml' | 'json'
): APOADefinition {
  const detectedFormat = format ?? (input.trimStart().startsWith('{') ? 'json' : 'yaml');
  let raw: unknown;

  try {
    if (detectedFormat === 'json') {
      raw = JSON.parse(input);
    } else {
      // Lazy-load yaml to keep it optional
      throw new Error('YAML parsing requires the "yaml" package. Use JSON format or install "yaml".');
    }
  } catch (err) {
    if (err instanceof SyntaxError) {
      throw new DefinitionValidationError('Failed to parse definition', [
        `Invalid ${detectedFormat}: ${err.message}`,
      ]);
    }
    throw err;
  }

  return validateDefinition(raw);
}

/**
 * Validate a parsed object as an APOADefinition.
 * Returns the validated definition or throws DefinitionValidationError.
 */
function validateDefinition(raw: unknown): APOADefinition {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!raw || typeof raw !== 'object') {
    throw new DefinitionValidationError('Definition must be an object', [
      'Definition must be an object',
    ]);
  }

  const obj = raw as Record<string, unknown>;

  // Required fields
  if (!obj.principal || typeof obj.principal !== 'object') {
    errors.push("missing required field 'principal'");
  } else {
    const p = obj.principal as Record<string, unknown>;
    if (!p.id || typeof p.id !== 'string') {
      errors.push("'principal.id' must be a non-empty string");
    }
  }

  if (!obj.agent || typeof obj.agent !== 'object') {
    errors.push("missing required field 'agent'");
  } else {
    const a = obj.agent as Record<string, unknown>;
    if (!a.id || typeof a.id !== 'string') {
      errors.push("'agent.id' must be a non-empty string");
    }
  }

  if (!obj.services || !Array.isArray(obj.services) || obj.services.length === 0) {
    errors.push("'services' must be a non-empty array");
  } else {
    for (let i = 0; i < obj.services.length; i++) {
      const svc = obj.services[i] as Record<string, unknown>;
      if (!svc.service || typeof svc.service !== 'string') {
        errors.push(`services[${i}].service must be a non-empty string`);
      }
      if (!svc.scopes || !Array.isArray(svc.scopes) || svc.scopes.length === 0) {
        errors.push(`services[${i}].scopes must be a non-empty array`);
      }

      // Phase 2b: Browser mode validation
      validateServiceAccessMode(svc, i, errors, warnings);
    }
  }

  if (obj.expires === undefined || obj.expires === null) {
    errors.push("missing required field 'expires'");
  }

  // Metadata validation
  if (obj.metadata !== undefined) {
    validateMetadata(obj.metadata, errors);
  }

  // Phase 2b: AgentProvider validation
  if (obj.agentProvider !== undefined) {
    validateAgentProvider(obj.agentProvider, errors);
  }

  // Phase 2b: Legal framework validation
  if (obj.legal !== undefined) {
    validateLegalFramework(obj.legal, errors);
  }

  if (errors.length > 0) {
    const err = new DefinitionValidationError(
      `Invalid definition: ${errors.length} problem(s) found`,
      errors
    );
    // Attach warnings for callers that want them
    (err as DefinitionValidationError & { warnings?: string[] }).warnings = warnings;
    throw err;
  }

  // Convert date strings to Date objects where needed
  const def = obj as unknown as APOADefinition;
  if (typeof def.expires === 'string') {
    def.expires = def.expires; // keep as string — the spec allows Date | string
  }
  if (typeof def.notBefore === 'string') {
    def.notBefore = def.notBefore;
  }

  return def;
}

function validateMetadata(metadata: unknown, errors: string[]): void {
  if (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata)) {
    errors.push("'metadata' must be a plain object");
    return;
  }

  const keys = Object.keys(metadata as Record<string, unknown>);
  if (keys.length > 20) {
    errors.push(`metadata has ${keys.length} keys (max 20)`);
  }

  const serialized = JSON.stringify(metadata);
  if (serialized.length > 1024) {
    errors.push(
      `metadata serialized size is ${serialized.length} bytes (max 1024)`
    );
  }

  const record = metadata as Record<string, unknown>;
  for (const key of keys) {
    const value = record[key];
    if (
      value !== null &&
      typeof value !== 'string' &&
      typeof value !== 'number' &&
      typeof value !== 'boolean'
    ) {
      errors.push(
        `metadata['${key}'] has invalid type '${typeof value}' (must be string | number | boolean | null)`
      );
    }
  }
}

function validateServiceAccessMode(
  svc: Record<string, unknown>,
  index: number,
  errors: string[],
  warnings: string[]
): void {
  const accessMode = svc.accessMode as string | undefined;

  if (accessMode === 'browser') {
    if (!svc.browserConfig || typeof svc.browserConfig !== 'object') {
      errors.push(
        `services[${index}] has accessMode 'browser' but no browserConfig. ` +
        `Browser-based access requires explicit URL restrictions and a credential vault reference.`
      );
      return;
    }

    const bc = svc.browserConfig as Record<string, unknown>;

    if (!bc.allowedUrls || !Array.isArray(bc.allowedUrls) || bc.allowedUrls.length === 0) {
      errors.push(
        `services[${index}].browserConfig.allowedUrls must be a non-empty array`
      );
    }

    if (!bc.credentialVaultRef || typeof bc.credentialVaultRef !== 'string') {
      errors.push(
        `services[${index}].browserConfig.credentialVaultRef must be a non-empty string`
      );
    }

    if (bc.maxSessionDuration !== undefined) {
      if (typeof bc.maxSessionDuration !== 'number' || bc.maxSessionDuration > 86400) {
        errors.push(
          `services[${index}].browserConfig.maxSessionDuration must be <= 86400 seconds`
        );
      }
    }
  }

  if (accessMode === 'api' && svc.browserConfig) {
    warnings.push(
      `services[${index}] has accessMode 'api' but browserConfig is present (will be ignored)`
    );
  }
}

function validateAgentProvider(provider: unknown, errors: string[]): void {
  if (typeof provider !== 'object' || provider === null) {
    errors.push("'agentProvider' must be an object");
    return;
  }

  const p = provider as Record<string, unknown>;
  if (!p.name || typeof p.name !== 'string') {
    errors.push("'agentProvider.name' is required and must be a non-empty string");
  }
}

function validateLegalFramework(legal: unknown, errors: string[]): void {
  if (typeof legal !== 'object' || legal === null) {
    errors.push("'legal' must be an object");
    return;
  }

  const l = legal as Record<string, unknown>;

  if (l.model !== 'provider-as-agent') {
    errors.push("'legal.model' must be 'provider-as-agent'");
  }

  if (l.jurisdiction !== undefined) {
    if (typeof l.jurisdiction !== 'string') {
      errors.push("'legal.jurisdiction' must be a string");
    } else {
      // ISO 3166 format: 2-letter country code, optionally followed by -subdivision
      // Examples: "US", "US-CA", "GB", "DE"
      const iso3166Pattern = /^[A-Z]{2}(-[A-Z0-9]{1,3})?$/;
      if (!iso3166Pattern.test(l.jurisdiction)) {
        errors.push(
          `'legal.jurisdiction' must be ISO 3166 format (e.g., "US", "US-CA", "GB"), got '${l.jurisdiction}'`
        );
      }
    }
  }
}
