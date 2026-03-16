import {
  createClient,
  generateKeyPair,
  cascadeRevoke,
} from '../src/index.js';
import { MemoryRevocationStore } from '../src/revocation/store.js';

const keys = await generateKeyPair();
const revocationStore = new MemoryRevocationStore();

const apoa = createClient({
  revocationStore,
  defaultSigningOptions: { privateKey: keys.privateKey },
});

// Step 1: Create the root token (HomeBot has broad access)
const rootToken = await apoa.createToken({
  principal: { id: 'did:apoa:jane', name: 'Jane Doe' },
  agent: { id: 'did:apoa:homebot', name: 'HomeBot Pro' },
  services: [
    {
      service: 'mychart.com',
      scopes: ['appointments:read', 'appointments:write', 'prescriptions:read'],
    },
    {
      service: 'stripe.com',
      scopes: ['charges:read', 'balance:read', 'invoices:read'],
    },
  ],
  expires: '2099-09-01',
  delegatable: true,
  maxDelegationDepth: 2,
});

console.log(`Root token: ${rootToken.jti}`);
console.log(`  Agent: ${rootToken.definition.agent.name}`);
console.log(`  Services: ${rootToken.audience?.join(', ')}`);

// Step 2: Delegate to a specialized sub-agent (narrower scope)
const childToken = await apoa.delegate(rootToken, {
  agent: { id: 'did:apoa:appointment-bot', name: 'AppointmentBot' },
  services: [
    {
      service: 'mychart.com',
      scopes: ['appointments:read'], // subset of parent
    },
  ],
  expires: '2098-06-01', // before parent
});

console.log(`\nChild token: ${childToken.jti}`);
console.log(`  Agent: ${childToken.definition.agent.name}`);
console.log(`  Parent: ${childToken.parentToken}`);
console.log(`  Principal: ${childToken.definition.principal.name} (inherited)`);

// Step 3: Verify the chain
const chainResult = await apoa.verifyChain([rootToken, childToken]);
console.log(`\nChain verification: ${chainResult.valid ? 'VALID' : 'INVALID'}`);
console.log(`  Depth: ${chainResult.depth}`);
console.log(`  Root: ${chainResult.root.definition.agent.name}`);
console.log(`  Leaf: ${chainResult.leaf.definition.agent.name}`);

// Step 4: Use the child token
const scopeCheck = apoa.checkScope(childToken, 'mychart.com', 'appointments:read');
console.log(`\nChild scope check (appointments:read): ${scopeCheck.allowed ? 'ALLOWED' : 'DENIED'}`);

const expandCheck = apoa.checkScope(childToken, 'mychart.com', 'appointments:write');
console.log(`Child scope check (appointments:write): ${expandCheck.allowed ? 'ALLOWED' : 'DENIED'}`);

const crossCheck = apoa.checkScope(childToken, 'stripe.com', 'charges:read');
console.log(`Child scope check (stripe charges:read): ${crossCheck.allowed ? 'ALLOWED' : 'DENIED'}`);

// Step 5: Cascade revoke — kill the parent, kill the children
console.log('\n--- Cascade Revocation ---');
const record = await cascadeRevoke(
  rootToken.jti,
  [childToken.jti],
  { revokedBy: 'did:apoa:jane', reason: 'No longer needed' },
  revocationStore
);

console.log(`Revoked parent: ${record.tokenId}`);
console.log(`Cascaded to: ${record.cascaded.join(', ')}`);
console.log(`Parent revoked: ${await apoa.isRevoked(rootToken.jti)}`);
console.log(`Child revoked: ${await apoa.isRevoked(childToken.jti)}`);

// Chain is now invalid
const postRevokeChain = await apoa.verifyChain([rootToken, childToken]);
console.log(`\nPost-revoke chain: ${postRevokeChain.valid ? 'VALID' : 'INVALID'}`);
console.log(`Errors: ${postRevokeChain.errors.join('; ')}`);
