'use strict';

/**
 * Reference evaluator for the creator sales-authorization vectors
 * (media_buy.social_profiles, #6538). It follows the order in
 * static/compliance/source/test-vectors/creator-attestations/README.md.
 */

const assert = require('node:assert/strict');
const { createHash, createPublicKey, verify } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { describe, it } = require('node:test');
const { isDeepStrictEqual } = require('node:util');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const {
  applicableBrandRefAgents,
  canonicalizeFixtureUrl,
} = require('./helpers/reference-brand-response-authorizer.cjs');

const ROOT = path.resolve(__dirname, '..');
const SCHEMA_ROOT = path.join(ROOT, 'static/schemas/source');
const fixture = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'static/compliance/source/test-vectors/creator-attestations/vectors.json'),
  'utf8',
));
const { profile } = fixture;
const CLOCK_SKEW_MS = 60_000;
const MAX_LIFETIME_AFTER_CHECK_MS = 7 * 24 * 60 * 60 * 1000;
const IDENTIFIER_TYPE_BASE = 'https://adcontextprotocol.org/identifier-types/';
const ALLOWED_ALGS = ['EdDSA', 'ES256'];
const REVOKING_STATUSES = ['paused', 'revoked', 'unknown'];

function evaluate(testCase, now) {
  const network = { responses: testCase.network, requests: 0 };
  const result = outcome => ({ outcome, network_requests: network.requests });

  // Step 1 makes no request.
  const reference = testCase.carrier.attestations[0];
  if (
    reference.claim_type !== profile.claim_type
    || reference.subject?.type !== 'resource'
    || reference.subject.resource_type !== profile.subject_resource_type
  ) return result('unsupported');
  const embedded = reference.embedded_credential;
  if (typeof embedded?.value !== 'string' || typeof reference.content_digest !== 'string') return result('invalid');
  if (embedded.format !== profile.proof_format) return result('unsupported');
  if (sha256(embedded.value) !== reference.content_digest) return result('digest_mismatch');
  const jws = decodeJws(embedded.value);
  if (!jws || jws.header.typ !== profile.credential_typ || !jws.header.kid) return result('invalid');
  if (!ALLOWED_ALGS.includes(jws.header.alg)) return result('invalid');
  if (!carrierNames(testCase, reference.subject, jws.payload)) return result('subject_mismatch');
  const issuerBrand = reference.issuer.brand;
  const operator = registrableDomain(new URL(testCase.selling_agent_url).hostname);
  if (reference.issuer.type !== 'brand' || issuerBrand?.domain !== operator) return result('untrusted_issuer');

  // Step 2 reads the issuer's brand.json and the selling agent's JWKS, then checks the signature.
  const brandJson = request(network, `https://${issuerBrand.domain}/.well-known/brand.json`);
  if (!brandJson) return result('unverifiable');
  const agentUrl = canonicalizeFixtureUrl(testCase.selling_agent_url);
  const resolution = applicableBrandRefAgents(brandJson, issuerBrand);
  const entries = resolution.agents.filter(agent => (
    agent?.type === 'sales' && canonicalizeFixtureUrl(agent.url) === agentUrl
  ));
  if (resolution.ambiguous || entries.length !== 1) return result('invalid');
  const jwks = request(network, entries[0].jwks_uri ?? `${new URL(entries[0].url).origin}/.well-known/jwks.json`);
  if (!jwks) return result('unverifiable');
  if (!verifyWith(jwks, jws)) return result('invalid');

  // Step 3 checks the signed claim and makes no request.
  const claim = jws.payload;
  if (claim.claim_type !== reference.claim_type || !isDeepStrictEqual(claim.issuer, reference.issuer)) {
    return result('invalid');
  }
  if (!isDeepStrictEqual(claim.subject, reference.subject)) return result('subject_mismatch');
  if (
    !claim.value?.scope?.includes('sales_authorization')
    || !isDeepStrictEqual(claim.value.seller, issuerBrand)
    || !isDeepStrictEqual(claim.evidence?.verified_by, issuerBrand)
    || `${IDENTIFIER_TYPE_BASE}${claim.evidence?.account?.type}` !== claim.subject.namespace
    || claim.evidence?.account?.value !== claim.subject.id
  ) return result('invalid');
  const issuedAt = Date.parse(claim.issued_at);
  const expiresAt = Date.parse(claim.expires_at);
  const verifiedAt = Date.parse(claim.evidence.verified_at);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || issuedAt > now + CLOCK_SKEW_MS) {
    return result('invalid');
  }
  if (expiresAt <= now) return result('expired');
  if (!Number.isFinite(verifiedAt) || expiresAt - verifiedAt > MAX_LIFETIME_AFTER_CHECK_MS) return result('invalid');

  // Step 4 runs only when the credential carries a status_url.
  if (claim.status_url !== undefined) {
    const statusOutcome = evaluateStatus(claim, issuerBrand, jwks, network, now);
    if (statusOutcome) return result(statusOutcome);
  }

  // The anchor is evaluated only for a verified credential.
  const anchor = evaluateAnchor(claim, network);
  return {
    ...result('verified'),
    action_binding: { action_type: profile.action_type, action_id: agentUrl },
    anchor,
  };
}

// A URL missing from the case's network map, or a non-200 response, is a failed request.
function request(network, url) {
  network.requests += 1;
  const response = network.responses[url];
  return response?.status === 200 ? response.body : null;
}

// The subject must name an account of the carrier, and each carrier kind lists its accounts differently.
function carrierNames(testCase, subject, claim) {
  const { carrier } = testCase;
  let accounts;
  if (testCase.carrier_kind === 'property') {
    accounts = carrier.identifiers;
  } else if (testCase.carrier_kind === 'collection') {
    accounts = carrier.distribution
      .filter(entry => entry.publisher_domain === claim?.evidence?.platform_domain)
      .flatMap(entry => entry.identifiers);
  } else {
    accounts = [{ type: carrier.identifier_type, value: carrier.identifier }];
  }
  return accounts.some(account => (
    subject.namespace === `${IDENTIFIER_TYPE_BASE}${account.type}` && subject.id === account.value
  ));
}

// Returns the failing outcome, or null when the signed status is current and active.
function evaluateStatus(claim, issuerBrand, jwks, network, now) {
  let statusUrl;
  try {
    statusUrl = new URL(claim.status_url);
  } catch {
    return 'unverifiable';
  }
  if (statusUrl.protocol !== 'https:' || !onDomain(statusUrl.hostname, issuerBrand.domain)) return 'unverifiable';
  const status = decodeJws(request(network, claim.status_url));
  if (!status || status.header.typ !== profile.status_typ || !verifyWith(jwks, status)) {
    return 'unverifiable';
  }
  if (status.payload.credential_id !== claim.credential_id) return 'unverifiable';
  const thisUpdate = Date.parse(status.payload.this_update);
  const nextUpdate = Date.parse(status.payload.next_update);
  if (!(thisUpdate <= now + CLOCK_SKEW_MS && nextUpdate > now)) return 'unverifiable';
  if (status.payload.status === 'active') return null;
  return REVOKING_STATUSES.includes(status.payload.status) ? 'revoked' : 'unverifiable';
}

function evaluateAnchor(claim, network) {
  const { anchor } = claim;
  if (!anchor) return 'absent';
  if (anchor.type !== 'platform_profile_text' || typeof anchor.expected !== 'string') return 'unconfirmed';
  let url;
  try {
    url = new URL(anchor.url);
  } catch {
    return 'unconfirmed';
  }
  if (url.protocol !== 'https:') return 'unconfirmed';
  const prefix = fixture.profile_address_prefixes[claim.evidence.account.type];
  if (!prefix) return 'unconfirmed';
  if (withoutTrailingSlash(anchor.url) !== `${prefix}${claim.subject.id.replace(/^@/, '')}`) return 'unconfirmed';
  if (!anchor.expected.includes(claim.issuer.brand.domain)) return 'unconfirmed';
  const page = request(network, anchor.url);
  return typeof page === 'string' && page.includes(anchor.expected) ? 'confirmed' : 'unconfirmed';
}

// The key is taken from the selling agent's JWKS, so a signature it verifies is bound to that key's material.
function verifyWith(jwks, jws) {
  const keys = (jwks.keys ?? []).filter(candidate => candidate?.kid === jws.header.kid);
  if (keys.length !== 1) return false;
  const [key] = keys;
  if (key.adcp_use !== 'attestation-signing' || key.use !== 'sig' || !key.key_ops?.includes('verify')) return false;
  if (key.alg !== jws.header.alg || !ALLOWED_ALGS.includes(jws.header.alg)) return false;
  const { kid: _kid, alg: _alg, use: _use, key_ops: _ops, adcp_use: _purpose, ...publicJwk } = key;
  try {
    const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' });
    return verify(
      jws.header.alg === 'ES256' ? 'sha256' : null,
      Buffer.from(jws.signingInput),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      jws.signature,
    );
  } catch {
    return false;
  }
}

function decodeJws(compact) {
  if (typeof compact !== 'string') return null;
  const parts = compact.split('.');
  if (parts.length !== 3) return null;
  try {
    return {
      header: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')),
      payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: Buffer.from(parts[2], 'base64url'),
    };
  } catch {
    return null;
  }
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value, 'ascii').digest('hex')}`;
}

// Fixture hosts use .example, whose registrable domain is the last two labels.
function registrableDomain(host) {
  return host.split('.').slice(-2).join('.');
}

function onDomain(host, domain) {
  return host === domain || host.endsWith(`.${domain}`);
}

function withoutTrailingSlash(url) {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

function readSchema(uri) {
  assert.match(uri, /^\/schemas\//);
  return JSON.parse(fs.readFileSync(path.join(SCHEMA_ROOT, uri.slice('/schemas/'.length)), 'utf8'));
}

async function compile(schema) {
  const ajv = new Ajv({ allErrors: true, strict: false, discriminator: true, loadSchema: async ref => readSchema(ref) });
  addFormats(ajv);
  return ajv.compileAsync(schema);
}

describe('creator sales-authorization vectors', () => {
  const now = Date.parse(fixture.evaluation_time);

  it('uses the profile identifiers the security documentation defines', () => {
    const security = fs.readFileSync(path.join(ROOT, 'docs/building/by-layer/L1/security.mdx'), 'utf8');
    for (const value of [profile.claim_type, profile.subject_resource_type, profile.proof_format, profile.action_type]) {
      assert.ok(security.includes(value), value);
    }
  });

  it('builds profile addresses with the paths the security documentation defines', () => {
    const security = fs.readFileSync(path.join(ROOT, 'docs/building/by-layer/L1/security.mdx'), 'utf8');
    const documented = {
      youtube_channel_id: 'https://www.youtube.com/channel/',
      tiktok_id: 'https://www.tiktok.com/@',
      instagram_handle: 'https://www.instagram.com/',
    };
    assert.deepEqual(Object.keys(fixture.profile_address_prefixes).sort(), Object.keys(documented).sort());
    for (const [type, address] of Object.entries(documented)) {
      assert.ok(security.includes(`\`${type}\`: \`${address}\``), type);
      assert.equal(new URL(fixture.profile_address_prefixes[type]).pathname, new URL(address).pathname, type);
    }
  });

  it('gives every verified case an anchor result and no other case one', () => {
    const security = fs.readFileSync(path.join(ROOT, 'docs/building/by-layer/L1/security.mdx'), 'utf8');
    assert.ok(security.includes('The anchor result is `confirmed`, `unconfirmed` or `absent`, and it never changes the outcome.'));
    for (const testCase of fixture.cases) {
      const hasAnchorResult = ['confirmed', 'unconfirmed', 'absent'].includes(testCase.expected.anchor);
      assert.equal(hasAnchorResult, testCase.expected.outcome === 'verified', testCase.name);
    }
  });

  it('carries schema-valid carriers, brand.json documents and status payloads', async () => {
    const carrierSchemas = {
      brand_json_property: await compile({ $ref: '/schemas/brand.json#/definitions/property' }),
      property: await compile(readSchema('/schemas/core/property.json')),
      collection: await compile(readSchema('/schemas/core/collection.json')),
    };
    const brand = await compile(readSchema('/schemas/brand.json'));
    const statusSchema = await compile(readSchema('/schemas/core/creator-assertion-status.json'));
    const assertion = await compile(readSchema('/schemas/core/creator-assertion.json'));
    for (const testCase of fixture.cases) {
      const carrier = carrierSchemas[testCase.carrier_kind];
      assert.equal(carrier(testCase.carrier), true, `${testCase.name}: ${JSON.stringify(carrier.errors)}`);
      for (const [url, response] of Object.entries(testCase.network)) {
        if (response.status !== 200) continue;
        if (url.endsWith('/brand.json')) {
          assert.equal(brand(response.body), true, `${testCase.name}: ${JSON.stringify(brand.errors)}`);
        }
        const status = response.content_type === 'application/jose' ? decodeJws(response.body) : null;
        if (status) assert.equal(statusSchema(status.payload), true, `${testCase.name}: ${JSON.stringify(statusSchema.errors)}`);
      }
      const credential = decodeJws(testCase.carrier.attestations[0].embedded_credential.value);
      assert.equal(assertion(credential.payload), true, `${testCase.name}: ${JSON.stringify(assertion.errors)}`);
    }
  });

  it('expects only stable attestation outcomes', () => {
    const outcomes = readSchema('/schemas/core/attestation-evaluation.json').properties.outcome.enum;
    for (const testCase of fixture.cases) {
      assert.ok(outcomes.includes(testCase.expected.outcome), testCase.name);
    }
  });

  for (const testCase of fixture.cases) {
    it(testCase.name, () => {
      assert.deepEqual(evaluate(testCase, now), testCase.expected);
    });
  }
});
