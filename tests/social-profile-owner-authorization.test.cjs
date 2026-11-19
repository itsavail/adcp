'use strict';

/**
 * Schema contract for experimental social_profile properties, their owner
 * authorization records and the signed creator sales-authorization credential
 * (media_buy.social_profiles, #6538).
 */

const assert = require('node:assert/strict');
const { createHash, createPublicKey, verify } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');

const SCHEMA_ROOT = path.join(__dirname, '../static/schemas/source');

function readSchema(uri) {
  assert.ok(uri.startsWith('/schemas/'), `Unexpected schema URI: ${uri}`);
  return JSON.parse(fs.readFileSync(path.join(SCHEMA_ROOT, uri.slice('/schemas/'.length)), 'utf8'));
}

async function compile(schema) {
  const ajv = new Ajv({ allErrors: true, strict: false, discriminator: true, loadSchema: async ref => readSchema(ref) });
  addFormats(ajv);
  return ajv.compileAsync(schema);
}

const record = {
  method: 'platform_oauth',
  platform_domain: 'videoplatform.example',
  account: { type: 'youtube_channel_id', value: 'UCexample123456' },
  verified_by: { domain: 'novacreators.example' },
  verified_at: '2026-10-20T14:05:00Z',
};

// brand.json's property definition is not addressable on its own, so validate it through a fragment ref.
const brandProperty = { $ref: '/schemas/brand.json#/definitions/property' };

test('owner-authorization accepts a platform_oauth record and its documented example', async () => {
  const schema = readSchema('/schemas/core/owner-authorization.json');
  const validate = await compile(schema);
  assert.equal(validate(record), true, JSON.stringify(validate.errors));
  for (const example of schema.examples) {
    assert.equal(validate(example), true, JSON.stringify(validate.errors));
  }
  for (const account of [
    { type: 'tiktok_id', value: 'kitchenlab' },
    { type: 'instagram_account_id', value: '17841400000000000' },
    { type: 'instagram_handle', value: 'kitchenlab' },
  ]) {
    assert.equal(validate({ ...record, account }), true, JSON.stringify(validate.errors));
  }
});

test('owner-authorization rejects records missing required members or with bad values', async () => {
  const validate = await compile(readSchema('/schemas/core/owner-authorization.json'));
  for (const key of ['method', 'platform_domain', 'account', 'verified_by', 'verified_at']) {
    const { [key]: _omitted, ...rest } = record;
    assert.equal(validate(rest), false, `missing ${key} should fail`);
  }
  for (const bad of [
    { ...record, method: 'self_declared' },
    { ...record, platform_domain: 'https://videoplatform.example' },
    { ...record, platform_domain: 'localhost' },
    { ...record, account: { type: 'handle', value: '@kitchenlab' } },
    { ...record, account: { type: 'instagram_user_id', value: '17841400000000000' } },
    { ...record, account: { type: 'domain', value: 'jordanvega.example' } },
    { ...record, account: { ...record.account, extra: true } },
    { ...record, verified_at: 'yesterday' },
  ]) {
    assert.equal(validate(bad), false, JSON.stringify(bad));
  }
});

test('property accepts a social_profile with owner_authorizations', async () => {
  const validate = await compile(readSchema('/schemas/core/property.json'));
  const property = {
    property_type: 'social_profile',
    name: 'Kitchen Lab with Jordan Vega',
    identifiers: [{ type: 'youtube_channel_id', value: 'UCexample123456' }],
    supported_channels: ['influencer'],
    owner_authorizations: [record],
  };
  assert.equal(validate(property), true, JSON.stringify(validate.errors));
  assert.equal(validate({ ...property, owner_authorizations: [] }), false);
});

test('collection accepts owner_authorizations alongside distribution', async () => {
  const validate = await compile(readSchema('/schemas/core/collection.json'));
  const collection = {
    collection_id: 'kitchen_lab',
    name: 'Kitchen Lab with Jordan Vega',
    kind: 'series',
    distribution: [
      {
        publisher_domain: 'videoplatform.example',
        identifiers: [{ type: 'youtube_channel_id', value: 'UCexample123456' }],
      },
    ],
    owner_authorizations: [record],
  };
  assert.equal(validate(collection), true, JSON.stringify(validate.errors));
});

test('brand.json property accepts a delegated social_profile with identifier_type', async () => {
  const validate = await compile(brandProperty);
  const social = {
    type: 'social_profile',
    identifier: 'UCexample123456',
    identifier_type: 'youtube_channel_id',
    relationship: 'delegated',
    owner_authorizations: [record],
  };
  assert.equal(validate(social), true, JSON.stringify(validate.errors));
  assert.equal(validate({ ...social, identifier_type: 'handle' }), false, 'unknown identifier_type should fail');
  assert.equal(validate({ ...social, identifier_type: 'domain' }), false, 'a non-social identifier_type should fail');
  assert.equal(validate({ type: 'website', identifier: 'novacreators.example', identifier_type: 'domain' }), true, 'other types keep the full identifier list');
  const { identifier_type, ...untyped } = social;
  assert.equal(validate(untyped), false, 'social_profile without identifier_type should fail');
  assert.equal(validate({ type: 'website', identifier: 'novacreators.example' }), true, 'other types need no identifier_type');
});

const vectors = JSON.parse(fs.readFileSync(
  path.join(__dirname, '../static/compliance/source/test-vectors/creator-attestations/vectors.json'), 'utf8'));
const verifiedCase = vectors.cases.find((testCase) => testCase.name === 'verified-credential');
const [reference] = verifiedCase.carrier.attestations;
const issuerJwks = verifiedCase.network['https://novacreators.example/.well-known/jwks.json'].body;
const [encodedHeader, encodedPayload, encodedSignature] = reference.embedded_credential.value.split('.');
const jwsHeader = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
const assertion = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));

test('property, collection and brand.json property accept a sales-authorization attestation', async () => {
  const property = await compile(readSchema('/schemas/core/property.json'));
  const social = {
    property_type: 'social_profile',
    name: 'Kitchen Lab with Jordan Vega',
    identifiers: [{ type: 'youtube_channel_id', value: 'UCexample123456' }],
    owner_authorizations: [record],
    attestations: [reference],
  };
  assert.equal(property(social), true, JSON.stringify(property.errors));
  assert.equal(property({ ...social, attestations: [] }), false, 'an empty attestations list should fail');

  const collection = await compile(readSchema('/schemas/core/collection.json'));
  const kitchenLab = {
    collection_id: 'kitchen_lab',
    name: 'Kitchen Lab with Jordan Vega',
    kind: 'series',
    distribution: [{ publisher_domain: 'videoplatform.example', identifiers: [{ type: 'youtube_channel_id', value: 'UCexample123456' }] }],
    attestations: [reference],
  };
  assert.equal(collection(kitchenLab), true, JSON.stringify(collection.errors));

  const brand = await compile(brandProperty);
  const entry = { type: 'social_profile', identifier: 'UCexample123456', identifier_type: 'youtube_channel_id', attestations: [reference] };
  assert.equal(brand(entry), true, JSON.stringify(brand.errors));
});

test('the vector credential is a signed creator-assertion matching its reference', async () => {
  const digest = `sha256:${createHash('sha256').update(reference.embedded_credential.value, 'ascii').digest('hex')}`;
  assert.equal(digest, reference.content_digest);

  assert.equal(jwsHeader.typ, 'adcp-creator-assertion+jws');
  const jwk = issuerJwks.keys.find((key) => key.kid === jwsHeader.kid);
  assert.ok(jwk, 'the header kid resolves in the issuer JWKS');
  assert.equal(jwk.adcp_use, 'attestation-signing');
  const { kid: _kid, alg: _alg, use: _use, key_ops: _ops, adcp_use: _purpose, ...publicJwk } = jwk;
  const signed = verify(
    null,
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    createPublicKey({ key: publicJwk, format: 'jwk' }),
    Buffer.from(encodedSignature, 'base64url'),
  );
  assert.equal(signed, true, 'the signature verifies with the published key');

  const validate = await compile(readSchema('/schemas/core/creator-assertion.json'));
  assert.equal(validate(assertion), true, JSON.stringify(validate.errors));
  assert.deepEqual(assertion.issuer, reference.issuer);
  assert.equal(assertion.claim_type, reference.claim_type);
  assert.deepEqual(assertion.subject, reference.subject);
  assert.equal(reference.subject.namespace.split('/').pop(), assertion.evidence.account.type);
  assert.equal(reference.subject.id, assertion.evidence.account.value);
  assert.ok(assertion.value.scope.includes('sales_authorization'));
  assert.deepEqual(assertion.value.seller, reference.issuer.brand);
  assert.deepEqual(assertion.evidence.verified_by, reference.issuer.brand);
  assert.equal(jwsHeader.alg, jwk.alg);
});

test('creator-assertion rejects an open-ended or mis-typed claim', async () => {
  const schema = readSchema('/schemas/core/creator-assertion.json');
  const validate = await compile(schema);
  for (const example of schema.examples) {
    assert.equal(validate(example), true, JSON.stringify(validate.errors));
  }
  for (const type of ['youtube_channel_id', 'tiktok_id', 'instagram_account_id', 'instagram_handle']) {
    const subject = { ...assertion.subject, namespace: `https://adcontextprotocol.org/identifier-types/${type}` };
    assert.equal(validate({ ...assertion, subject }), true, type);
  }
  for (const key of ['claim_type', 'credential_id', 'issuer', 'subject', 'value', 'evidence', 'issued_at', 'expires_at']) {
    const { [key]: _omitted, ...rest } = assertion;
    assert.equal(validate(rest), false, `missing ${key} should fail`);
  }
  const { status_url: _statusUrl, ...withoutStatusUrl } = assertion;
  assert.equal(validate(withoutStatusUrl), true, 'status_url is optional');
  for (const bad of [
    { ...assertion, claim_type: 'https://adcontextprotocol.org/claims/rights/grant' },
    { ...assertion, subject: { ...assertion.subject, resource_type: 'https://adcontextprotocol.org/claims/subjects/signal' } },
    { ...assertion, subject: { ...assertion.subject, namespace: 'https://videoplatform.example' } },
    { ...assertion, value: { ...assertion.value, scope: [] } },
    { ...assertion, status_url: 'http://novacreators.example/status' },
    { ...assertion, issuer: { type: 'origin', origin: 'https://novacreators.example' } },
    { ...assertion, subject: { ...assertion.subject, namespace: 'https://adcontextprotocol.org/identifier-types/domain' } },
    { ...assertion, subject: { ...assertion.subject, namespace: 'https://adcontextprotocol.org/identifier-types/instagram_user_id' } },
    { ...assertion, evidence: { ...assertion.evidence, account: { type: 'domain', value: 'novacreators.example' } } },
  ]) {
    assert.equal(validate(bad), false, JSON.stringify(bad));
  }
});

test('creator-anchor accepts a profile text anchor and rejects other shapes', async () => {
  const schema = readSchema('/schemas/core/creator-anchor.json');
  const validate = await compile(schema);
  const [anchor] = schema.examples;
  assert.equal(validate(anchor), true, JSON.stringify(validate.errors));
  for (const bad of [
    { type: 'email_alias', address: 'deals@kitchenlab.example' },
    { type: 'trust_json', domain: 'jordanvega.example' },
    { type: 'platform_profile_text', url: anchor.url },
    { type: 'platform_profile_text', expected: anchor.expected },
    { ...anchor, url: 'http://videoplatform.example/channel/UCexample123456' },
  ]) {
    assert.equal(validate(bad), false, JSON.stringify(bad));
  }
  const withAnchor = { ...assertion, anchor };
  const validateAssertion = await compile(readSchema('/schemas/core/creator-assertion.json'));
  assert.equal(validateAssertion(withAnchor), true, JSON.stringify(validateAssertion.errors));
});

test('creator-assertion-status requires both update times', async () => {
  const schema = readSchema('/schemas/core/creator-assertion-status.json');
  const validate = await compile(schema);
  const [status] = schema.examples;
  assert.equal(validate(status), true, JSON.stringify(validate.errors));
  for (const key of ['credential_id', 'status', 'this_update', 'next_update']) {
    const { [key]: _omitted, ...rest } = status;
    assert.equal(validate(rest), false, `missing ${key} should fail`);
  }
  assert.equal(validate({ ...status, status: 'paused', reason: 'The agency paused its sales agent.' }), true, JSON.stringify(validate.errors));
  assert.equal(validate({ ...status, status: 'suspended' }), false);
});

test('the social profile surface is experimental and listed in the registry', () => {
  for (const uri of [
    '/schemas/core/owner-authorization.json',
    '/schemas/core/creator-assertion.json',
    '/schemas/core/creator-assertion-status.json',
    '/schemas/core/creator-anchor.json',
  ]) {
    assert.equal(readSchema(uri)['x-status'], 'experimental', uri);
  }
  for (const uri of ['/schemas/core/property.json', '/schemas/core/collection.json']) {
    const { properties } = readSchema(uri);
    assert.equal(properties.owner_authorizations['x-status'], 'experimental', uri);
    assert.equal(properties.attestations['x-status'], 'experimental', uri);
  }
  const { properties } = readSchema('/schemas/brand.json').definitions.property;
  for (const field of ['identifier_type', 'owner_authorizations', 'attestations']) {
    assert.equal(properties[field]['x-status'], 'experimental', field);
  }
  const registry = fs.readFileSync(path.join(__dirname, '../docs/reference/experimental-status.mdx'), 'utf8');
  assert.match(registry, /\| `media_buy\.social_profiles` \|/);
});

test('a credential is bound to the selling agent\'s operator and to the account it is attached to', () => {
  const carriers = [
    readSchema('/schemas/core/property.json').properties.attestations,
    readSchema('/schemas/core/collection.json').properties.attestations,
    readSchema('/schemas/brand.json').definitions.property.properties.attestations,
  ];
  for (const { description } of carriers) {
    assert.match(description, /subject MUST name .* or the evaluation is subject_mismatch/);
  }
  const { issuer } = readSchema('/schemas/core/creator-assertion.json').properties;
  assert.match(issuer.description, /domain is the selling agent's operator, the registrable domain of the selling agent's host/);
  const security = fs.readFileSync(path.join(__dirname, '../docs/building/by-layer/L1/security.mdx'), 'utf8');
  const profile = security.slice(security.indexOf('### Creator sales-authorization profile'));
  assert.match(profile, /domain MUST equal `eTLD\+1\(host\(A\)\)`, the selling agent's operator/);
  assert.match(profile, /\*\*Check before any request\.\*\*[^\n]*Any other issuer is `untrusted_issuer`/);
  assert.match(profile, /names another account is `subject_mismatch`/);
  assert.match(profile, /An issuer that resumes a paused claim issues a new credential with a new `credential_id`/);
  assert.match(profile, /A status that is not current, .* produces `unverifiable`/);
  assert.match(profile, /`status_url` is optional\. A credential without one skips this step/);
  assert.match(profile, /`action_id` equal to `A`/);
  assert.match(profile, /`youtube_channel_id`: `https:\/\/www\.youtube\.com\/channel\/` followed by `subject\.id`/);
  assert.match(profile, /`tiktok_id`: `https:\/\/www\.tiktok\.com\/@` followed by `subject\.id`/);
  assert.match(profile, /`instagram_handle`: `https:\/\/www\.instagram\.com\/` followed by `subject\.id`/);
  assert.match(profile, /For an `instagram_account_id` subject the evaluator cannot check that the page belongs to the account/);
});
