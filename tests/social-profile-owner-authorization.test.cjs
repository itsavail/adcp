const assert = require('node:assert/strict');
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
  const ajv = new Ajv({ allErrors: true, strict: false, loadSchema: async ref => readSchema(ref) });
  addFormats(ajv);
  return ajv.compileAsync(schema);
}

const record = {
  method: 'platform_oauth',
  platform_domain: 'videoplatform.example',
  account: { type: 'youtube_channel_id', value: 'UCexample123456' },
  verified_by: { domain: 'creator-network.example' },
  verified_at: '2026-10-20T14:05:00Z',
  granted_scopes: ['analytics.readonly'],
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
    { ...record, account: { type: 'handle', value: '@novacooks' } },
    { ...record, account: { ...record.account, extra: true } },
    { ...record, verified_at: 'yesterday' },
    { ...record, granted_scopes: [] },
  ]) {
    assert.equal(validate(bad), false, JSON.stringify(bad));
  }
});

test('property accepts a social_profile with owner_authorizations', async () => {
  const validate = await compile(readSchema('/schemas/core/property.json'));
  const property = {
    property_type: 'social_profile',
    name: 'Nova Cooks',
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
    collection_id: 'nova_cooks',
    name: 'Nova Cooks',
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
});
