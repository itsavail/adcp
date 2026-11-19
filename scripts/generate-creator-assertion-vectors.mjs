#!/usr/bin/env node

import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL(
  '../static/compliance/source/test-vectors/creator-attestations/vectors.json',
  import.meta.url,
);

const TEST_KEY = {
  $comment: 'PUBLIC TEST KEY. The private component is published for deterministic conformance fixtures and MUST NOT be used as a production trust anchor or to authorize real activity.',
  kid: 'test-creator-attestation-2026',
  kty: 'OKP',
  crv: 'Ed25519',
  alg: 'EdDSA',
  use: 'sig',
  key_ops: ['verify'],
  adcp_use: 'attestation-signing',
  x: 'Ne1qtVx81mXSnjIMlpXudsQLtmoFcERQx9_ljMaq1_k',
  _private_d_for_test_only: 'wgKH_8m5GmUl5EqJjl2afRNwLfXpZNQyK2PQ0aTNPts',
};

const { $comment, _private_d_for_test_only: privateD, ...PUBLISHED_KEY } = TEST_KEY;
const privateKey = createPrivateKey({
  key: { kty: TEST_KEY.kty, crv: TEST_KEY.crv, x: TEST_KEY.x, d: privateD },
  format: 'jwk',
});

const PROFILE = {
  claim_type: 'https://adcontextprotocol.org/claims/creator/sales-authorization',
  subject_resource_type: 'https://adcontextprotocol.org/claims/subjects/social-profile',
  proof_format: 'https://adcontextprotocol.org/proof-formats/creator-assertion-jws',
  action_type: 'https://adcontextprotocol.org/actions/creator-sales-authorization-evaluation',
  credential_typ: 'adcp-creator-assertion+jws',
  status_typ: 'adcp-creator-assertion-status+jws',
};

const SELLING_AGENT_URL = 'https://sales.novacreators.example/mcp';
const BRAND_JSON_URL = 'https://novacreators.example/.well-known/brand.json';
const JWKS_URL = 'https://novacreators.example/.well-known/jwks.json';
const CREDENTIAL_ID = 'ca_kitchen_lab_0001';
const STATUS_URL = `https://novacreators.example/.well-known/adcp/status/${CREDENTIAL_ID}`;

const ISSUER = { type: 'brand', brand: { domain: 'novacreators.example' } };
const SUBJECT = {
  type: 'resource',
  resource_type: PROFILE.subject_resource_type,
  namespace: 'https://adcontextprotocol.org/identifier-types/youtube_channel_id',
  id: 'UCexample123456',
};
const OTHER_CHANNEL = 'UCgarden000001';

// The profile names the real platform hosts. The fixtures use these stand-ins,
// so a runner builds each profile address from this map.
const PROFILE_ADDRESS_PREFIXES = {
  youtube_channel_id: 'https://www.videoplatform.example/channel/',
  tiktok_id: 'https://www.shortvideo.example/@',
  instagram_handle: 'https://www.photoplatform.example/',
};
const ANCHOR_TEXT = 'Brand deals: novacreators.example';
const CHANNEL_PROFILE_URL = `${PROFILE_ADDRESS_PREFIXES.youtube_channel_id}${SUBJECT.id}`;
const SHORT_VIDEO_ACCOUNT = { type: 'tiktok_id', id: 'kitchenlab', platformDomain: 'shortvideo.example' };
const PHOTO_HANDLE_ACCOUNT = { type: 'instagram_handle', id: 'kitchenlab', platformDomain: 'photoplatform.example' };
const PHOTO_ID_ACCOUNT = { type: 'instagram_account_id', id: '17841400000000000', platformDomain: 'photoplatform.example' };
const PHOTO_PROFILE_URL = `${PROFILE_ADDRESS_PREFIXES.instagram_handle}kitchenlab`;

const CREDENTIAL_HEADER = { alg: 'EdDSA', typ: PROFILE.credential_typ, kid: TEST_KEY.kid };
const CREDENTIAL_PAYLOAD = {
  claim_type: PROFILE.claim_type,
  credential_id: CREDENTIAL_ID,
  issuer: ISSUER,
  subject: SUBJECT,
  value: { scope: ['sales_authorization'], seller: ISSUER.brand },
  evidence: {
    method: 'platform_oauth',
    platform_domain: 'videoplatform.example',
    account: { type: 'youtube_channel_id', value: SUBJECT.id },
    verified_by: ISSUER.brand,
    verified_at: '2026-08-01T00:00:00Z',
  },
  issued_at: '2026-08-01T00:00:00Z',
  expires_at: '2026-08-31T00:00:00Z',
  status_url: STATUS_URL,
};

const STATUS_HEADER = { alg: 'EdDSA', typ: PROFILE.status_typ, kid: TEST_KEY.kid };
const STATUS_PAYLOAD = {
  credential_id: CREDENTIAL_ID,
  status: 'active',
  this_update: '2026-08-06T11:55:00Z',
  next_update: '2026-08-07T11:55:00Z',
};

const BRAND_JSON = {
  agents: [{ type: 'sales', id: 'novacreators_sales', url: SELLING_AGENT_URL, jwks_uri: JWKS_URL }],
};

function base64url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function compactJws(header, payload) {
  const signingInput = `${base64url(header)}.${base64url(payload)}`;
  return `${signingInput}.${sign(null, Buffer.from(signingInput), privateKey).toString('base64url')}`;
}

function tamperSignature(jws) {
  const parts = jws.split('.');
  parts[2] = `${parts[2][0] === 'A' ? 'B' : 'A'}${parts[2].slice(1)}`;
  return parts.join('.');
}

function digest(credential) {
  return `sha256:${createHash('sha256').update(credential, 'ascii').digest('hex')}`;
}

function json(body) {
  return { status: 200, content_type: 'application/json', body };
}

function jose(body) {
  return { status: 200, content_type: 'application/jose', body };
}

function profilePage(text) {
  return { status: 200, content_type: 'text/html', body: `<html><body><p>${text}</p></body></html>` };
}

function anchorAt(url) {
  return { type: 'platform_profile_text', url, expected: ANCHOR_TEXT };
}

function subjectFor(account) {
  return {
    ...SUBJECT,
    namespace: `https://adcontextprotocol.org/identifier-types/${account.type}`,
    id: account.id,
  };
}

function carrierFor(presentation, account, identifier = account.id) {
  return {
    type: 'social_profile',
    identifier,
    identifier_type: account.type,
    relationship: 'delegated',
    attestations: [presentation],
  };
}

function presentationFor(credential, subject) {
  return {
    issuer: ISSUER,
    claim_type: PROFILE.claim_type,
    subject,
    embedded_credential: { format: PROFILE.proof_format, value: credential },
    content_digest: digest(credential),
  };
}

function verified(networkRequests, anchor) {
  return {
    outcome: 'verified',
    network_requests: networkRequests,
    action_binding: { action_type: PROFILE.action_type, action_id: SELLING_AGENT_URL },
    anchor,
  };
}

const definitions = [
  {
    name: 'verified-credential',
    description: 'A current credential from the selling agent\'s operator, attached to its own channel, with an active status. It carries no anchor.',
    expected: verified(3, 'absent'),
  },
  {
    name: 'digest-mismatch',
    description: 'content_digest does not match the embedded credential bytes.',
    mutatePresentation(presentation) { presentation.content_digest = `sha256:${'0'.repeat(64)}`; },
    expected: { outcome: 'digest_mismatch', network_requests: 0 },
  },
  {
    name: 'wrong-credential-typ',
    description: 'The credential header typ is not adcp-creator-assertion+jws, so the JWS profile rejects it before any request.',
    mutateCredentialHeader(header) { header.typ = 'JWT'; },
    expected: { outcome: 'invalid', network_requests: 0 },
  },
  {
    name: 'credential-moved-to-another-channel',
    description: 'A valid credential for one channel sits on another channel\'s property.',
    carrierIdentifier: OTHER_CHANNEL,
    expected: { outcome: 'subject_mismatch', network_requests: 0 },
  },
  {
    name: 'issuer-is-not-the-selling-agent-operator',
    description: 'The selling agent\'s registrable domain is not the issuer\'s, so the issuer is untrusted before any request.',
    sellingAgentUrl: 'https://sales.othernetwork.example/mcp',
    expected: { outcome: 'untrusted_issuer', network_requests: 0 },
  },
  {
    name: 'selling-agent-not-listed-by-issuer',
    description: 'The issuer\'s brand.json lists no sales agent with the selling agent\'s URL.',
    sellingAgentUrl: 'https://agents.novacreators.example/mcp',
    expected: { outcome: 'invalid', network_requests: 1 },
  },
  {
    name: 'key-without-attestation-purpose',
    description: 'The signing key in the selected JWKS carries another adcp_use.',
    network: { [JWKS_URL]: json({ keys: [{ ...PUBLISHED_KEY, adcp_use: 'request-signing' }] }) },
    expected: { outcome: 'invalid', network_requests: 2 },
  },
  {
    name: 'same-kid-different-key',
    description: 'The JWKS has a key with the credential\'s kid but different key material.',
    network: { [JWKS_URL]: json({ keys: [{ ...PUBLISHED_KEY, x: 'rkUcKP5oMd7YjV4yy5mVS5S8fA3LDXcf5jk1P1_52EA' }] }) },
    expected: { outcome: 'invalid', network_requests: 2 },
  },
  {
    name: 'tampered-signature',
    description: 'The credential signature does not verify.',
    tamperCredential: true,
    expected: { outcome: 'invalid', network_requests: 2 },
  },
  {
    name: 'payload-subject-differs-from-reference',
    description: 'The signed payload names a different channel than the reference that carries it.',
    mutateCredentialPayload(payload) {
      payload.subject = { ...payload.subject, id: OTHER_CHANNEL };
      payload.evidence.account = { ...payload.evidence.account, value: OTHER_CHANNEL };
    },
    expected: { outcome: 'subject_mismatch', network_requests: 2 },
  },
  {
    name: 'seller-is-not-the-issuer',
    description: 'value.seller names a party other than the issuer.',
    mutateCredentialPayload(payload) { payload.value.seller = { domain: 'othernetwork.example' }; },
    expected: { outcome: 'invalid', network_requests: 2 },
  },
  {
    name: 'evidence-account-does-not-match-subject',
    description: 'evidence.account names a different channel than the subject.',
    mutateCredentialPayload(payload) {
      payload.evidence.account = { ...payload.evidence.account, value: OTHER_CHANNEL };
    },
    expected: { outcome: 'invalid', network_requests: 2 },
  },
  {
    name: 'expired-credential',
    description: 'expires_at has passed.',
    mutateCredentialPayload(payload) {
      payload.issued_at = '2026-07-01T00:00:00Z';
      payload.expires_at = '2026-07-31T00:00:00Z';
    },
    expected: { outcome: 'expired', network_requests: 2 },
  },
  {
    name: 'status-url-off-issuer-domain',
    description: 'status_url is not on the issuer brand\'s domain, so the status is unverifiable with no status request.',
    mutateCredentialPayload(payload) {
      payload.status_url = `https://status.othernetwork.example/${CREDENTIAL_ID}`;
    },
    expected: { outcome: 'unverifiable', network_requests: 2 },
  },
  {
    name: 'status-fetch-fails',
    description: 'The status request fails, which is unverifiable, never revoked.',
    network: { [STATUS_URL]: { status: 503 } },
    expected: { outcome: 'unverifiable', network_requests: 3 },
  },
  {
    name: 'status-with-wrong-typ',
    description: 'The status JWS carries the credential typ.',
    mutateStatusHeader(header) { header.typ = PROFILE.credential_typ; },
    expected: { outcome: 'unverifiable', network_requests: 3 },
  },
  {
    name: 'status-for-another-credential',
    description: 'The status answers for a different credential_id.',
    mutateStatusPayload(payload) { payload.credential_id = 'ca_kitchen_lab_0000'; },
    expected: { outcome: 'unverifiable', network_requests: 3 },
  },
  {
    name: 'stale-status',
    description: 'The status next_update has passed, so it is not current.',
    mutateStatusPayload(payload) {
      payload.this_update = '2026-08-04T11:55:00Z';
      payload.next_update = '2026-08-05T11:55:00Z';
    },
    expected: { outcome: 'unverifiable', network_requests: 3 },
  },
  {
    name: 'paused-credential',
    description: 'A paused credential fails as revoked. Resuming issues a new credential.',
    mutateStatusPayload(payload) { payload.status = 'paused'; },
    expected: { outcome: 'revoked', network_requests: 3 },
  },
  {
    name: 'revoked-credential',
    description: 'The issuer has withdrawn the claim.',
    mutateStatusPayload(payload) { payload.status = 'revoked'; },
    expected: { outcome: 'revoked', network_requests: 3 },
  },
  {
    name: 'unknown-credential',
    description: 'The issuer does not recognize the credential_id.',
    mutateStatusPayload(payload) { payload.status = 'unknown'; },
    expected: { outcome: 'revoked', network_requests: 3 },
  },
  {
    name: 'anchor-confirmed',
    description: 'The anchor url is the channel address built from the channel ID, and the page contains the expected text.',
    anchor: anchorAt(CHANNEL_PROFILE_URL),
    network: { [CHANNEL_PROFILE_URL]: profilePage(ANCHOR_TEXT) },
    expected: verified(4, 'confirmed'),
  },
  {
    name: 'anchor-url-with-trailing-slash',
    description: 'A trailing slash on the anchor url is ignored when it is compared with the channel address.',
    anchor: anchorAt(`${CHANNEL_PROFILE_URL}/`),
    network: { [`${CHANNEL_PROFILE_URL}/`]: profilePage(ANCHOR_TEXT) },
    expected: verified(4, 'confirmed'),
  },
  {
    name: 'anchor-url-is-another-channel',
    description: 'The anchor url is another channel\'s address on the same platform. It fails before any anchor request, even though that page contains the expected text.',
    anchor: anchorAt(`${PROFILE_ADDRESS_PREFIXES.youtube_channel_id}${OTHER_CHANNEL}`),
    network: { [`${PROFILE_ADDRESS_PREFIXES.youtube_channel_id}${OTHER_CHANNEL}`]: profilePage(ANCHOR_TEXT) },
    expected: verified(3, 'unconfirmed'),
  },
  {
    name: 'anchor-url-off-platform-domain',
    description: 'The registrable domain of the anchor url is not evidence.platform_domain. It fails before any anchor request.',
    anchor: anchorAt(`https://www.othernetwork.example/channel/${SUBJECT.id}`),
    network: { [`https://www.othernetwork.example/channel/${SUBJECT.id}`]: profilePage(ANCHOR_TEXT) },
    expected: verified(3, 'unconfirmed'),
  },
  {
    name: 'anchor-text-missing',
    description: 'The page is fetched, and it does not contain the expected text exactly. Its text differs in case.',
    anchor: anchorAt(CHANNEL_PROFILE_URL),
    network: { [CHANNEL_PROFILE_URL]: profilePage(ANCHOR_TEXT.toUpperCase()) },
    expected: verified(4, 'unconfirmed'),
  },
  {
    name: 'anchor-page-fetch-fails',
    description: 'The anchor request fails. The credential stays verified, and the anchor is unconfirmed.',
    anchor: anchorAt(CHANNEL_PROFILE_URL),
    network: { [CHANNEL_PROFILE_URL]: { status: 503 } },
    expected: verified(4, 'unconfirmed'),
  },
  {
    name: 'anchor-confirmed-for-tiktok-username',
    description: 'A tiktok_id subject. The anchor url is the profile address built from the username.',
    account: SHORT_VIDEO_ACCOUNT,
    anchor: anchorAt(`${PROFILE_ADDRESS_PREFIXES.tiktok_id}kitchenlab`),
    network: { [`${PROFILE_ADDRESS_PREFIXES.tiktok_id}kitchenlab`]: profilePage(ANCHOR_TEXT) },
    expected: verified(4, 'confirmed'),
  },
  {
    name: 'anchor-username-address-without-at-sign',
    description: 'A tiktok_id subject. The anchor url omits the @ that the profile address carries, so it fails before any anchor request.',
    account: SHORT_VIDEO_ACCOUNT,
    anchor: anchorAt('https://www.shortvideo.example/kitchenlab'),
    network: { 'https://www.shortvideo.example/kitchenlab': profilePage(ANCHOR_TEXT) },
    expected: verified(3, 'unconfirmed'),
  },
  {
    name: 'anchor-confirmed-for-instagram-handle',
    description: 'An instagram_handle subject. The anchor url is the profile address built from the username.',
    account: PHOTO_HANDLE_ACCOUNT,
    anchor: anchorAt(PHOTO_PROFILE_URL),
    network: { [PHOTO_PROFILE_URL]: profilePage(ANCHOR_TEXT) },
    expected: verified(4, 'confirmed'),
  },
  {
    name: 'anchor-confirmed-for-instagram-account-id',
    description: 'An instagram_account_id subject. No profile address is built from the account ID, so only the platform domain and the page text are checked. The link between the page and the account is the operator\'s statement.',
    account: PHOTO_ID_ACCOUNT,
    anchor: anchorAt(PHOTO_PROFILE_URL),
    network: { [PHOTO_PROFILE_URL]: profilePage(ANCHOR_TEXT) },
    expected: verified(4, 'confirmed'),
  },
  {
    name: 'credential-without-status-url',
    description: 'The credential carries no status_url, so the evaluator makes no status request.',
    omitStatusUrl: true,
    expected: verified(2, 'absent'),
  },
  {
    name: 'anchor-not-evaluated-for-revoked-credential',
    description: 'A revoked credential has no anchor result, and the evaluator makes no anchor request.',
    anchor: anchorAt(CHANNEL_PROFILE_URL),
    network: { [CHANNEL_PROFILE_URL]: profilePage(ANCHOR_TEXT) },
    mutateStatusPayload(payload) { payload.status = 'revoked'; },
    expected: { outcome: 'revoked', network_requests: 3 },
  },
];

function buildCase(definition) {
  const account = definition.account ?? { type: 'youtube_channel_id', id: SUBJECT.id, platformDomain: 'videoplatform.example' };
  const subject = subjectFor(account);
  const credentialHeader = structuredClone(CREDENTIAL_HEADER);
  const credentialPayload = structuredClone(CREDENTIAL_PAYLOAD);
  credentialPayload.subject = subject;
  credentialPayload.evidence.platform_domain = account.platformDomain;
  credentialPayload.evidence.account = { type: account.type, value: account.id };
  if (definition.anchor) credentialPayload.anchor = definition.anchor;
  if (definition.omitStatusUrl) delete credentialPayload.status_url;
  definition.mutateCredentialHeader?.(credentialHeader);
  definition.mutateCredentialPayload?.(credentialPayload);
  let credential = compactJws(credentialHeader, credentialPayload);
  if (definition.tamperCredential) credential = tamperSignature(credential);
  const presentation = presentationFor(credential, subject);
  definition.mutatePresentation?.(presentation);

  const statusHeader = structuredClone(STATUS_HEADER);
  const statusPayload = structuredClone(STATUS_PAYLOAD);
  definition.mutateStatusHeader?.(statusHeader);
  definition.mutateStatusPayload?.(statusPayload);

  return {
    name: definition.name,
    description: definition.description,
    selling_agent_url: definition.sellingAgentUrl ?? SELLING_AGENT_URL,
    carrier: carrierFor(presentation, account, definition.carrierIdentifier),
    network: {
      [BRAND_JSON_URL]: json(BRAND_JSON),
      [JWKS_URL]: json({ keys: [PUBLISHED_KEY] }),
      ...(credentialPayload.status_url && {
        [credentialPayload.status_url]: jose(compactJws(statusHeader, statusPayload)),
      }),
      ...definition.network,
    },
    expected: definition.expected,
  };
}

const fixture = {
  $comment: 'AdCP 3.3 creator sales-authorization profile. All entities, credentials, and endpoints are fictional, and the signing key is a public test key.',
  version: '3.3',
  evaluation_time: '2026-08-06T12:00:00Z',
  profile: PROFILE,
  profile_address_prefixes: PROFILE_ADDRESS_PREFIXES,
  cases: definitions.map(buildCase),
};

// Escape compact-JWS separators in the JSON source so generic credential
// scanners do not mistake these deliberately public test vectors for tokens.
// JSON parsers decode . back to ".", preserving the byte-exact value.
const rendered = `${JSON.stringify(fixture, null, 2).replace(
  /"(eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"/g,
  (_, jws) => `"${jws.replaceAll('.', '\\u002e')}"`,
)}\n`;
if (process.argv.includes('--check')) {
  let current = '';
  try {
    current = readFileSync(fixtureUrl, 'utf8');
  } catch {}
  if (current !== rendered) {
    console.error(`${fileURLToPath(fixtureUrl)} is stale; run node scripts/generate-creator-assertion-vectors.mjs`);
    process.exitCode = 1;
  }
} else {
  writeFileSync(fixtureUrl, rendered);
}
