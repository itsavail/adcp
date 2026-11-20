# Creator attestation vectors

These vectors exercise the experimental creator sales-authorization profile (`media_buy.social_profiles`) composed with the shared portable-attestation contract. They are served at `/compliance/{version}/test-vectors/creator-attestations/vectors.json`.

Each case is complete. It gives the selling agent URL, the carrier that holds the presentation in `attestations[0]`, and the responses the evaluator's network returns, keyed by URL. `carrier_kind` says what the carrier is. `brand_json_property` is a `brand.json` property, `property` is a `core/property.json` property, and `collection` is a collection. A URL missing from `network`, or a non-200 response, is a failed request. The credentials and status responses are real Ed25519 JWS compact serializations signed with a public test key. `scripts/generate-creator-assertion-vectors.mjs` builds the file, and `npm run test:creator-attestations` checks that it is current. The script publishes the private key for the fixture only. Never use that key as a production trust anchor.

Evaluate each case at `evaluation_time` under the [creator sales-authorization profile](/docs/building/by-layer/L1/security#creator-sales-authorization-profile-3-3-experimental), in this order:

1. Without network access, check that the reference is this profile's, then the digest, the credential header, the subject against the carrier, and the issuer against the selling agent's operator. The fixture hosts use `.example`, so a host's registrable domain is its last two labels.
2. The issuer's `brand.json` at `/.well-known/brand.json`, then the JWKS of the one `type: "sales"` entry whose URL is the selling agent's, then the signature.
3. The payload claim checks, without network access.
4. The status, when the credential carries a `status_url`. First the host check, then the request, then the signed status. A credential with no `status_url` skips this step.
5. The creator anchor, only when the outcome is `verified`. First the profile address check, then the check that the expected text names the issuer, then the request for the page. A case with no `anchor` in the credential payload has the result `absent`.

Conformance runners MUST produce `expected.outcome`, make exactly `expected.network_requests` requests, and, for a `verified` result, produce `expected.action_binding`, `expected.anchor` and `expected.valid_until`. A verified result that used the status check also carries `expected.revocation_checked_at`, which is the evaluation time. The request count includes the anchor request. An anchor that fails either of the first two checks makes no request. A paused, revoked or unknown status fails as `revoked`. A failed or unverifiable status is `unverifiable`, never `revoked`.

The profile names the real platform hosts in its profile address rule. The fixtures use `.example` hosts in their place, and `profile_address_prefixes` gives the stand-in for each identifier type. A runner builds the profile address as the prefix followed by `subject.id`. The paths are the ones the profile defines, `/channel/<id>`, `/@<username>` and `/<username>`. An identifier type with no entry, `instagram_account_id`, has no profile address, so its anchor is `unconfirmed`. A leading `@` on `subject.id` is dropped before the address is built.
