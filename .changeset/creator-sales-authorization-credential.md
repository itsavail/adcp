---
"adcontextprotocol": minor
---

Creator sales-authorization credential (experimental, `media_buy.social_profiles`, part of #6538): an operator that sells for a creator's platform account can sign that claim.

`core/property.json`, `core/collection.json` and the `brand.json` property definition gain `attestations`, a list of portable attestation references. For a `social_profile` account the reference embeds a JWS whose payload is the new `core/creator-assertion.json`. The issuer is the selling agent's operator. The credential expires. An optional `status_url` answers a signed `core/creator-assertion-status.json`, so the operator can pause or revoke a copy that a buyer has stored. A buyer can also confirm a credential by reading it from the selling agent's current response or published file.

The optional `core/creator-anchor.json` lets the creator confirm the claim with a line of text in the account's public profile. A buyer that confirms the anchor with its own request treats the claim as mutually attested. Without a confirmed anchor the claim is operator-attested.

`attestations` joins the closed list of collection fields on which a response copy wins over `adagents.json`. The creator sales-authorization profile in the security documentation defines the evaluation order, and `static/compliance/source/test-vectors/creator-attestations/` holds the conformance vectors.
