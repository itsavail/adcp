---
"adcontextprotocol": minor
---

Social profiles (experimental, `media_buy.social_profiles`, part of #6538): creator and publisher accounts on social and video platforms become properties, with operator-attested evidence that the account owner connected the operator.

- **`social_profile` properties.** `enums/property-type.json` adds `social_profile`, and `enums/identifier-types.json` adds `youtube_channel_id`, `tiktok_id`, `instagram_account_id` and `instagram_handle`, the names the collection identifier list already uses. `tiktok_id` and `instagram_handle` hold the username, and the `tiktok_id` description now says so in both lists. The `brand.json` property definition gains `identifier_type`, required when `type` is `social_profile`.
- **Owner authorization.** `core/owner-authorization.json` is carried as `owner_authorizations` on `core/property.json`, `core/collection.json` and the `brand.json` property definition. A `platform_oauth` record states that the account owner approved an OAuth grant to the operator. Buyers rank it above owner-attested carriage and below `adagents.json`-backed states. For a username record, the operator re-reads the username at each check, and buyers treat a record older than 7 days as absent.
- **Collection copies.** A response copy wins over `adagents.json` for `owner_authorizations`.
