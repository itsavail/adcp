---
"adcontextprotocol": minor
---

Add experimental `social_profile` properties with operator-attested owner authorization (`media_buy.social_profiles`, part of #6538). Adds the `social_profile` property type, the `youtube_channel_id`, `tiktok_id` and `instagram_user_id` identifier types, and `core/owner-authorization.json`, carried as `owner_authorizations` on properties, collections and `brand.json` properties. A `platform_oauth` record states that the account owner approved an OAuth grant to the operator. Buyers rank it above owner-attested carriage and below `adagents.json`-backed states. `owner_authorizations` is excluded from `publisher_collection` definition pins, and a response copy wins over `adagents.json` for it.
