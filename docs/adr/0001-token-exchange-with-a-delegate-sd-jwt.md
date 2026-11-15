# Token exchange with a Delegate SD-JWT

An AI agent proves its delegation with a dSD-JWT+KB as described in draft-ietf-oauth-delegate-sd-jwt-00 §5.1.1. Keycloak takes it as the `subject_token` of an RFC 8693 token exchange and returns an access token for the realm.

The token type is `urn:eudi-dev:params:oauth:token-type:dsd-jwt-kb`. The draft defines no token type URN, so the extension uses its own. It will switch to a registered URN once the draft has one.

The extension plugs into the token exchange provider SPI with order 20. Keycloak asks the provider with the highest order first, and standard token exchange has order 10. The provider claims every request with the Delegate SD-JWT token type, so no other provider reads the dSD-JWT+KB as a token of its own. It refuses the requests it cannot serve with a precise error.

The provider reuses the standard token exchange of Keycloak 26.8.2 for everything after the chain check. Client authentication, audience checks, consent, client policies and token building stay the same as for any other exchange.

## Consequences

The exchange issues access tokens only. A request for a refresh token or an ID token is refused, and so is the scope `openid`. The agent asks for a new token with a fresh Key Binding JWT when the old one expires.

`actor_token`, `requested_subject`, `requested_issuer` and `subject_issuer` are refused. The chain itself says who acts for whom.

The client needs standard token exchange enabled and must be confidential.
