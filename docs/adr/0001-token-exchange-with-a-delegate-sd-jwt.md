# Token exchange with a Delegate SD-JWT

An agent proves its delegation with a dSD-JWT+KB (draft-ietf-oauth-delegate-sd-jwt-00 §5.1.1). It sends the chain as the `subject_token` of an RFC 8693 token exchange and gets an access token of the realm.

The draft defines no token type URN. The extension uses `urn:eudi-dev:params:oauth:token-type:dsd-jwt-kb`.

The extension is a token exchange provider with order 20. Keycloak asks the provider with the highest order first, and 20 is higher than the order of every built-in provider. So the extension handles every request with its token type, and no other provider reads the chain as its own token. An unsupported request gets a precise error.

Keycloak authenticates the client and runs the client policies for the request. The provider then checks the chain and builds the access token (ADR 0008).

## Consequences

The exchange issues access tokens only. It refuses requests for a refresh token or an ID token and any `scope`. When the token expires, the agent exchanges the chain again with a fresh Key Binding JWT.

The exchange refuses `actor_token`, `requested_subject`, `requested_issuer` and `subject_issuer`. The chain itself says who acts for whom.

The client must be confidential and have standard token exchange turned on.
