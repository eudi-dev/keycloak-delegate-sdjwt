# Token Status List check

When a credential has a `status` claim, the exchange fetches its status list as draft-ietf-oauth-status-list-21 describes. If the status is not VALID, the exchange fails. It also fails if the list cannot be loaded or its URI does not use https. The same applies to a list token with a bad signature, a wrong `sub`, an expired `exp` or a missing `iat`. The draft requires `iat` in §5.1.

A credential without a `status` claim passes. Its trusted issuer signed it without one.

The status list token must be signed with a key of the credential issuer (ADR 0005). With X.509 trust anchors, the leaf certificate of the status list token must name the credential issuer too. The draft does not require `iss` in that token. If it has one, it must equal the `iss` of the credential.

## Consequences

The exchange loads the list on every request through the Keycloak HTTP client. Each load has 5 seconds per connection step and 10 seconds in total, and the list token can have at most 1 MB. There is no cache yet, and any https host is accepted as a status list location.

The KB-SD-JWTs carry no status. A delegation ends when its `exp` passes.
