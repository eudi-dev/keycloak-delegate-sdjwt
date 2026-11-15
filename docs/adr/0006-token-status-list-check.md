# Token Status List check

If the credential has a `status` claim, the exchange loads its status list (draft-ietf-oauth-status-list-21). The exchange fails if the status is not VALID. It also fails if the list can't be loaded, its URI doesn't use https, or the list token is invalid. A list token is invalid with a bad signature, a wrong `sub`, an expired `exp` or no `iat` (§5.1).

A credential without a `status` claim passes. Its trusted issuer signed it without one.

The status list token must be signed with a key of the credential issuer (ADR 0005). With X.509 trust anchors, its leaf certificate must match the credential `iss`. The draft doesn't require `iss` in the list token. If it has one, it must equal the credential `iss`.

## Consequences

The exchange loads the list on every request with the Keycloak HTTP client. Each connection step has 5 seconds and the whole load 10 seconds. The list token can have at most 1 MB. There is no cache. Any https host can serve a status list.

The KB-SD-JWTs have no status. A delegation ends when its `exp` passes.
