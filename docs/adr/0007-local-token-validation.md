# Local token validation

The API validates the access token locally. It checks the signature with the realm JWKS, then `iss`, `aud`, `exp` and the roles.

Keycloak keeps no session for the token (ADR 0008), and its `sub` is no stored user (ADR 0002). So token introspection reports it as inactive and the userinfo endpoint refuses it.

The access token is a plain bearer token. DPoP (RFC 9449) is not supported.

## Consequences

To revoke a delegation early, the issuer revokes the credential in its status list. An access token stays valid until its `exp`, which is never after the earliest `exp` of the chain.

The extension implements internal SPIs of Keycloak (token exchange, identity provider, mapper and realm resource). Keycloak logs KC-SERVICES0047 at startup for each of these providers. Internal SPIs can change in any Keycloak release, so each Keycloak update needs a run of the integration tests.
