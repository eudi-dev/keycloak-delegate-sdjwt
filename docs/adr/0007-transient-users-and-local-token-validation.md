# Transient users and local token validation

The token subject is a Keycloak lightweight user that lives only in a transient user session. This needs the `transient-users` feature, which Keycloak 26.8.2 marks as experimental. The exchange provider is not available without it.

The API that receives the access token validates it locally. It checks the signature with the realm JWKS and then `iss`, `aud`, `exp` and the roles. Keycloak keeps no session for the token. Its `sub` never belongs to a stored user (ADR 0002), so token introspection reports it as inactive and the userinfo endpoint refuses it.

The access token is a plain bearer token. DPoP (RFC 9449) is out of scope for now.

## Consequences

Revoking a delegation early needs the status list of the credential. The access token stays valid until its `exp`, which never passes the earliest `exp` of the chain.

Keycloak logs a warning at startup that the `transient-users` feature is experimental. It also logs KC-SERVICES0047 for each provider of an internal SPI, which here are the token exchange, identity provider, mapper and realm resource providers. Internal SPIs can change in any Keycloak release, so each Keycloak update needs a run of the integration tests.
