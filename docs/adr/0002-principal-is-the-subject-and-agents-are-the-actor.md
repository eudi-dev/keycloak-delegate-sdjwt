# The principal is the subject and the agents are the actor

The access token says who the agent acts for in `sub` and who acts in `act`, as RFC 8693 §4.1 describes. The last agent of the chain is the outermost `act`. Each earlier agent nests 1 level deeper.

```json
{
  "sub": "5c0b5f0e-3bd4-3a43-9a5b-4b5fe2f1b0a1",
  "act": {
    "sub": "urn:eudi-test:agent:procurement-2",
    "act": { "sub": "urn:eudi-test:agent:procurement-1" }
  }
}
```

The principal comes from a credential claim. The identity provider setting `principalClaim` holds its path, for example `euid_reference`. An agent is the value at `agentIdPath` in its Delegate Payload. Without that value the agent is the JWK thumbprint URI of its `cnf` key (RFC 9278).

The principal becomes a transient user with the principal as username. Its `sub` is a UUID made from the credential `iss` and the principal. The issuer key or certificate is bound to that `iss` (ADR 0005), so 1 issuer cannot claim the principals of another. The same principal always gets the same `sub`. Nothing is stored in the realm.

The `sub` is never the id of a stored user. Keycloak introspects a token without a session by loading the user with the `sub` as id. For a stored user it would then report the user's own roles and drop the delegated ones. If a stored user has the derived `sub` as id, the exchange fails with `server_error`.

## Consequences

The token carries only the roles the mappers grant.

Keycloak needs the `transient-users` feature, because the token subject is a lightweight user (see ADR 0007).
