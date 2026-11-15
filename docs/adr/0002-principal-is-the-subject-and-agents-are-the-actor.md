# The principal is the subject and the agents are the actor

The access token says who the agent acts for in `sub` and who acts in `act` (RFC 8693 §4.1). The last agent of the chain is the outermost `act`. Each earlier agent is nested 1 level deeper.

```json
{
  "sub": "d50f1bc1-22df-3ff7-af38-04b58dedb013",
  "act": {
    "sub": "urn:eudi-test:agent:procurement-2",
    "act": { "sub": "urn:eudi-test:agent:procurement-1" }
  }
}
```

The principal is a text claim of the credential. The setting `principalClaim` holds its path, for example `euid_reference`. Each agent id is the value at `agentIdPath` in its Delegate Payload. Without that value, the agent id is the JWK thumbprint URI of its `cnf` key (RFC 9278).

The `sub` is a UUID made from the credential `iss` and the principal. The same principal always gets the same `sub`, and nothing is stored in the realm. The issuer key is bound to the `iss` (ADR 0005), so 1 issuer cannot speak for the principals of another.

The `sub` is never the id of a stored user. For a token without a session, Keycloak looks up the user with the `sub` as id. For a stored user it would then report that user's own roles. If a stored user has the derived id, the exchange fails with `server_error`.

## Consequences

The token carries only the roles granted by the mappers. The principal is no user of the realm, and the token has no session (ADR 0008).
