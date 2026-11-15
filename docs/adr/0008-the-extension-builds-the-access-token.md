# The extension builds the access token

After the chain check, the exchange provider builds the access token itself. It signs the token with `session.tokens().encode`, so the active realm key and the access token algorithm of the client apply. There is no user, no user session and no client session behind the token.

Keycloak builds its tokens from a user session. The principal is no user of the realm, so such a session would need a user that exists only for the request. Keycloak 26.8.2 offers that only through the experimental `transient-users` feature, which Keycloak plans to remove. Building the token in the extension needs no experimental feature.

The token holds these claims.

| Claim | Value |
| --- | --- |
| `iss` | The realm issuer |
| `sub` | The UUID of the principal (ADR 0002) |
| `act` | The agents of the chain (ADR 0002) |
| `azp` | The client that asks for the token |
| `aud` | Each other client the token holds a role of |
| `iat`, `exp` | The access token lifespan of the client or else of the realm, but never after the earliest `exp` of the chain |
| `jti` | A random UUID |
| `typ` | `Bearer` |
| `realm_access`, `resource_access` | The roles the action role mappers grant, with their composite roles |

The claim mappers add their claims last (ADR 0004).

With the `audience` parameter, each requested client must be one the token holds a role of. Then `aud` and `resource_access` hold only the requested clients. Any other requested audience gives `invalid_request`.

The response holds `access_token`, `issued_token_type` with the value `urn:ietf:params:oauth:token-type:access_token`, `token_type` with `Bearer` and `expires_in`.

## Consequences

Only the mappers of the identity provider shape the token. The protocol mappers, client scopes, scope mappings and full scope setting of the client don't apply. A hardcoded role mapper on the client adds no role.

No scope can narrow the token, so the exchange refuses the `scope` parameter and the token has no `scope` claim.

Keycloak authenticates the client and runs the client policies for the token exchange request. Client policies on the token response and consent need a client session, so they don't run.

The exchange needs only the `token-exchange-standard` feature of Keycloak.
