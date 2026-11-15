# The extension builds the access token

After the checks, the exchange provider builds the access token itself. There is no user, no user session and no client session behind the token. Keycloak builds its own tokens from a user session, but the principal is no user of the realm.

The provider signs the token with `session.tokens().encode`. The active realm key and the access token algorithm of the client apply.

| Claim | Value |
| --- | --- |
| `iss` | The realm issuer |
| `sub` | The UUID of the principal (ADR 0002) |
| `act` | The agents of the chain (ADR 0002) |
| `azp` | The client that asks for the token |
| `aud` | Each other client with a role in the token |
| `iat`, `exp` | The access token lifespan of the client or else of the realm, but never after the earliest `exp` of the chain |
| `jti` | A random UUID |
| `typ` | `Bearer` |
| `realm_access`, `resource_access` | The roles granted by the action role mappers, with their composite roles |

The claim mappers add their claims last (ADR 0004).

With the `audience` parameter, each requested client must have a role in the token. `aud` and `resource_access` then hold only the requested clients. Any other audience gives `invalid_request`.

The response holds `access_token`, `token_type` `Bearer`, `expires_in` and `issued_token_type` `urn:ietf:params:oauth:token-type:access_token`.

## Consequences

Only the mappers of the identity provider shape the token. The protocol mappers, client scopes, scope mappings and full scope setting of the client don't apply. A hardcoded role mapper on the client adds no role.

No scope can narrow the token, so the exchange refuses `scope` and the token has no `scope` claim.

Client policies for the token response and consent need a client session, so they don't run.

The exchange needs only the `token-exchange-standard` feature of Keycloak.
