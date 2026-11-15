# Keycloak Delegate SD-JWT

A Keycloak 26.8.2 extension for AI agents. An agent sends a Delegate SD-JWT (draft-ietf-oauth-delegate-sd-jwt-00) in an RFC 8693 token exchange. The extension checks the whole delegation chain and returns an access token. Mappers in the realm decide which roles and claims the token gets.

## Example

Bob is an accountant at Acme Logistics GmbH. He holds a power of attorney credential for Acme. Bob delegates invoice approval to the "Procurement agent" up to 2500 EUR. The agent gets a supplier invoice of 1840 EUR and wants to approve it in Acme's invoice API.

1. Bob signs a KB-SD-JWT for the agent. Its Delegate Payload allows the action `invoice.approve` with a limit of 2500 EUR.
2. The agent gets a nonce from Keycloak and signs a Key Binding JWT with it.
3. The agent exchanges the chain at the Keycloak token endpoint.
4. Keycloak returns an access token with the role `invoice-approver` and the claim `approval_limit`.
5. The invoice API checks the token. 1840 EUR is within `approval_limit`, so it approves the invoice.

The decoded Delegate Payload signed by Bob:

```json
{
  "vct": "urn:eudi-test:business:agent-mandate:1",
  "iat": 1795075100,
  "exp": 1795078800,
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } },
  "agent": { "id": "urn:eudi-test:agent:procurement-1", "name": "Procurement agent" },
  "mandate": {
    "actions": ["invoice.approve"],
    "limit": { "amount": "2500.00", "currency": "EUR" },
    "audiences": ["https://iam.acme.example/realms/acme"]
  }
}
```

The access token for the agent:

```json
{
  "iss": "https://iam.acme.example/realms/acme",
  "sub": "d50f1bc1-22df-3ff7-af38-04b58dedb013",
  "aud": "invoice-api",
  "azp": "procurement-agent",
  "typ": "Bearer",
  "iat": 1795075200,
  "exp": 1795075500,
  "jti": "0f8e1c52-2d4b-4a51-9b7e-3c1d2e4f5a6b",
  "act": { "sub": "urn:eudi-test:agent:procurement-1" },
  "resource_access": { "invoice-api": { "roles": ["invoice-approver"] } },
  "approval_limit": { "amount": "2500.00", "currency": "EUR" }
}
```

`sub` stands for Acme, the principal of the credential. Bob signs the delegation, but he doesn't appear in the token. `act` is the agent (ADR 0002).

## Names

| Source | Names |
| --- | --- |
| draft-ietf-oauth-delegate-sd-jwt-00 | dSD-JWT+KB, KB-SD-JWT with typ `kb-sd-jwt+kb`, Delegate Payload in `delegate_payload`, `cnf` key in each Delegate Payload, `sd_hash` and `issuer_jwt_hash` |
| RFC 9901 (SD-JWT) | Key Binding JWT with typ `kb+jwt`, Disclosures |
| RFC 8693 (token exchange) | `subject_token`, `audience`, the `act` claim |
| This extension | Token type `urn:eudi-dev:params:oauth:token-type:dsd-jwt-kb`, the nonce endpoint, the identity provider type and the 2 mapper types |
| Example choices | All `vct` values, `euid_reference`, `authorisation.actions`, `agent.id`, `mandate.actions`, `mandate.limit`, `mandate.audiences`, `invoice.approve`, `invoice-api`, `invoice-approver`, `approval_limit`, `procurement-agent` |

The draft leaves the content of a Delegate Payload open. Each realm sets its own paths for the principal, actions, agent id and audience. `agent.id` and `mandate.actions` are only the defaults.

## Install

Requirements:

- Keycloak 26.8.2
- The feature `token-exchange-standard` (on by default)
- For a Default Trust identity provider, one of the features `oid4vc-vci`, `oid4vc-vp` or `client-auth-abca`

Build the JAR with Java 21 or later. The integration tests need Docker. Add `-DskipITs` to skip them.

```sh
mvn -B verify
cp target/keycloak-delegate-sdjwt.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
```

## Realm setup

### Client

Create a confidential client `procurement-agent` for the agent. Turn on **Standard Token Exchange**. It needs no other flow.

Create a client `invoice-api` with the client role `invoice-approver`.

### Identity provider

Add an identity provider of type **Delegate SD-JWT**.

| Setting | Example | Meaning |
| --- | --- | --- |
| `clients` | `procurement-agent` | Clients that may exchange a Delegate SD-JWT, comma separated. A client may appear in only 1 such identity provider |
| `trustedIssuerJwks` | `{"https://register.example": {"keys": [...]}}` | Keys of each trusted credential issuer, by `iss` |
| `trustMaterialIdps` | | Aliases of trust material identity providers, for example a Default Trust identity provider with X.509 anchors. Use this instead of `trustedIssuerJwks` |
| `credentialTypes` | `urn:eudi-test:business:poa:1` | Accepted `vct` values of the credential. Required |
| `principalClaim` | `euid_reference` | Path of the principal in the credential. Required |
| `credentialActionsPath` | `authorisation.actions` | Path of the action list in the credential. Required |
| `actionsPath` | `mandate.actions` | Path of the action list in a Delegate Payload (default `mandate.actions`) |
| `agentIdPath` | `agent.id` | Path of the agent id in a Delegate Payload (default `agent.id`) |
| `audiencePath` | `mandate.audiences` | Path of a list in each Delegate Payload. The list must contain the realm issuer |

A path is a list of object keys, separated by dots. ADR 0005 explains issuer trust.

### Mappers

Add mappers to the identity provider. They run in the order of their names.

**Delegated Action to Role** grants a role when the credential and every Delegate Payload allow the action.

| Setting | Example |
| --- | --- |
| `action` | `invoice.approve` |
| `role` | `invoice-api.invoice-approver` |

**Delegate Payload to Claim** copies a value of the first Delegate Payload into a token claim. A later Delegate Payload may leave it out or repeat it. Any other value makes the exchange fail.

| Setting | Example |
| --- | --- |
| `source` | `mandate.limit` |
| `claim.name` | `approval_limit` |
| `required` | `true` |

The agent may leave out any Disclosure. Mark a value that restricts the agent, like a limit, as `required`. ADR 0004 has the details.

## Exchange

The agent gets a nonce. It is valid for 120 seconds. The option `--spi-realm-restapi-extension--delegate-sd-jwt--nonce-lifespan` changes that.

```sh
curl -s -u procurement-agent:$CLIENT_SECRET -X POST \
  https://iam.acme.example/realms/acme/delegate-sd-jwt/nonce
```

```json
{ "nonce": "oF0Jx1n0r7cUv0W2kXo5vN8Q6Yh3dPq1aLz4sTn9mEc", "expires_in": 120 }
```

The agent puts the nonce and the realm issuer as `aud` in its Key Binding JWT. Keycloak accepts the Key Binding JWT for 5 minutes after its `iat`. All time claims have 60 seconds of tolerance. Then the agent exchanges the dSD-JWT+KB.

```sh
curl -s -u procurement-agent:$CLIENT_SECRET \
  https://iam.acme.example/realms/acme/protocol/openid-connect/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:eudi-dev:params:oauth:token-type:dsd-jwt-kb \
  --data-urlencode subject_token="$DSD_JWT_KB" \
  -d audience=invoice-api
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "expires_in": 300,
  "token_type": "Bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

The token expires with the realm or client access token lifespan, and never after the earliest `exp` of the chain.

## Checks

- The credential is signed by a trusted key of its `iss` and has an accepted `vct`.
- Each KB-SD-JWT is signed by the `cnf` key of the step before it. Its hashes and Disclosures match and its Delegate Payload has not expired.
- The chain has at most 4 KB-SD-JWTs.
- The Key Binding JWT is signed by the `cnf` key of the last Delegate Payload. Its `aud` is the realm issuer and its nonce is unused.
- The delegated actions are those that the credential and every Delegate Payload allow.
- If the credential has a Token Status List entry, its status is valid (draft-ietf-oauth-status-list-21).

A failed check returns `invalid_request` with the reason. A public client gets `invalid_client`. A client without an identity provider gets `unauthorized_client`. A `scope` parameter gets `invalid_scope`. A configuration error gets `server_error`.

## Limits

- The extension doesn't compare amounts. The invoice API checks the 1840 EUR against `approval_limit`.
- The exchange returns only an access token. It returns no refresh token and no ID token, and it refuses `scope`.
- Keycloak keeps no user and no session for the token. Introspection reports it as inactive and userinfo refuses it. The API validates the token locally with the realm JWKS.
- The token is a plain bearer token. DPoP is not supported.
- The status list is loaded on every exchange, without a cache.
- A KB-SD-JWT has no status. A delegation ends when its `exp` passes.

## Sample chains

The tests use sample chains from eudi-dev. `tools/samplechains` writes them with the eudi-dev Go library (version 3.11.0 or later). The Java tests verify the same bytes.

```sh
cd tools/samplechains && go run . -out ../../src/test/resources/sample-chains
```

## Design decisions

The ADRs in [docs/adr](docs/adr) explain each decision.

1. [Token exchange with a Delegate SD-JWT](docs/adr/0001-token-exchange-with-a-delegate-sd-jwt.md)
2. [The principal is the subject and the agents are the actor](docs/adr/0002-principal-is-the-subject-and-agents-are-the-actor.md)
3. [A single use nonce from the realm](docs/adr/0003-single-use-nonce-from-the-realm.md)
4. [Mappers decide what the token grants](docs/adr/0004-mappers-decide-what-the-token-grants.md)
5. [Issuer trust through Keycloak](docs/adr/0005-issuer-trust-through-keycloak.md)
6. [Token Status List check](docs/adr/0006-token-status-list-check.md)
7. [Local token validation](docs/adr/0007-local-token-validation.md)
8. [The extension builds the access token](docs/adr/0008-the-extension-builds-the-access-token.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
