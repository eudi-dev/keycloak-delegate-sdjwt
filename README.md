# Keycloak Delegate SD-JWT

A Keycloak extension that lets an AI agent exchange its delegation for an access token.

A company gives an agent a Delegate SD-JWT with Key Binding (draft-ietf-oauth-delegate-sd-jwt-00). The agent sends it to Keycloak in an RFC 8693 token exchange. Keycloak checks the whole chain and returns an access token. The token carries the roles and claims the realm admin mapped from the delegation. The agent then calls an internal API with that token.

Acme Logistics GmbH holds a power of attorney credential. It delegates invoice payments for Bolt Supplies B.V. to its procurement agent. The agent gets this access token:

```json
{
  "iss": "https://iam.acme.example/realms/acme",
  "sub": "5c0b5f0e-3bd4-3a43-9a5b-4b5fe2f1b0a1",
  "azp": "procurement-agent",
  "act": { "sub": "urn:eudi-test:agent:procurement-1" },
  "resource_access": { "invoice-api": { "roles": ["invoice-payer"] } },
  "mandate_limit": { "amount": "5000.00", "currency": "EUR" }
}
```

## What it checks

- The credential has an `iss` and is signed by a key of that issuer (ADR 0005).
- The credential has an accepted `vct`. The delegated actions are limited to the ones the credential lists (ADR 0004).
- Each KB-SD-JWT is signed by the `cnf` key of the step before it. Its `sd_hash`, Delegate Payload and disclosures match, and its `iat`, `nbf` and `exp` hold.
- The chain has at most 4 KB-SD-JWTs.
- The Key Binding JWT is signed by the `cnf` key of the last Delegate Payload. Its `aud` is the realm issuer and its nonce is a fresh one from the realm (ADR 0003).
- The credential status is VALID when it has a status list entry (ADR 0006).

If a check fails, the exchange returns `invalid_request` with a description of the failure. Other refusals use these errors.

- `invalid_client` for a public client.
- `unauthorized_client` when no Delegate SD-JWT identity provider lists the client.
- `invalid_scope` for the scope `openid`.
- `server_error` when the identity provider or a mapper is misconfigured.

## Requirements

- Keycloak 26.8.2
- The features `token-exchange-standard` (on by default) and `transient-users`
- For a Default Trust identity provider, one of the features `oid4vc-vci`, `oid4vc-vp` or `client-auth-abca`

## Install

Build the JAR with Java 21 or later:

```sh
mvn -B verify
```

The integration tests start Keycloak with Testcontainers, so they need Docker. Use `-DskipITs` to skip them.

Copy `target/keycloak-delegate-sdjwt.jar` to `/opt/keycloak/providers/` and start Keycloak with transient users:

```sh
bin/kc.sh build --features=transient-users
bin/kc.sh start --optimized
```

`transient-users` is an experimental Keycloak feature (ADR 0007).

## Realm setup

### Client

The agent uses a confidential client with **Standard Token Exchange** turned on. It needs no other flow. Full scope or scope mappings must allow the roles the mappers grant.

### Identity provider

Add an identity provider of type **Delegate SD-JWT**. It holds the settings for the clients it lists. A client may appear in only 1 such identity provider.

| Setting | Default | Meaning |
| --- | --- | --- |
| `clients` | | Client IDs that may exchange a Delegate SD-JWT, comma separated |
| `trustMaterialIdps` | | Aliases of trust material identity providers with the issuer keys or X.509 anchors. A Default Trust identity provider needs X.509 turned on. A Delegate SD-JWT identity provider is not accepted. Set this or `trustedIssuerJwks` |
| `trustedIssuerJwks` | | JSON object from each issuer `iss` to the JWK Set of that issuer, for example `{"https://register.example": {"keys": [...]}}`. Set this or `trustMaterialIdps` |
| `principalClaim` | | Path of the credential claim with the principal, for example `euid_reference` |
| `credentialTypes` | | Accepted `vct` values of the credential, comma separated. Required |
| `credentialActionsPath` | | Path of the action list in the credential, for example `authority.proxy_employee_authorisation.authorisation_scope`. Required |
| `actionsPath` | `mandate.actions` | Path of the action list in a Delegate Payload |
| `agentIdPath` | `agent.id` | Path of the agent identifier in a Delegate Payload |
| `audiencePath` | | Path of a list in each Delegate Payload that must contain the realm issuer |
| `delegateTypes` | | Accepted `vct` values of a Delegate Payload, comma separated |

A path is a dot separated list of object keys.

The Key Binding JWT is accepted for 5 minutes after its `iat`. Every time claim has 60 seconds of tolerance.

With X.509 trust anchors, the leaf certificate of the credential and of the status list token must name the `iss`. ADR 0005 has the rules.

ADR 0002 describes how the principal and the agents appear in the token.

### Mappers

The identity provider takes 2 mapper types. They run in the order of their names.

**Delegated Action to Role** grants a role when every Delegate Payload of the chain allows the action.

| Setting | Example |
| --- | --- |
| `action` | `invoice:pay` |
| `role` | `invoice-api.invoice-payer` |

**Delegate Payload to Claim** copies a value of the first Delegate Payload into an access token claim. A later link may leave the value out or repeat it. If a later link changes the value or adds one, the exchange fails. The first delegator sets the value, and the credential does not limit it.

| Setting | Example |
| --- | --- |
| `source` | `mandate.limit` |
| `claim.name` | `mandate_limit` |
| `required` | `true` |

Without `required`, a delegation that lacks the value gets a token without the claim. An agent may leave out any Disclosure, so map a value that restricts the agent, like a spending limit, as required.

An action without a mapper grants nothing. If a delegation grants no role, the exchange fails. ADR 0004 has the rules for both mapper types.

### Nonce lifespan

A nonce is valid for 120 seconds. To change it, start Keycloak with `--spi-realm-restapi-extension--delegate-sd-jwt--nonce-lifespan=60`.

## Exchange

The token type of the `subject_token` is `urn:eudi-dev:params:oauth:token-type:dsd-jwt-kb` (ADR 0001).

First the agent gets a nonce:

```sh
curl -s -u procurement-agent:$CLIENT_SECRET -X POST \
  https://iam.acme.example/realms/acme/delegate-sd-jwt/nonce
```

```json
{ "nonce": "oF0Jx1n0r7cUv0W2kXo5vN8Q6Yh3dPq1aLz4sTn9mEc", "expires_in": 120 }
```

The agent puts the nonce and the realm issuer as `aud` in its Key Binding JWT. Then it exchanges the dSD-JWT+KB:

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

The exchange returns no refresh token and no ID token. The token never outlives the chain.

## Calling the API

The API validates the access token with the realm JWKS. It checks `iss`, `aud`, `exp` and the roles. Introspection reports these tokens as inactive, because Keycloak keeps no session for them (ADR 0007). The token is a plain bearer token.

## Test vectors

`tools/vectorgen` writes the chains in `src/test/resources/vectors` with the eudi-dev Go library. It needs eudi-dev 3.11.0 or later. The Java tests check the same bytes, so both implementations agree.

```sh
cd tools/vectorgen && go run . -out ../../src/test/resources/vectors
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
