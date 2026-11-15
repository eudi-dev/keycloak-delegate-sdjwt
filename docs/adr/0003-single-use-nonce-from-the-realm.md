# A single use nonce from the realm

The Key Binding JWT must carry a nonce issued by Keycloak. A captured dSD-JWT+KB then works only once.

A client gets a nonce with `POST /realms/{realm}/delegate-sd-jwt/nonce`. The endpoint authenticates the client like the token endpoint and refuses public clients. The response has `Cache-Control: no-store`.

The nonce is 32 random bytes in base64url. Keycloak keeps it in its single use object store for 120 seconds by default. The option `--spi-realm-restapi-extension--delegate-sd-jwt--nonce-lifespan` changes the lifespan.

The store keys each nonce by realm, client and value. The exchange fails for an unknown, expired or used nonce, and for a nonce of another client. A request from another client leaves the nonce in the store, so its own client can still use it.

The `aud` of the Key Binding JWT must be the realm issuer.

## Consequences

The single use object store is shared across a Keycloak cluster. A nonce works once even with several nodes.

The exchange removes the nonce after the chain is verified and the delegation is read. The status check and the mappers run after that. If one of them fails, the agent needs a new nonce.
