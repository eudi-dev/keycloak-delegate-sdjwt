# A single use nonce from the realm

The Key Binding JWT must carry a nonce that Keycloak issued. This stops a captured dSD-JWT+KB from being exchanged a second time.

A client gets a nonce with `POST /realms/{realm}/delegate-sd-jwt/nonce`. The endpoint authenticates the client like the token endpoint. It refuses public clients.

The nonce is 32 random bytes in base64url. Keycloak keeps it in its single use object store for 120 seconds by default. The option `--spi-realm-restapi-extension--delegate-sd-jwt--nonce-lifespan` changes that. The response has `Cache-Control: no-store`.

The store keys each nonce by realm, client and value. The exchange removes the nonce from the store after the chain checks pass. If the nonce is unknown, expired, already used or issued to another client, the exchange fails. A request from another client never touches the nonce, so its owner can still use it.

The `aud` of the Key Binding JWT must equal the realm issuer.

## Consequences

The single use object store is shared across a Keycloak cluster, so a nonce works once even with several nodes.

The exchange uses up the nonce once the chain verifies and its delegation is read, so a check that fails after that needs a new nonce.
