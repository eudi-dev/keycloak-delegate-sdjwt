# Issuer trust through Keycloak

The extension trusts a credential issuer the same way the OID4VP identity provider of Keycloak 26.8.2 does. On top of that, every key that verifies a credential must belong to the issuer that its `iss` names. The `sub` of the token is made from the `iss` (ADR 0002), so 1 trusted issuer must not be able to sign in the name of another.

A credential without `iss` is refused. draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 makes `iss` optional when an `x5c` certificate names the issuer. The `sub` is made from the `iss` (ADR 0002), so the extension refuses such a credential anyway.

The setting `trustMaterialIdps` lists trust material identity providers, for example a Default Trust identity provider. Another Delegate SD-JWT identity provider is no trust material, because its own `trustedIssuerJwks` would then decide which issuers this one trusts.

When they hold X.509 trust anchors, the `x5c` chain in the credential header must validate against them, as HAIP 1.0 §6.1.1 requires. A CA such as a national register can certify many issuers, so the chain alone does not bind the `iss`. draft-ietf-oauth-sd-jwt-vc-19 §2.5 says the subject of the leaf certificate is the issuer, and a key that cannot be bound to the issuer must be refused. It does not say how to compare them. The extension builds on the rule of draft-ietf-oauth-sd-jwt-vc-09 §3.5 and makes it stricter.

- A URI subject alternative name of the leaf equals the `iss`.
- Or the `iss` is a bare https host and a DNS name equals that host. A bare host has no port, path, query, fragment or user info. A single `/` as the path is allowed.

For example the `iss` `https://register.example` matches the URI name `https://register.example` or the DNS name `register.example`.

Draft 09 also accepts a DNS name for an `iss` with a path, but then the issuers `https://issue.example/acme` and `https://issue.example/bolt` on 1 host could sign for each other.

A trailing dot on the host or on the DNS name is ignored, because `register.example.` and `register.example` name the same host.

Without X.509, a trust material identity provider supplies keys from its JWKS. They count only for the issuer in the `issuer` setting of that identity provider. A disabled identity provider or one without `issuer` supplies no keys. A Default Trust identity provider has no `issuer` setting, so it must use X.509. The admin console refuses one without X.509 in `trustMaterialIdps`.

Without trust material identity providers, the setting `trustedIssuerJwks` holds the issuer keys inline. It maps each issuer `iss` to the JWK Set of that issuer. A key verifies only credentials whose `iss` it is listed under. An identity provider sets either `trustMaterialIdps` or `trustedIssuerJwks`, never both.

The trust that checks the credential also checks the status list token, with the `iss` of the credential (ADR 0006).

## Consequences

Only the credential needs a trusted issuer. Each KB-SD-JWT is signed by the `cnf` key of the step before it, as §6 of the draft describes, and the Key Binding JWT by the `cnf` key of the last Delegate Payload.

An issuer certificate without a subject alternative name for the `iss` is refused, also when a trusted CA signed it. The status list signer certificate needs the same name.
