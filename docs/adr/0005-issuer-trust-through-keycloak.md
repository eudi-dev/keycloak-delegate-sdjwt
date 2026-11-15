# Issuer trust through Keycloak

The extension trusts a credential issuer the same way as the OID4VP identity provider of Keycloak 26.8.2. In addition, the key that verifies a credential must belong to the issuer in its `iss`. The token `sub` is made from the `iss` (ADR 0002), so 1 trusted issuer must not sign for another.

A credential without `iss` is refused.

## Trust material identity providers

The setting `trustMaterialIdps` lists trust material identity providers, for example a Default Trust identity provider. A Delegate SD-JWT identity provider is refused as trust material. Otherwise the `trustedIssuerJwks` setting of another identity provider would decide the trusted issuers.

With X.509 trust anchors, the `x5c` chain in the credential header must validate against them (HAIP 1.0 §6.1.1). A CA such as a national register can certify many issuers, so the chain alone doesn't bind the `iss`. draft-ietf-oauth-sd-jwt-vc-19 §2.5 requires the key to belong to the issuer, but defines no comparison. The extension accepts the leaf certificate when one of these holds.

- A URI subject alternative name equals the `iss`.
- The `iss` is a bare https host and a DNS subject alternative name equals that host. A bare host has no port, query, fragment, user info or path other than `/`.

For example the `iss` `https://register.example` matches the URI `https://register.example` or the DNS name `register.example`. An `iss` with a path needs a URI match, because 2 issuers on the same host must not sign for each other. A trailing dot on a host is ignored.

Without X.509, a trust material identity provider supplies the keys of its JWKS. They count only for the issuer in its `issuer` setting, and only while it is enabled. A Default Trust identity provider has no `issuer` setting, so it must use X.509.

## Inline keys

The setting `trustedIssuerJwks` maps each issuer `iss` to its JWK Set. A key verifies only credentials of its own issuer. An identity provider sets either `trustMaterialIdps` or `trustedIssuerJwks`, never both.

## Consequences

Only the credential needs a trusted issuer. Each KB-SD-JWT is signed by the `cnf` key of the step before it (draft §6). The Key Binding JWT is signed by the `cnf` key of the last Delegate Payload.

The same trust checks the status list token, with the credential `iss` (ADR 0006).

An issuer certificate without a matching subject alternative name is refused, even when a trusted CA signed it. The status list signer certificate needs the same match.
