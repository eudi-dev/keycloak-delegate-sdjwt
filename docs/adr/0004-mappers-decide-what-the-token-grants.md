# Mappers decide what the token grants

The realm admin decides what a delegation is worth. Identity provider mappers of the Delegate SD-JWT identity provider turn the delegation into roles and claims. The chain itself grants nothing.

The action role mapper grants 1 realm or client role when the delegation allows its action. An action that no mapper knows grants nothing. If a delegation grants no role at all, the exchange fails.

The actions of a chain are those that the credential and every Delegate Payload allow. The setting `credentialActionsPath` holds the path of the action list in the credential. A credential without that list allows no action. So the first agent can only pass on what the credential holder may do, and a later agent can narrow what an earlier agent passed on but never widen it.

The setting `credentialTypes` is required. Only credentials of the listed types can start a chain, so another credential from a trusted issuer cannot stand in for a power of attorney.

The claim mapper copies a value from the first Delegate Payload into an access token claim. A later link may leave the value out or repeat it. If a later link changes the value or adds one, the exchange fails. So a later agent can neither raise a limit an earlier agent set nor add one that is missing. The first delegator sets the value, and the credential does not limit it. The value keeps its JSON type.

The claim mapper adds nothing when the first Delegate Payload lacks the value. With the setting `required`, the exchange fails instead. A Delegate Holder may leave out any selective disclosure of a Delegate Payload (draft-ietf-oauth-delegate-sd-jwt-00 §4.1). So a value that restricts the agent must be mapped as required, or the delegator must put it directly in the Delegate Payload.

A Disclosure can also sit inside the value, for example for the `amount` of `mandate.limit`. If the agent leaves it out, the value is still there but lacks a member. So a required value must also be disclosed whole. The chain verifier records each object and array of the first Delegate Payload that holds a digest without a presented Disclosure. A required mapper refuses a value that holds such an object or array, with the same error as for a missing value. RFC 9901 §4.2.5 decoy digests look the same, so a required value with a decoy inside is refused too.

## Consequences

A mapper must not set a claim that the token already holds, such as `sub`, `act`, `aud` or `azp`. The check runs on the finished token. A mapper must not add a claim with a protocol meaning either, even when the token lacks it. These are the registered JWT, OAuth and OpenID Connect claims such as `aud`, `client_id`, `scope`, `cnf` and `sid`, the OpenID Connect Core §5.1 claims such as `email` and `name` that describe the principal, and the Keycloak claims such as `realm_access` and `allowed-origins`. 2 mappers must not set the same claim. Such a setup gives a `server_error`.

A mapper may grant an admin role only when the identity provider allows admin role mapping. Otherwise the exchange gives a `server_error`.

Mappers of other types on the identity provider give a `server_error`, because they cannot read a delegation.

The protocol mappers and client scopes of the client don't apply to the token (ADR 0008). A hardcoded role mapper on the client adds no role.
