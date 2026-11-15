# Mappers decide what the token grants

The chain itself grants nothing. The realm admin adds mappers to the Delegate SD-JWT identity provider. They turn the delegation into roles and claims.

## Actions and roles

The actions of a chain are those allowed by the credential and by every Delegate Payload. The setting `credentialActionsPath` holds the path of the action list in the credential. A credential without that list allows no action. So the first agent gets at most the actions of the credential. Each later agent gets at most the actions of the previous agent.

Only credentials with a `vct` from `credentialTypes` can start a chain. Another credential of a trusted issuer cannot replace the power of attorney.

The action role mapper grants 1 realm or client role when the chain allows its action. An action without a mapper grants nothing. If the chain grants no role at all, the exchange fails.

## Claims

The claim mapper copies a value of the first Delegate Payload into a token claim. The value keeps its JSON type. A later Delegate Payload may leave the value out or repeat it. A different value, or a value that the first Delegate Payload lacks, makes the exchange fail. So a later agent can't raise a limit or add a missing one. The credential does not restrict the value.

A Delegate Holder may leave out any Disclosure (draft-ietf-oauth-delegate-sd-jwt-00 §4.1). If the first Delegate Payload lacks the value, the claim mapper adds nothing. With `required`, the exchange fails instead. A value that restricts the agent must be required, or the delegator puts it in the Delegate Payload without a Disclosure.

A Disclosure can also sit inside the value, for example for the `amount` of `mandate.limit`. If the agent leaves it out, the value lacks that member. The chain verifier records each object and array of the first Delegate Payload with a digest that has no Disclosure. A required mapper refuses a value with such an object or array, with the same error as for a missing value. Decoy digests (RFC 9901 §4.2.5) look the same, so a decoy inside a required value is refused too.

## Consequences

A mapper must not set a claim that the finished token already holds, such as `sub`, `act` or `azp`. 2 mappers must not set the same claim. Both give `server_error`.

A mapper may grant an admin role only when the identity provider allows admin role mapping. Otherwise the exchange gives `server_error`.

Mappers of other types on the identity provider give `server_error`, because they can't read a delegation.

The protocol mappers and client scopes of the client don't apply to the token (ADR 0008).
