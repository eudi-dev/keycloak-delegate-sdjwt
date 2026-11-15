/*
 * Copyright 2026 Dominik Schlosser
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.dominikschlosser.keycloak.dsdjwt.delegation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.JwkVerifiers;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.VerifiedChain;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.VerifiedLink;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Reads the principal, the actions and the agents of a verified chain. */
public final class DelegationReader {

    private final Settings settings;

    /**
     * @param principal where the credential holds the principal
     * @param credentialActions where the credential lists the actions its holder may delegate
     * @param actions where a Delegate Payload lists its actions
     * @param agentId where a Delegate Payload holds the agent identifier
     * @param audiences where a Delegate Payload lists the services it may be used at, or null
     * @param credentialTypes the accepted vct values of the credential
     * @param delegateTypes the accepted vct values of a Delegate Payload, empty for any
     * @param realmIssuer the issuer of the realm that runs the exchange
     */
    public record Settings(
            ClaimPath principal,
            ClaimPath credentialActions,
            ClaimPath actions,
            ClaimPath agentId,
            ClaimPath audiences,
            Set<String> credentialTypes,
            Set<String> delegateTypes,
            String realmIssuer) {}

    public DelegationReader(Settings settings) {
        this.settings = settings;
    }

    public Delegation read(VerifiedChain chain) throws ChainException {
        ObjectNode credential = chain.credential();
        checkType(credential, settings.credentialTypes(), "the credential");
        String principal = settings.principal()
                .find(credential)
                .filter(JsonNode::isTextual)
                .map(JsonNode::textValue)
                .filter(value -> !value.isBlank())
                .orElseThrow(() -> new ChainException(
                        "the credential has no text claim " + settings.principal() + " for the principal"));

        // The holder can delegate only the actions its credential allows. An absent list allows none.
        Set<String> actions = strings(credential, settings.credentialActions(), "the credential");
        List<ObjectNode> payloads = new ArrayList<>();
        Map<String, Object> actor = null;
        for (int i = 0; i < chain.links().size(); i++) {
            VerifiedLink link = chain.links().get(i);
            ObjectNode payload = link.delegatePayload();
            String label = "the Delegate Payload of KB-SD-JWT " + (i + 1);
            checkType(payload, settings.delegateTypes(), label);
            checkAudience(payload, label);
            Set<String> allowed = strings(payload, settings.actions(), label);
            // A link can only narrow what the credential and the links before it allow.
            actions.retainAll(allowed);
            Map<String, Object> act = new LinkedHashMap<>();
            act.put("sub", agentId(link, label));
            if (actor != null) {
                act.put("act", actor);
            }
            actor = act;
            payloads.add(payload);
        }
        // ChainVerifier refuses a credential without an iss string.
        String issuer = credential.get("iss").textValue();
        return new Delegation(issuer, principal, actions, actor, payloads, chain.firstWithheld(), chain.expiresAt());
    }

    private String agentId(VerifiedLink link, String label) throws ChainException {
        Optional<JsonNode> id = settings.agentId().find(link.delegatePayload());
        if (id.isEmpty()) {
            return JwkVerifiers.thumbprintUri(link.delegateKey());
        }
        if (!id.get().isTextual() || id.get().textValue().isBlank()) {
            throw new ChainException(label + " has a " + settings.agentId() + " that is not a text");
        }
        return id.get().textValue();
    }

    private void checkAudience(ObjectNode payload, String label) throws ChainException {
        if (settings.audiences() == null) {
            return;
        }
        if (!strings(payload, settings.audiences(), label).contains(settings.realmIssuer())) {
            throw new ChainException(
                    label + " does not list " + settings.realmIssuer() + " in " + settings.audiences());
        }
    }

    private static void checkType(ObjectNode claims, Set<String> accepted, String label) throws ChainException {
        if (accepted.isEmpty()) {
            return;
        }
        JsonNode vct = claims.get("vct");
        if (vct == null || !vct.isTextual() || !accepted.contains(vct.textValue())) {
            throw new ChainException(label + " has vct " + vct + ", which is not accepted");
        }
    }

    /** Reads a text or an array of texts. An absent claim gives an empty set. */
    private static Set<String> strings(ObjectNode claims, ClaimPath path, String label) throws ChainException {
        Optional<JsonNode> value = path.find(claims);
        Set<String> result = new LinkedHashSet<>();
        if (value.isEmpty()) {
            return result;
        }
        if (value.get().isTextual()) {
            result.add(value.get().textValue());
            return result;
        }
        if (!value.get().isArray()) {
            throw new ChainException(label + " has a " + path + " that is neither a text nor an array");
        }
        for (JsonNode element : value.get()) {
            if (!element.isTextual()) {
                throw new ChainException(label + " has a " + path + " with an element that is not a text");
            }
            result.add(element.textValue());
        }
        return result;
    }
}
