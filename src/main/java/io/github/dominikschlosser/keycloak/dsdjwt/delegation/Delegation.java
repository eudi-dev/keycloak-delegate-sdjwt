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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * What a verified chain grants to its last agent.
 *
 * @param issuer the iss claim of the credential
 * @param principal the organisation or holder the agents act for
 * @param actions the actions every Delegate Payload of the chain allows
 * @param actor the RFC 8693 §4.1 act claim, with the last agent outermost
 * @param delegatePayloads the Delegate Payloads in chain order
 * @param firstWithheld the paths in the first Delegate Payload of each object or array that holds a
 *     digest without a presented Disclosure
 * @param expiresAt the earliest expiry of the chain in seconds since the epoch
 */
public record Delegation(
        String issuer,
        String principal,
        Set<String> actions,
        Map<String, Object> actor,
        List<ObjectNode> delegatePayloads,
        Set<List<String>> firstWithheld,
        long expiresAt) {

    public Delegation {
        actions = Set.copyOf(actions);
        actor = Map.copyOf(actor);
        delegatePayloads = List.copyOf(delegatePayloads);
        firstWithheld = Set.copyOf(firstWithheld);
    }

    /** Whether the agent left out a Disclosure inside the value at this path of the first Delegate Payload. */
    public boolean partlyDisclosed(ClaimPath path) {
        return firstWithheld.stream().anyMatch(path::holds);
    }

    /**
     * Returns the value at this path of the first Delegate Payload. A later Delegate Payload may leave
     * the claim out or repeat the same value, so a later agent can neither change nor add what the first
     * link granted.
     */
    public Optional<JsonNode> claim(ClaimPath path) throws ChainException {
        Optional<JsonNode> first = path.find(delegatePayloads.get(0));
        for (int i = 1; i < delegatePayloads.size(); i++) {
            Optional<JsonNode> value = path.find(delegatePayloads.get(i));
            if (value.isPresent() && !value.equals(first)) {
                throw new ChainException("the Delegate Payload of KB-SD-JWT " + (i + 1) + " has another value for "
                        + path + " than the first link");
            }
        }
        return first;
    }
}
