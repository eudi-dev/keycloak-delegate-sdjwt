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

package io.github.dominikschlosser.keycloak.dsdjwt.mapper;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dominikschlosser.keycloak.dsdjwt.delegation.Delegation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.util.JsonSerialization;

final class MapperTestSupport {

    private MapperTestSupport() {}

    static IdentityProviderMapperModel mapper(String name, Map<String, String> config) {
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setName(name);
        model.setConfig(new HashMap<>(config));
        return model;
    }

    static Delegation delegation(Set<String> actions, String... payloads) throws Exception {
        return delegation(actions, Set.of(), payloads);
    }

    static Delegation delegation(Set<String> actions, Set<List<String>> firstWithheld, String... payloads)
            throws Exception {
        List<ObjectNode> nodes = new ArrayList<>();
        for (String payload : payloads) {
            nodes.add((ObjectNode) JsonSerialization.mapper.readTree(payload));
        }
        return new Delegation(
                "https://register.example",
                "DEACME.HRB4711",
                actions,
                Map.of("sub", "urn:eudi-test:agent:procurement-1"),
                nodes,
                firstWithheld,
                1794574900L);
    }
}
