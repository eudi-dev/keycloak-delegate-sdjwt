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

import static io.github.dominikschlosser.keycloak.dsdjwt.mapper.MapperTestSupport.delegation;
import static io.github.dominikschlosser.keycloak.dsdjwt.mapper.MapperTestSupport.mapper;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dominikschlosser.keycloak.dsdjwt.ConfigurationException;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ActionRoleMapperTest {

    private final ActionRoleMapper mapper = new ActionRoleMapper();

    @Test
    void grantsNothingForActionOutsideDelegation() throws Exception {
        DelegationGrant grant = new DelegationGrant();

        mapper.map(
                null,
                null,
                mapper("pay", Map.of("action", "invoice:pay", "role", "invoice-payer")),
                delegation(Set.of("order:create"), "{}"),
                grant);

        assertTrue(grant.roles().isEmpty());
    }

    @Test
    void refusesMapperWithoutAction() {
        assertThrows(
                ConfigurationException.class,
                () -> mapper.map(
                        null,
                        null,
                        mapper("pay", Map.of("role", "invoice-payer")),
                        delegation(Set.of("invoice:pay"), "{}"),
                        new DelegationGrant()));
    }
}
