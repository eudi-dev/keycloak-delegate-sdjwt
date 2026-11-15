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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dominikschlosser.keycloak.dsdjwt.ConfigurationException;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import io.github.dominikschlosser.keycloak.dsdjwt.delegation.Delegation;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.AccessToken;

class ClaimMapperTest {

    private static final String PAYLOAD = """
            {"mandate": {"limit": {"amount": 2500, "currency": "EUR"},
                         "suppliers": ["Bolt Supplies B.V."]}}""";

    private final ClaimMapper mapper = new ClaimMapper();

    @Test
    void mapsScalarAsScalar() throws Exception {
        AccessToken token = map(Map.of("source", "mandate.limit.currency", "claim.name", "limit_currency"), PAYLOAD);

        assertEquals("EUR", token.getOtherClaims().get("limit_currency"));
    }

    @Test
    void mapsNumberObjectAndListWithTheirJsonShape() throws Exception {
        AccessToken amount = map(Map.of("source", "mandate.limit.amount", "claim.name", "limit_amount"), PAYLOAD);
        AccessToken limit = map(Map.of("source", "mandate.limit", "claim.name", "limit"), PAYLOAD);
        AccessToken suppliers = map(Map.of("source", "mandate.suppliers", "claim.name", "suppliers"), PAYLOAD);

        assertEquals(2500, amount.getOtherClaims().get("limit_amount"));
        assertEquals(
                Map.of("amount", 2500, "currency", "EUR"),
                limit.getOtherClaims().get("limit"));
        assertEquals(List.of("Bolt Supplies B.V."), suppliers.getOtherClaims().get("suppliers"));
    }

    @Test
    void nestsClaimAtDottedName() throws Exception {
        AccessToken token = map(Map.of("source", "mandate.limit.amount", "claim.name", "mandate.max_amount"), PAYLOAD);

        assertEquals(Map.of("max_amount", 2500), token.getOtherClaims().get("mandate"));
    }

    @Test
    void skipsAbsentAndNullValues() throws Exception {
        DelegationGrant grant = new DelegationGrant();
        mapper.map(
                null,
                null,
                mapper("absent", Map.of("source", "mandate.budget", "claim.name", "budget")),
                delegation(Set.of(), PAYLOAD),
                grant);
        mapper.map(
                null,
                null,
                mapper("null", Map.of("source", "mandate.note", "claim.name", "note")),
                delegation(Set.of(), "{\"mandate\": {\"note\": null}}"),
                grant);

        AccessToken token = new AccessToken();
        grant.applyClaims(token);
        assertTrue(token.getOtherClaims().isEmpty());
    }

    @Test
    void refusesARequiredValueThatTheFirstDelegatePayloadLacks() throws Exception {
        ChainException e = assertThrows(
                ChainException.class,
                () -> mapper.map(
                        null,
                        null,
                        mapper(
                                "budget",
                                Map.of("source", "mandate.budget", "claim.name", "budget", "required", "true")),
                        delegation(Set.of(), PAYLOAD),
                        new DelegationGrant()));

        assertEquals("the first Delegate Payload has no mandate.budget, which mapper budget requires", e.getMessage());
    }

    @Test
    void refusesARequiredValueThatIsOnlyPartlyDisclosed() throws Exception {
        ChainException e = assertThrows(
                ChainException.class,
                () -> mapper.map(
                        null,
                        null,
                        mapper("limit", Map.of("source", "mandate.limit", "claim.name", "limit", "required", "true")),
                        delegation(Set.of(), Set.of(List.of("mandate", "limit")), PAYLOAD),
                        new DelegationGrant()));

        assertEquals("the first Delegate Payload has no mandate.limit, which mapper limit requires", e.getMessage());
    }

    @Test
    void mapsARequiredValueBesideAWithheldDisclosure() throws Exception {
        DelegationGrant grant = new DelegationGrant();
        mapper.map(
                null,
                null,
                mapper(
                        "currency",
                        Map.of("source", "mandate.limit.currency", "claim.name", "currency", "required", "true")),
                delegation(Set.of(), Set.of(List.of("mandate", "limit")), PAYLOAD),
                grant);

        AccessToken token = new AccessToken();
        grant.applyClaims(token);
        assertEquals("EUR", token.getOtherClaims().get("currency"));
    }

    @Test
    void mapsARequiredValue() throws Exception {
        AccessToken token = map(
                Map.of("source", "mandate.limit.currency", "claim.name", "limit_currency", "required", "true"),
                PAYLOAD);

        assertEquals("EUR", token.getOtherClaims().get("limit_currency"));
    }

    @Test
    void refusesLinksThatDisagree() throws Exception {
        Delegation delegation = delegation(
                Set.of(),
                "{\"mandate\": {\"limit\": {\"currency\": \"EUR\"}}}",
                "{\"mandate\": {\"limit\": {\"currency\": \"USD\"}}}");

        ChainException e = assertThrows(
                ChainException.class,
                () -> mapper.map(
                        null,
                        null,
                        mapper("currency", Map.of("source", "mandate.limit.currency", "claim.name", "currency")),
                        delegation,
                        new DelegationGrant()));
        assertEquals(
                "the Delegate Payload of KB-SD-JWT 2 has another value for mandate.limit.currency than the first link",
                e.getMessage());
    }

    @Test
    void refusesMissingClaimName() {
        assertThrows(
                ConfigurationException.class, () -> ClaimMapper.claimName(mapper("unnamed", Map.of("source", "a"))));
    }

    @Test
    void refusesInvalidSourcePath() {
        assertThrows(
                ConfigurationException.class,
                () -> mapper.map(
                        null,
                        null,
                        mapper("bad", Map.of("source", "", "claim.name", "x")),
                        delegation(Set.of(), PAYLOAD),
                        new DelegationGrant()));
    }

    private AccessToken map(Map<String, String> config, String payload) throws Exception {
        DelegationGrant grant = new DelegationGrant();
        mapper.map(null, null, mapper("mapper", config), delegation(Set.of(), payload), grant);
        AccessToken token = new AccessToken();
        grant.applyClaims(token);
        return token;
    }
}
