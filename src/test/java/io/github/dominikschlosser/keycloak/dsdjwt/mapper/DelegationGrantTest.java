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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.dominikschlosser.keycloak.dsdjwt.ConfigurationException;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

class DelegationGrantTest {

    @ParameterizedTest
    @ValueSource(strings = {"sub", "act", "exp", "preferred_username", "azp", "acme_tenant.id"})
    void refusesClaimTheTokenHolds(String claim) {
        DelegationGrant grant = new DelegationGrant();
        grant.addClaim("limit", "limit", "5000.00");
        grant.addClaim("spoof", claim, "urn:eudi-test:agent:bolt");
        AccessToken token = token();

        ConfigurationException e = assertThrows(ConfigurationException.class, () -> grant.applyClaims(token));

        assertEquals("mapper spoof must not set the claim " + claim.split("\\.")[0] + " of the token", e.getMessage());
        assertFalse(token.getOtherClaims().containsKey("limit"));
    }

    @Test
    void nestsClaimsOfSeveralMappersUnderOneName() {
        DelegationGrant grant = new DelegationGrant();
        grant.addClaim("amount", "mandate.max_amount", 5000);
        grant.addClaim("currency", "mandate.currency", "EUR");
        AccessToken token = token();

        grant.applyClaims(token);

        assertEquals(
                Map.of("max_amount", 5000, "currency", "EUR"),
                token.getOtherClaims().get("mandate"));
    }

    @Test
    void refusesTwoMappersForOneClaim() {
        DelegationGrant grant = new DelegationGrant();
        grant.addClaim("first", "limit", "EUR");

        ConfigurationException e =
                assertThrows(ConfigurationException.class, () -> grant.addClaim("second", "limit", "USD"));

        assertEquals("mapper second sets the claim limit, which mapper first sets too", e.getMessage());
        AccessToken token = token();
        grant.applyClaims(token);
        assertEquals("EUR", token.getOtherClaims().get("limit"));
    }

    private static AccessToken token() {
        AccessToken token = new AccessToken();
        token.issuer("https://idp.example/realms/demo");
        token.subject("8f14e45f-ceea-367a-9a36-dedd4bea2543");
        token.exp(1_800_000_000L);
        token.issuedFor("procurement-agent");
        token.setPreferredUsername("deacme.hrb4711");
        token.getOtherClaims().put(IDToken.ACT, Map.of("sub", "urn:eudi-test:agent:procurement-1"));
        token.getOtherClaims().put("acme_tenant", Map.of("region", "eu"));
        return token;
    }
}
