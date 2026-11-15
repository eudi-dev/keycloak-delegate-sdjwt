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

package io.github.dominikschlosser.keycloak.dsdjwt.idp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.util.JsonSerialization;

class DelegateSdJwtIdentityProviderTest {

    private static final String ACME = "https://register.acme.example";
    private static final String SUPPLIER = "https://register.supplier.example";

    private static KeyWrapper acmeKey;
    private static KeyWrapper supplierKey;
    private static DelegateSdJwtIdentityProvider provider;

    @BeforeAll
    static void trustTwoIssuers() throws Exception {
        CryptoIntegration.init(DelegateSdJwtIdentityProviderTest.class.getClassLoader());
        acmeKey = ChainBuilder.ecKey();
        supplierKey = ChainBuilder.ecKey();
        DelegateSdJwtIdentityProviderConfig config = new DelegateSdJwtIdentityProviderConfig();
        config.setAlias("delegation");
        config.setConfig(Map.of(
                "trustedIssuerJwks",
                JsonSerialization.writeValueAsString(Map.of(
                        ACME, Map.of("keys", List.of(ChainBuilder.publicJwk(acmeKey))),
                        SUPPLIER, Map.of("keys", List.of(ChainBuilder.publicJwk(supplierKey)))))));
        provider = new DelegateSdJwtIdentityProvider(null, config);
    }

    @Test
    void resolvesOnlyTheKeysOfTheCredentialIssuer() {
        assertEquals(List.of(x(acmeKey)), keys(ACME));
        assertEquals(List.of(x(supplierKey)), keys(SUPPLIER));
    }

    @Test
    void resolvesNoKeysForAnUnknownOrMissingIssuer() {
        assertEquals(List.of(), keys("https://register.crate.example"));
        assertEquals(List.of(), keys(null));
    }

    private static List<String> keys(String issuer) {
        TrustMaterialRequest request =
                TrustMaterialRequest.builder().algorithm("ES256").issuer(issuer).build();
        return provider.resolveKeys(request)
                .map(DelegateSdJwtIdentityProviderTest::x)
                .toList();
    }

    private static String x(KeyWrapper key) {
        return x(ChainBuilder.publicJwk(key));
    }

    private static String x(JWK jwk) {
        return JsonSerialization.mapper.valueToTree(jwk).get("x").asText();
    }
}
