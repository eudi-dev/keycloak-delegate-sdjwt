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

import static io.github.dominikschlosser.keycloak.dsdjwt.Stubs.stub;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.provider.TrustMaterialIdentityProvider;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderStorageProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.util.JsonSerialization;

class DelegateSdJwtIdentityProviderTest {

    private static final String ACME = "https://register.acme.example";
    private static final String BOLT = "https://register.bolt.example";
    private static final String STUB_TRUST = "stub-trust";

    private static KeyWrapper acmeKey;
    private static KeyWrapper boltKey;
    private static DelegateSdJwtIdentityProvider provider;

    @BeforeAll
    static void trustTwoIssuers() throws Exception {
        CryptoIntegration.init(DelegateSdJwtIdentityProviderTest.class.getClassLoader());
        acmeKey = ChainBuilder.ecKey();
        boltKey = ChainBuilder.ecKey();
        DelegateSdJwtIdentityProviderConfig config = new DelegateSdJwtIdentityProviderConfig();
        config.setAlias("delegation");
        config.setConfig(Map.of(
                "trustedIssuerJwks",
                JsonSerialization.writeValueAsString(Map.of(
                        ACME, Map.of("keys", List.of(ChainBuilder.publicJwk(acmeKey))),
                        BOLT, Map.of("keys", List.of(ChainBuilder.publicJwk(boltKey)))))));
        provider = new DelegateSdJwtIdentityProvider(null, config);
    }

    @Test
    void resolvesOnlyTheKeysOfTheCredentialIssuer() {
        assertEquals(List.of(x(acmeKey)), keys(ACME));
        assertEquals(List.of(x(boltKey)), keys(BOLT));
    }

    @Test
    void resolvesNoKeysForAnUnknownOrMissingIssuer() {
        assertEquals(List.of(), keys("https://register.crate.example"));
        assertEquals(List.of(), keys(null));
    }

    @Test
    void resolvesTrustMaterialKeysOnlyFromAnIdentityProviderWhoseIssuerIsTheCredentialIssuer() {
        Map<String, IdentityProviderModel> models = Map.of(
                "acme-trust", trustModel("acme-trust", ACME, true),
                "bolt-trust", trustModel("bolt-trust", null, true),
                "crate-trust", trustModel("crate-trust", "https://register.crate.example", false));
        Map<String, KeyWrapper> trustKeys = Map.of("acme-trust", acmeKey, "bolt-trust", boltKey);
        DelegateSdJwtIdentityProviderConfig config = new DelegateSdJwtIdentityProviderConfig();
        config.setAlias("delegation");
        config.setConfig(Map.of("trustMaterialIdps", "acme-trust,bolt-trust,crate-trust"));
        DelegateSdJwtIdentityProvider trustMaterial =
                new DelegateSdJwtIdentityProvider(session(models, trustKeys), config);

        assertEquals(List.of(x(acmeKey)), keys(trustMaterial, ACME));
        assertEquals(List.of(), keys(trustMaterial, BOLT));
        assertEquals(List.of(), keys(trustMaterial, "https://register.crate.example"));
    }

    private static IdentityProviderModel trustModel(String alias, String issuer, boolean enabled) {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias(alias);
        model.setProviderId(STUB_TRUST);
        model.setEnabled(enabled);
        if (issuer != null) {
            model.getConfig().put(IdentityProviderModel.ISSUER, issuer);
        }
        return model;
    }

    /** A session whose trust material identity providers each serve 1 fixed key. */
    private static KeycloakSession session(
            Map<String, IdentityProviderModel> models, Map<String, KeyWrapper> trustKeys) {
        IdentityProviderStorageProvider storage = stub(IdentityProviderStorageProvider.class, (method, args) -> {
            if (method.equals("getByAlias")) {
                return models.get((String) args[0]);
            }
            throw new UnsupportedOperationException(method);
        });
        IdentityProviderFactory<?> factory = stub(IdentityProviderFactory.class, (method, args) -> switch (method) {
            case "getId" -> STUB_TRUST;
            case "create" -> {
                KeyWrapper key = trustKeys.get(((IdentityProviderModel) args[1]).getAlias());
                yield stub(TrustMaterialIdentityProvider.class, (inner, innerArgs) -> {
                    if (inner.equals("resolveKeys")) {
                        return Stream.ofNullable(key).map(ChainBuilder::publicJwk);
                    }
                    throw new UnsupportedOperationException(inner);
                });
            }
            default -> throw new UnsupportedOperationException(method);
        });
        KeycloakSessionFactory sessionFactory = stub(KeycloakSessionFactory.class, (method, args) -> {
            if (method.equals("getProviderFactoriesStream")) {
                return args[0] == IdentityProvider.class ? Stream.of(factory) : Stream.empty();
            }
            throw new UnsupportedOperationException(method);
        });
        return stub(KeycloakSession.class, (method, args) -> switch (method) {
            case "identityProviders" -> storage;
            case "getKeycloakSessionFactory" -> sessionFactory;
            default -> throw new UnsupportedOperationException(method);
        });
    }

    private static List<String> keys(String issuer) {
        return keys(provider, issuer);
    }

    private static List<String> keys(DelegateSdJwtIdentityProvider provider, String issuer) {
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
