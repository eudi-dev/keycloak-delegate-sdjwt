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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.models.IdentityProviderModel;

class DelegateSdJwtIdentityProviderConfigTest {

    private static final String JWKS = """
            {"https://register.example": {"keys": [{"kty": "EC", "crv": "P-256", "kid": "register",
              "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
              "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}}""";

    @Test
    void validConfigUsesDefaults() {
        DelegateSdJwtIdentityProviderConfig config = config(Map.of());

        config.validate(null);

        assertEquals(Set.of("procurement-agent"), config.getClients());
        assertEquals("mandate.actions", config.getActionsPath().toString());
        assertEquals("agent.id", config.getAgentIdPath().toString());
        assertNull(config.getAudiencePath());
    }

    @Test
    void refusesConfigWithoutClients() {
        assertRefused(Map.of("clients", " , "), "clients must list at least 1 client");
    }

    @Test
    void refusesConfigWithoutTrust() {
        Map<String, String> values = new HashMap<>();
        values.put("trustedIssuerJwks", null);
        assertRefused(values, "set trustMaterialIdps or trustedIssuerJwks to trust a credential issuer");
    }

    @Test
    void refusesItselfAsTrustMaterial() {
        DelegateSdJwtIdentityProviderConfig config = config(Map.of("trustMaterialIdps", "register-trust, delegation"));
        Map<String, IdentityProviderModel> providers = Map.of("register-trust", x509Trust("register-trust"));

        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> config.checkTrustMaterial(providers::get));

        assertEquals(
                "trustMaterialIdps must not list the Delegate SD-JWT identity provider delegation", e.getMessage());
    }

    @Test
    void refusesAnotherDelegateSdJwtProviderAsTrustMaterial() {
        DelegateSdJwtIdentityProviderConfig config = config(Map.of("trustMaterialIdps", "register-trust, ledger"));
        Map<String, IdentityProviderModel> providers =
                Map.of("register-trust", x509Trust("register-trust"), "ledger", provider("ledger", "delegate-sd-jwt"));

        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> config.checkTrustMaterial(providers::get));

        assertEquals("trustMaterialIdps must not list the Delegate SD-JWT identity provider ledger", e.getMessage());
    }

    @Test
    void acceptsX509TrustMaterial() {
        DelegateSdJwtIdentityProviderConfig config = config(Map.of("trustMaterialIdps", "register-trust"));

        config.checkTrustMaterial(Map.of("register-trust", x509Trust("register-trust"))::get);
    }

    @Test
    void refusesTrustMaterialTogetherWithJwks() {
        assertRefused(
                Map.of("trustMaterialIdps", "register-trust"),
                "set either trustMaterialIdps or trustedIssuerJwks, not both");
    }

    @Test
    void refusesJwksThatDoNotMapIssuersToKeys() {
        for (String jwks :
                List.of("not json", "{\"keys\": []}", "[{\"keys\": []}]", "{\"https://register.example\": {}}")) {
            assertRefused(Map.of("trustedIssuerJwks", jwks), "trustedIssuerJwks must map each issuer to a JWK Set");
        }
    }

    @Test
    void refusesMissingPrincipalClaim() {
        assertRefused(Map.of("principalClaim", ""), "principalClaim is required");
    }

    @Test
    void refusesMissingCredentialActionsPath() {
        assertRefused(Map.of("credentialActionsPath", ""), "credentialActionsPath is required");
    }

    @Test
    void refusesMissingCredentialTypes() {
        assertRefused(Map.of("credentialTypes", " "), "credentialTypes must list at least 1 vct");
    }

    private static void assertRefused(Map<String, String> overrides, String message) {
        IllegalArgumentException e = assertThrows(
                IllegalArgumentException.class, () -> config(overrides).validate(null));
        assertEquals(message, e.getMessage());
    }

    private static IdentityProviderModel x509Trust(String alias) {
        IdentityProviderModel model = provider(alias, "default-trust");
        model.getConfig().put("useX509", "true");
        return model;
    }

    private static IdentityProviderModel provider(String alias, String providerId) {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias(alias);
        model.setProviderId(providerId);
        return model;
    }

    private static DelegateSdJwtIdentityProviderConfig config(Map<String, String> overrides) {
        Map<String, String> values = new HashMap<>();
        values.put("clients", "procurement-agent");
        values.put("trustedIssuerJwks", JWKS);
        values.put("principalClaim", "euid_reference");
        values.put("credentialActionsPath", "authorisation.actions");
        values.put("credentialTypes", "urn:eudi-test:business:poa:1");
        values.putAll(overrides);
        values.values().removeIf(Objects::isNull);
        DelegateSdJwtIdentityProviderConfig config = new DelegateSdJwtIdentityProviderConfig();
        config.setAlias("delegation");
        config.setConfig(values);
        return config;
    }
}
