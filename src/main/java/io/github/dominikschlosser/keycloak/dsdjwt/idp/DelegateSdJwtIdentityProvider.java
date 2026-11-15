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

import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;
import org.keycloak.broker.provider.TrustMaterialIdentityProvider;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.broker.provider.TrustMaterialResolver;
import org.keycloak.broker.provider.X509TrustMaterial;
import org.keycloak.broker.trust.TrustKeyUtil;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.IdentityBrokerService;

/**
 * Holds the settings and the issuer trust of a Delegate SD-JWT exchange. Keycloak lists it as
 * trust material, so it never appears on the login page.
 */
public class DelegateSdJwtIdentityProvider
        implements TrustMaterialIdentityProvider<DelegateSdJwtIdentityProviderConfig> {

    private final KeycloakSession session;
    private final DelegateSdJwtIdentityProviderConfig config;

    public DelegateSdJwtIdentityProvider(KeycloakSession session, DelegateSdJwtIdentityProviderConfig config) {
        this.session = session;
        this.config = config;
    }

    @Override
    public DelegateSdJwtIdentityProviderConfig getConfig() {
        return config;
    }

    @Override
    public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
        if (!config.getTrustMaterialAliases().isEmpty()) {
            return config.getTrustMaterialAliases().stream()
                    .map(alias -> issuerTrustMaterial(alias, request.getIssuer()))
                    .flatMap(Optional::stream)
                    .flatMap(provider -> provider.resolveKeys(request));
        }
        String jwks = config.getTrustedIssuerJwks();
        if (jwks == null || jwks.isBlank()) {
            return Stream.empty();
        }
        JSONWebKeySet issuerKeys =
                DelegateSdJwtIdentityProviderConfig.parseIssuerJwks(jwks).get(request.getIssuer());
        if (issuerKeys == null) {
            return Stream.empty();
        }
        return TrustKeyUtil.filterKeys(Arrays.stream(issuerKeys.getKeys()), request);
    }

    /**
     * Returns the trust material identity provider only when its issuer setting names this issuer.
     * draft-ietf-oauth-sd-jwt-vc-19 §2.5 requires that the key belongs to the Issuer, and a plain
     * JWK Set says nothing about whose keys it holds.
     */
    private Optional<TrustMaterialIdentityProvider<?>> issuerTrustMaterial(String alias, String issuer) {
        IdentityProviderModel model = session.identityProviders().getByAlias(alias);
        if (model == null
                || !model.isEnabled()
                || issuer == null
                || !issuer.equals(model.getConfig().get(IdentityProviderModel.ISSUER))) {
            return Optional.empty();
        }
        return Optional.ofNullable(
                IdentityBrokerService.getIdentityProvider(session, model, TrustMaterialIdentityProvider.class));
    }

    @Override
    public Stream<X509TrustMaterial> resolveX509Trust(TrustMaterialRequest request) {
        return new TrustMaterialResolver()
                .resolveX509Trust(session, String.join(",", config.getTrustMaterialAliases()), request);
    }

    @Override
    public void close() {}
}
