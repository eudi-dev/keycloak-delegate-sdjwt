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

package io.github.dominikschlosser.keycloak.dsdjwt.nonce;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class NonceResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "delegate-sd-jwt";
    public static final String LIFESPAN = "nonceLifespan";
    public static final long DEFAULT_LIFESPAN = 120;

    private long lifespanSeconds = DEFAULT_LIFESPAN;

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new NonceResource(session, lifespanSeconds);
    }

    @Override
    public void init(Config.Scope config) {
        lifespanSeconds = config.getLong(LIFESPAN, DEFAULT_LIFESPAN);
        if (lifespanSeconds <= 0) {
            throw new IllegalArgumentException(LIFESPAN + " must be positive");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(LIFESPAN)
                .type(ProviderConfigProperty.INTEGER_TYPE)
                .helpText("Seconds a nonce for the Key Binding JWT stays valid.")
                .defaultValue(DEFAULT_LIFESPAN)
                .add()
                .build();
    }
}
