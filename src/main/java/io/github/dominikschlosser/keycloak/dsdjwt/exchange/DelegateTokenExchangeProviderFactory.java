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

package io.github.dominikschlosser.keycloak.dsdjwt.exchange;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

public class DelegateTokenExchangeProviderFactory
        implements TokenExchangeProviderFactory, EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "delegate-sd-jwt";

    @Override
    public TokenExchangeProvider create(KeycloakSession session) {
        return new DelegateTokenExchangeProvider();
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /** The principal becomes a lightweight user, which needs the transient users feature. */
    @Override
    public boolean isSupported(Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE_STANDARD_V2)
                && Profile.isFeatureEnabled(Profile.Feature.TRANSIENT_USERS);
    }

    /**
     * Keycloak asks the factories with the highest order first. This one has 20 and standard token
     * exchange has 10, so this one sees the Delegate SD-JWT token type first.
     */
    @Override
    public int order() {
        return 20;
    }
}
