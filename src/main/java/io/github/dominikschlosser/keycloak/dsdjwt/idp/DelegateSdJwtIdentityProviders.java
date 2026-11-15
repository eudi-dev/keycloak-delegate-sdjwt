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

import io.github.dominikschlosser.keycloak.dsdjwt.ConfigurationException;
import java.util.List;
import java.util.Optional;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderQuery;
import org.keycloak.models.KeycloakSession;

/** Finds the Delegate SD-JWT identity provider of a client. */
public final class DelegateSdJwtIdentityProviders {

    private DelegateSdJwtIdentityProviders() {}

    /**
     * Returns the enabled identity provider that lists the client, or empty when none does.
     *
     * @throws ConfigurationException when more than 1 lists the client
     */
    public static Optional<DelegateSdJwtIdentityProviderConfig> forClient(KeycloakSession session, ClientModel client) {
        List<DelegateSdJwtIdentityProviderConfig> matches = session.identityProviders()
                .getAllStream(IdentityProviderQuery.any())
                .filter(model -> DelegateSdJwtIdentityProviderFactory.PROVIDER_ID.equals(model.getProviderId()))
                .filter(model -> model.isEnabled())
                .map(DelegateSdJwtIdentityProviderConfig::new)
                .filter(config -> config.getClients().contains(client.getClientId()))
                .toList();
        if (matches.size() > 1) {
            throw new ConfigurationException("the identity providers "
                    + matches.stream()
                            .map(DelegateSdJwtIdentityProviderConfig::getAlias)
                            .toList()
                    + " all list the client " + client.getClientId());
        }
        return matches.stream().findFirst();
    }
}
