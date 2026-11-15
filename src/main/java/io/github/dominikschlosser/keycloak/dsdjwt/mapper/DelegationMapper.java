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

import io.github.dominikschlosser.keycloak.dsdjwt.ConfigurationException;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import io.github.dominikschlosser.keycloak.dsdjwt.delegation.Delegation;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/** An identity provider mapper that turns part of a delegation into roles or claims. */
public interface DelegationMapper {

    /**
     * Adds what this mapper grants for the delegation.
     *
     * @throws ChainException when the delegation cannot be mapped, for example when its links disagree
     * @throws ConfigurationException when the mapper config cannot work
     */
    void map(
            KeycloakSession session,
            RealmModel realm,
            IdentityProviderMapperModel mapperModel,
            Delegation delegation,
            DelegationGrant grant)
            throws ChainException;
}
