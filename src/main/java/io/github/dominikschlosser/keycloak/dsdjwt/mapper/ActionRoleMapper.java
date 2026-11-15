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
import io.github.dominikschlosser.keycloak.dsdjwt.delegation.Delegation;
import io.github.dominikschlosser.keycloak.dsdjwt.idp.DelegateSdJwtIdentityProviderFactory;
import java.util.List;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.ConfigConstants;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/** Grants a role when every link of the chain allows an action. */
public class ActionRoleMapper extends AbstractIdentityProviderMapper implements DelegationMapper {

    public static final String PROVIDER_ID = "delegate-sd-jwt-action-role-mapper";
    public static final String ACTION = "action";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(ACTION)
            .label("Action")
            .helpText("Delegated action that grants the role, for example invoice:pay.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .required(true)
            .add()
            .property()
            .name(ConfigConstants.ROLE)
            .label("Role")
            .helpText("Role to grant. A client role has the form clientId.role.")
            .type(ProviderConfigProperty.ROLE_TYPE)
            .required(true)
            .add()
            .build();

    @Override
    public void map(
            KeycloakSession session,
            RealmModel realm,
            IdentityProviderMapperModel mapperModel,
            Delegation delegation,
            DelegationGrant grant) {
        String action = mapperModel.getConfig().get(ACTION);
        if (action == null || action.isBlank()) {
            throw new ConfigurationException("mapper " + mapperModel.getName() + " has no action");
        }
        if (!delegation.actions().contains(action.trim())) {
            return;
        }
        String roleName = mapperModel.getConfig().get(ConfigConstants.ROLE);
        RoleModel role = roleName == null ? null : KeycloakModelUtils.getRoleFromString(session, realm, roleName);
        if (role == null) {
            throw new ConfigurationException(
                    "mapper " + mapperModel.getName() + " grants the role " + roleName + ", which does not exist");
        }
        if (!isAdminRoleGrantAllowed(session, realm, role, mapperModel)) {
            throw new ConfigurationException("mapper " + mapperModel.getName() + " grants the admin role " + roleName
                    + ", but the identity provider does not allow admin role mapping");
        }
        grant.addRole(role);
    }

    @Override
    public String[] getCompatibleProviders() {
        return new String[] {DelegateSdJwtIdentityProviderFactory.PROVIDER_ID};
    }

    @Override
    public String getDisplayCategory() {
        return "Role Importer";
    }

    @Override
    public String getDisplayType() {
        return "Delegated Action to Role";
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return true;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getHelpText() {
        return "Grants a role to the access token when every Delegate Payload of the chain allows the action.";
    }
}
