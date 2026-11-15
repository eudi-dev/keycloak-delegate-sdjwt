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

import static io.github.dominikschlosser.keycloak.dsdjwt.idp.DelegateSdJwtIdentityProviderConfig.*;

import java.util.List;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class DelegateSdJwtIdentityProviderFactory
        extends AbstractIdentityProviderFactory<DelegateSdJwtIdentityProvider> {

    public static final String PROVIDER_ID = "delegate-sd-jwt";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(CLIENTS)
            .label("Clients")
            .helpText("Comma separated client IDs that may exchange a Delegate SD-JWT with these settings.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .required(true)
            .add()
            .property()
            .name(TRUST_MATERIAL_IDPS)
            .label("Trust Material Identity Providers")
            .helpText("Comma separated aliases of trust material identity providers with the trusted credential"
                    + " issuer keys or X.509 trust anchors. Set this or the trusted issuer JWKS, not both.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(TRUSTED_ISSUER_JWKS)
            .label("Trusted Issuer JWKS")
            .helpText("JSON object that maps each trusted credential issuer to the JWK Set with its keys, for"
                    + " example {\"https://issuer.example\": {\"keys\": [...]}}.")
            .type(ProviderConfigProperty.TEXT_TYPE)
            .add()
            .property()
            .name(PRINCIPAL_CLAIM)
            .label("Principal Claim")
            .helpText("Path of the credential claim with the organisation or holder, for example euid_reference.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .required(true)
            .add()
            .property()
            .name(CREDENTIAL_ACTIONS_PATH)
            .label("Credential Actions Path")
            .helpText("Path of the action list in the credential. The first Delegate Payload may allow only these"
                    + " actions.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .required(true)
            .add()
            .property()
            .name(ACTIONS_PATH)
            .label("Actions Path")
            .helpText("Path of the action list in a Delegate Payload.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(DEFAULT_ACTIONS_PATH)
            .add()
            .property()
            .name(AGENT_ID_PATH)
            .label("Agent ID Path")
            .helpText("Path of the agent identifier in a Delegate Payload. Without it the act claim holds the"
                    + " JWK thumbprint URI of the agent key.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .defaultValue(DEFAULT_AGENT_ID_PATH)
            .add()
            .property()
            .name(AUDIENCE_PATH)
            .label("Audience Path")
            .helpText("Path of a list in every Delegate Payload that must contain the realm issuer. Empty skips"
                    + " this check.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(CREDENTIAL_TYPES)
            .label("Credential Types")
            .helpText("Comma separated vct values the credential may have.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .required(true)
            .add()
            .build();

    @Override
    public String getName() {
        return "Delegate SD-JWT";
    }

    @Override
    public DelegateSdJwtIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new DelegateSdJwtIdentityProvider(session, new DelegateSdJwtIdentityProviderConfig(model));
    }

    @Override
    public DelegateSdJwtIdentityProviderConfig createConfig() {
        return new DelegateSdJwtIdentityProviderConfig();
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
        return "Settings and issuer trust for exchanging a Delegate SD-JWT at the token endpoint.";
    }
}
