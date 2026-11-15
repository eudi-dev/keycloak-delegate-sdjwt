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
import io.github.dominikschlosser.keycloak.dsdjwt.delegation.ClaimPath;
import io.github.dominikschlosser.keycloak.dsdjwt.delegation.Delegation;
import io.github.dominikschlosser.keycloak.dsdjwt.idp.DelegateSdJwtIdentityProviderFactory;
import java.util.List;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.JsonUtils;

/** Copies a value of the Delegate Payloads into a claim of the access token. */
public class ClaimMapper extends AbstractIdentityProviderMapper implements DelegationMapper {

    public static final String PROVIDER_ID = "delegate-sd-jwt-claim-mapper";
    public static final String SOURCE = "source";
    public static final String CLAIM = OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME;
    public static final String REQUIRED = "required";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
            .name(SOURCE)
            .label("Delegate Payload Path")
            .helpText("Dot separated path of the value in the Delegate Payloads, for example mandate.limit.amount.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .required(true)
            .add()
            .property()
            .name(CLAIM)
            .label("Token Claim Name")
            .helpText("Name of the access token claim. A dot nests the claim, as in protocol mappers.")
            .type(ProviderConfigProperty.STRING_TYPE)
            .required(true)
            .add()
            .property()
            .name(REQUIRED)
            .label("Required")
            .helpText("Refuse the exchange when the first Delegate Payload has no value at the path, or when the"
                    + " agent left out a Disclosure inside that value. Turn this on for a claim that restricts the"
                    + " agent, because the holder may leave any Disclosure out.")
            .type(ProviderConfigProperty.BOOLEAN_TYPE)
            .defaultValue(false)
            .add()
            .build();

    @Override
    public void map(
            KeycloakSession session,
            RealmModel realm,
            IdentityProviderMapperModel mapperModel,
            Delegation delegation,
            DelegationGrant grant)
            throws ChainException {
        String claim = claimName(mapperModel);
        ClaimPath source;
        try {
            source = ClaimPath.parse(mapperModel.getConfig().getOrDefault(SOURCE, ""));
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException("mapper " + mapperModel.getName() + ": " + e.getMessage(), e);
        }
        var value = delegation.claim(source);
        boolean required = Boolean.parseBoolean(mapperModel.getConfig().get(REQUIRED));
        // draft-ietf-oauth-delegate-sd-jwt-00 §4.1 lets the holder leave out any Disclosure, also one
        // inside the value, so a required value counts as present only when it is disclosed whole.
        if (required && (value.isEmpty() || delegation.partlyDisclosed(source))) {
            throw new ChainException("the first Delegate Payload has no " + source + ", which mapper "
                    + mapperModel.getName() + " requires");
        }
        if (value.isPresent()) {
            grant.addClaim(
                    mapperModel.getName(), claim, JsonSerialization.mapper.convertValue(value.get(), Object.class));
        }
    }

    static String claimName(IdentityProviderMapperModel mapperModel) {
        String claim = mapperModel.getConfig().get(CLAIM);
        List<String> segments = claim == null ? List.of() : JsonUtils.splitClaimPath(claim);
        if (segments.isEmpty() || segments.get(0).isBlank()) {
            throw new ConfigurationException("mapper " + mapperModel.getName() + " has no token claim name");
        }
        return claim;
    }

    @Override
    public String[] getCompatibleProviders() {
        return new String[] {DelegateSdJwtIdentityProviderFactory.PROVIDER_ID};
    }

    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Delegate Payload to Claim";
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
        return "Copies a value of the first Delegate Payload into an access token claim. A later link may leave it"
                + " out or repeat it but must not change or add it. A required claim must be in the first Delegate"
                + " Payload with all its Disclosures.";
    }
}
