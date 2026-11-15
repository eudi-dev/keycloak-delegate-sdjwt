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

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.dominikschlosser.keycloak.dsdjwt.delegation.ClaimPath;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.KeycloakSessionUtil;

/** The settings of a Delegate SD-JWT exchange. Each setting is a key of the identity provider config. */
public class DelegateSdJwtIdentityProviderConfig extends IdentityProviderModel {

    public static final String CLIENTS = "clients";
    public static final String TRUST_MATERIAL_IDPS = "trustMaterialIdps";
    public static final String TRUSTED_ISSUER_JWKS = "trustedIssuerJwks";
    public static final String PRINCIPAL_CLAIM = "principalClaim";
    public static final String CREDENTIAL_ACTIONS_PATH = "credentialActionsPath";
    public static final String ACTIONS_PATH = "actionsPath";
    public static final String AGENT_ID_PATH = "agentIdPath";
    public static final String AUDIENCE_PATH = "audiencePath";
    public static final String CREDENTIAL_TYPES = "credentialTypes";

    public static final String DEFAULT_ACTIONS_PATH = "mandate.actions";
    public static final String DEFAULT_AGENT_ID_PATH = "agent.id";

    public DelegateSdJwtIdentityProviderConfig() {}

    public DelegateSdJwtIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    @Override
    public Boolean isHideOnLogin() {
        return true;
    }

    @Override
    public void validate(RealmModel realm) {
        super.validate(realm);
        if (getClients().isEmpty()) {
            throw new IllegalArgumentException(CLIENTS + " must list at least 1 client");
        }
        if (isBlank(getTrustMaterialIdps()) && isBlank(getTrustedIssuerJwks())) {
            throw new IllegalArgumentException(
                    "set " + TRUST_MATERIAL_IDPS + " or " + TRUSTED_ISSUER_JWKS + " to trust a credential issuer");
        }
        if (!isBlank(getTrustMaterialIdps()) && !isBlank(getTrustedIssuerJwks())) {
            throw new IllegalArgumentException(
                    "set either " + TRUST_MATERIAL_IDPS + " or " + TRUSTED_ISSUER_JWKS + ", not both");
        }
        if (realm != null) {
            checkTrustMaterial(KeycloakSessionUtil.getKeycloakSession().identityProviders()::getByAlias);
        }
        if (!isBlank(getTrustedIssuerJwks())) {
            parseIssuerJwks(getTrustedIssuerJwks());
        }
        getPrincipalClaim();
        getCredentialActionsPath();
        if (getCredentialTypes().isEmpty()) {
            throw new IllegalArgumentException(CREDENTIAL_TYPES + " must list at least 1 vct");
        }
        getActionsPath();
        getAgentIdPath();
        getAudiencePath();
    }

    public Set<String> getClients() {
        return list(getConfig().get(CLIENTS));
    }

    public String getTrustMaterialIdps() {
        return getConfig().get(TRUST_MATERIAL_IDPS);
    }

    public Set<String> getTrustMaterialAliases() {
        return list(getTrustMaterialIdps());
    }

    public String getTrustedIssuerJwks() {
        return getConfig().get(TRUSTED_ISSUER_JWKS);
    }

    public ClaimPath getPrincipalClaim() {
        String value = getConfig().get(PRINCIPAL_CLAIM);
        if (isBlank(value)) {
            throw new IllegalArgumentException(PRINCIPAL_CLAIM + " is required");
        }
        return path(PRINCIPAL_CLAIM, value);
    }

    /**
     * Refuses a Delegate SD-JWT identity provider as trust material, this one included. Keycloak's
     * TrustMaterialResolver follows the aliases without a cycle check, and the trustedIssuerJwks of
     * another one would vouch for issuers that this one does not trust.
     */
    void checkTrustMaterial(Function<String, IdentityProviderModel> identityProviders) {
        for (String alias : getTrustMaterialAliases()) {
            IdentityProviderModel model = identityProviders.apply(alias);
            if (alias.equals(getAlias())
                    || (model != null
                            && DelegateSdJwtIdentityProviderFactory.PROVIDER_ID.equals(model.getProviderId()))) {
                throw new IllegalArgumentException(
                        TRUST_MATERIAL_IDPS + " must not list the Delegate SD-JWT identity provider " + alias);
            }
        }
    }

    public ClaimPath getCredentialActionsPath() {
        String value = getConfig().get(CREDENTIAL_ACTIONS_PATH);
        if (isBlank(value)) {
            throw new IllegalArgumentException(CREDENTIAL_ACTIONS_PATH + " is required");
        }
        return path(CREDENTIAL_ACTIONS_PATH, value);
    }

    public ClaimPath getActionsPath() {
        return path(ACTIONS_PATH, getConfig().getOrDefault(ACTIONS_PATH, DEFAULT_ACTIONS_PATH));
    }

    public ClaimPath getAgentIdPath() {
        return path(AGENT_ID_PATH, getConfig().getOrDefault(AGENT_ID_PATH, DEFAULT_AGENT_ID_PATH));
    }

    /** Returns null when the Delegate Payloads need not list the realm. */
    public ClaimPath getAudiencePath() {
        String value = getConfig().get(AUDIENCE_PATH);
        return isBlank(value) ? null : path(AUDIENCE_PATH, value);
    }

    public Set<String> getCredentialTypes() {
        return list(getConfig().get(CREDENTIAL_TYPES));
    }

    /**
     * Reads the trusted issuers. Each key is a credential iss and its value the JWK Set of that
     * issuer, so the key of one issuer never verifies a credential that names another.
     */
    static Map<String, JSONWebKeySet> parseIssuerJwks(String json) {
        Map<String, JSONWebKeySet> issuers;
        try {
            issuers = JsonSerialization.mapper.readValue(json, new TypeReference<>() {});
        } catch (IOException e) {
            throw new IllegalArgumentException(TRUSTED_ISSUER_JWKS + " must map each issuer to a JWK Set", e);
        }
        if (issuers == null || issuers.values().stream().anyMatch(jwks -> jwks == null || jwks.getKeys() == null)) {
            throw new IllegalArgumentException(TRUSTED_ISSUER_JWKS + " must map each issuer to a JWK Set");
        }
        return issuers;
    }

    private static ClaimPath path(String key, String value) {
        try {
            return ClaimPath.parse(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(key + ": " + e.getMessage(), e);
        }
    }

    private static Set<String> list(String value) {
        Set<String> result = new LinkedHashSet<>();
        if (value != null) {
            Arrays.stream(value.split(","))
                    .map(String::trim)
                    .filter(item -> !item.isEmpty())
                    .forEach(result::add);
        }
        return result;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
