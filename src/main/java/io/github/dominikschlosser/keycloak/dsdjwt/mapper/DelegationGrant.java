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

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dominikschlosser.keycloak.dsdjwt.ConfigurationException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.JsonUtils;

/** The roles and claims the mappers grant for one delegation. */
public final class DelegationGrant {

    /**
     * Claims that Keycloak, a resource server or the exchange give a meaning, although the token may
     * lack them. A mapper adding one could bind the token to an audience, a key, a session or roles it
     * does not have. The standard claims of OpenID Connect Core 1.0 §5.1 describe the subject, which
     * is the principal, so a Delegate Payload must not set them either. The names come from the IANA
     * JWT Claims registry entries of RFC 7519, RFC 7800, RFC 8693, RFC 9068 and OpenID Connect Core 1.0
     * §2 and §5.1, and from the AccessToken of Keycloak 26.8.2.
     */
    static final Set<String> PROTOCOL_CLAIMS = Set.of(
            "iss",
            "sub",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "typ",
            "azp",
            "client_id",
            "scope",
            "acr",
            "amr",
            "auth_time",
            "nonce",
            "sid",
            "session_state",
            "at_hash",
            "c_hash",
            "s_hash",
            "cnf",
            "act",
            "may_act",
            "groups",
            "roles",
            "entitlements",
            "realm_access",
            "resource_access",
            "authorization",
            "allowed-origins",
            "trusted-certs",
            "verify_caller",
            "name",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "email",
            "email_verified",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "phone_number",
            "phone_number_verified",
            "address",
            "updated_at");

    private record Claim(String mapperName, Object value) {}

    private final Set<RoleModel> roles = new LinkedHashSet<>();
    private final Map<String, Claim> claims = new LinkedHashMap<>();

    public void addRole(RoleModel role) {
        roles.add(role);
    }

    /** Adds a claim. 2 mappers must not set the same claim. */
    public void addClaim(String mapperName, String claim, Object value) {
        Claim earlier = claims.get(claim);
        if (earlier != null) {
            throw new ConfigurationException("mapper " + mapperName + " sets the claim " + claim + ", which mapper "
                    + earlier.mapperName() + " sets too");
        }
        claims.put(claim, new Claim(mapperName, value));
    }

    public Set<RoleModel> roles() {
        return Collections.unmodifiableSet(roles);
    }

    /**
     * Adds the claims to a token that holds everything else already. A claim whose top level name the
     * token holds, or one of {@link #PROTOCOL_CLAIMS}, throws a ConfigurationException before any
     * claim is added.
     */
    public void applyClaims(IDToken token) {
        JsonNode present = JsonSerialization.mapper.valueToTree(token);
        claims.forEach((claim, granted) -> {
            String name = JsonUtils.splitClaimPath(claim).get(0);
            if (present.has(name) || PROTOCOL_CLAIMS.contains(name)) {
                throw new ConfigurationException(
                        "mapper " + granted.mapperName() + " must not set the claim " + name + " of the token");
            }
        });
        claims.forEach((claim, granted) -> {
            ProtocolMapperModel model = new ProtocolMapperModel();
            model.setName(granted.mapperName());
            model.setConfig(Map.of(
                    OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME,
                    claim,
                    ProtocolMapperUtils.MULTIVALUED,
                    String.valueOf(granted.value() instanceof List<?>)));
            OIDCAttributeMapperHelper.mapClaim(token, model, granted.value());
        });
    }
}
