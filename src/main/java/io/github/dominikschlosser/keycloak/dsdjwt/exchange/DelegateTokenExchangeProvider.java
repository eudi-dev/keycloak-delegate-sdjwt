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

import io.github.dominikschlosser.keycloak.dsdjwt.ConfigurationException;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainVerifier;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.VerifiedChain;
import io.github.dominikschlosser.keycloak.dsdjwt.delegation.Delegation;
import io.github.dominikschlosser.keycloak.dsdjwt.delegation.DelegationReader;
import io.github.dominikschlosser.keycloak.dsdjwt.idp.DelegateSdJwtIdentityProvider;
import io.github.dominikschlosser.keycloak.dsdjwt.idp.DelegateSdJwtIdentityProviderConfig;
import io.github.dominikschlosser.keycloak.dsdjwt.idp.DelegateSdJwtIdentityProviders;
import io.github.dominikschlosser.keycloak.dsdjwt.idp.TrustedIssuerKeys;
import io.github.dominikschlosser.keycloak.dsdjwt.mapper.DelegationGrant;
import io.github.dominikschlosser.keycloak.dsdjwt.mapper.DelegationMapper;
import io.github.dominikschlosser.keycloak.dsdjwt.nonce.NonceStore;
import io.github.dominikschlosser.keycloak.dsdjwt.status.HttpStatusListFetcher;
import io.github.dominikschlosser.keycloak.dsdjwt.status.StatusListChecker;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.light.LightweightUserAdapter;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.tokenexchange.StandardTokenExchangeProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.util.TokenUtil;

/**
 * Exchanges a dSD-JWT+KB (draft-ietf-oauth-delegate-sd-jwt-00 §5.1.1) for an access token of the
 * realm, as RFC 8693 describes. The principal of the credential becomes the subject and the agents
 * become the act claim (RFC 8693 §4.1).
 */
public class DelegateTokenExchangeProvider extends StandardTokenExchangeProvider {

    public static final String TOKEN_TYPE = "urn:eudi-dev:params:oauth:token-type:dsd-jwt-kb";

    private static final String AUTH_METHOD = "delegate-sd-jwt";

    private Delegation delegation;
    private DelegationGrant grant;
    private String subjectId;

    /**
     * Claims every request with our token type, also the ones it cannot serve, so no other provider
     * treats a dSD-JWT+KB as a token of its own. tokenExchange refuses those requests.
     */
    @Override
    public boolean supports(TokenExchangeContext context) {
        return TOKEN_TYPE.equals(context.getParams().getSubjectTokenType());
    }

    @Override
    protected Response tokenExchange() {
        checkRequest();
        DelegateSdJwtIdentityProviderConfig config = identityProvider();
        // The chain parser also throws IllegalArgumentException on bad input, so a config error caught
        // later would hide a malformed request.
        try {
            config.validate(realm);
        } catch (IllegalArgumentException e) {
            throw misconfigured(e);
        }
        UserModel user;
        try {
            verify(config);
            user = user();
        } catch (ChainException e) {
            throw refuse(OAuthErrorException.INVALID_REQUEST, Errors.INVALID_TOKEN, e.getMessage());
        } catch (ConfigurationException e) {
            throw misconfigured(e);
        }
        event.user(subjectId).detail(Details.USERNAME, delegation.principal());
        UserSessionModel userSession = new UserSessionManager(session)
                .createUserSession(
                        null,
                        realm,
                        user,
                        delegation.principal(),
                        clientConnection.getRemoteHost(),
                        AUTH_METHOD,
                        false,
                        null,
                        null,
                        UserSessionModel.SessionPersistenceState.TRANSIENT);
        return exchangeClientToClient(user, userSession, null, true);
    }

    private void checkRequest() {
        if (client.isPublicClient()) {
            throw refuse(
                    OAuthErrorException.INVALID_CLIENT,
                    Errors.INVALID_CLIENT,
                    "a public client cannot exchange a Delegate SD-JWT");
        }
        if (!OIDCAdvancedConfigWrapper.fromClientModel(client).isStandardTokenExchangeEnabled()) {
            event.detail(Details.REASON, "standard token exchange is not enabled for the client");
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(
                    cors,
                    OAuthErrorException.UNAUTHORIZED_CLIENT,
                    "standard token exchange is not enabled for the client",
                    Response.Status.BAD_REQUEST);
        }
        for (String parameter : List.of(
                OAuth2Constants.ACTOR_TOKEN,
                OAuth2Constants.REQUESTED_SUBJECT,
                OAuth2Constants.REQUESTED_ISSUER,
                OAuth2Constants.SUBJECT_ISSUER)) {
            if (formParams.getFirst(parameter) != null) {
                throw refuse(
                        OAuthErrorException.INVALID_REQUEST,
                        Errors.INVALID_REQUEST,
                        "the parameter " + parameter + " is not supported with a Delegate SD-JWT");
            }
        }
        if (params.getSubjectToken() == null || params.getSubjectToken().isEmpty()) {
            throw refuse(
                    OAuthErrorException.INVALID_REQUEST,
                    Errors.INVALID_REQUEST,
                    "the parameter subject_token is required");
        }
        // The principal has no login at this realm, so the exchange issues no ID token.
        if (TokenUtil.isOIDCRequest(formParams.getFirst(OAuth2Constants.SCOPE))) {
            throw refuse(
                    OAuthErrorException.INVALID_SCOPE,
                    Errors.INVALID_SCOPE,
                    "the scope openid is not supported with a Delegate SD-JWT");
        }
    }

    private DelegateSdJwtIdentityProviderConfig identityProvider() {
        try {
            return DelegateSdJwtIdentityProviders.forClient(session, client)
                    .orElseThrow(() -> refuse(
                            OAuthErrorException.UNAUTHORIZED_CLIENT,
                            Errors.UNAUTHORIZED_CLIENT,
                            "no Delegate SD-JWT identity provider lists the client"));
        } catch (ConfigurationException e) {
            event.detail(Details.REASON, e.getMessage());
            event.error(Errors.INVALID_CONFIG);
            throw new CorsErrorResponseException(
                    cors, OAuthErrorException.SERVER_ERROR, e.getMessage(), Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    private CorsErrorResponseException misconfigured(RuntimeException e) {
        event.detail(Details.REASON, e.getMessage());
        event.error(Errors.INVALID_CONFIG);
        return new CorsErrorResponseException(
                cors,
                OAuthErrorException.SERVER_ERROR,
                "the Delegate SD-JWT identity provider is misconfigured: " + e.getMessage(),
                Response.Status.INTERNAL_SERVER_ERROR);
    }

    private void verify(DelegateSdJwtIdentityProviderConfig config) throws ChainException {
        String realmIssuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        TrustedIssuerKeys trust = new TrustedIssuerKeys(new DelegateSdJwtIdentityProvider(session, config));
        VerifiedChain chain =
                new ChainVerifier(trust, KeycloakClock.INSTANCE).verify(params.getSubjectToken(), realmIssuer);
        delegation = new DelegationReader(new DelegationReader.Settings(
                        config.getPrincipalClaim(),
                        config.getCredentialActionsPath(),
                        config.getActionsPath(),
                        config.getAgentIdPath(),
                        config.getAudiencePath(),
                        config.getCredentialTypes(),
                        config.getDelegateTypes(),
                        realmIssuer))
                .read(chain);
        NonceStore.consume(session, realm, client, chain.nonce());
        new StatusListChecker(
                        new HttpStatusListFetcher(
                                session.getProvider(HttpClientProvider.class).getHttpClient(),
                                HttpStatusListFetcher.DEFAULT_TIMEOUT,
                                HttpStatusListFetcher.DEFAULT_DEADLINE),
                        trust,
                        KeycloakClock.INSTANCE,
                        ChainVerifier.CLOCK_SKEW)
                .check(chain.credential());
        grant = new DelegationGrant();
        List<IdentityProviderMapperModel> mappers = session.identityProviders()
                .getMappersByAliasStream(config.getAlias())
                .sorted(Comparator.comparing(IdentityProviderMapperModel::getName))
                .toList();
        for (IdentityProviderMapperModel model : mappers) {
            IdentityProviderMapper factory = (IdentityProviderMapper) session.getKeycloakSessionFactory()
                    .getProviderFactory(IdentityProviderMapper.class, model.getIdentityProviderMapper());
            if (!(factory instanceof DelegationMapper mapper)) {
                throw new ConfigurationException("the mapper " + model.getName() + " of type "
                        + model.getIdentityProviderMapper() + " cannot map a delegation");
            }
            mapper.map(session, realm, model, delegation, grant);
        }
        if (grant.roles().isEmpty()) {
            throw new ChainException("the delegation allows no action that a mapper grants a role for");
        }
    }

    /** Builds a lightweight user with only the mapped roles. */
    private UserModel user() {
        String principal = delegation.principal();
        // The same issuer and principal always give the same subject. It is never the id of a stored
        // user: introspection of a token without sid builds a session for the stored user with the
        // subject id, and that session carries the user's own roles instead of the delegated ones.
        subjectId = UUID.nameUUIDFromBytes((delegation.issuer() + "|" + principal).getBytes(StandardCharsets.UTF_8))
                .toString();
        if (session.users().getUserById(realm, subjectId) != null) {
            throw new ConfigurationException("the stored user " + subjectId + " has the subject id of the principal "
                    + principal + ", so its own roles would apply to the token");
        }
        LightweightUserAdapter user = new LightweightUserAdapter(session, realm, subjectId);
        user.setUsername(principal);
        user.setEnabled(true);
        for (RoleModel role : grant.roles()) {
            user.grantRole(role);
        }
        return user;
    }

    @Override
    protected String getRequestedTokenType() {
        String requested = params.getRequestedTokenType();
        if (requested == null || OAuth2Constants.ACCESS_TOKEN_TYPE.equals(requested)) {
            return OAuth2Constants.ACCESS_TOKEN_TYPE;
        }
        throw refuse(
                OAuthErrorException.INVALID_REQUEST,
                Errors.INVALID_REQUEST,
                "the requested_token_type " + requested + " is not supported with a Delegate SD-JWT");
    }

    @Override
    protected void checkRequestedAudiences(TokenManager.AccessTokenResponseBuilder responseBuilder) {
        super.checkRequestedAudiences(responseBuilder);
        AccessToken token = responseBuilder.getAccessToken();
        token.subject(subjectId);
        token.getOtherClaims().put(IDToken.ACT, delegation.actor());
        try {
            grant.applyClaims(token);
        } catch (ConfigurationException e) {
            throw misconfigured(e);
        }
        if (token.getExp() == null || token.getExp() > delegation.expiresAt()) {
            token.exp(delegation.expiresAt());
        }
        checkGrantedRoles(token);
    }

    /**
     * The protocol mappers of the client run on the token after the user's roles. A hardcoded role
     * mapper there would give the agents a role the delegation does not allow.
     */
    private void checkGrantedRoles(AccessToken token) {
        Set<RoleModel> granted = RoleUtils.expandCompositeRoles(grant.roles());
        if (token.getRealmAccess() != null && token.getRealmAccess().getRoles() != null) {
            for (String name : token.getRealmAccess().getRoles()) {
                if (granted.stream()
                        .noneMatch(
                                role -> !role.isClientRole() && role.getName().equals(name))) {
                    throw notGranted(name);
                }
            }
        }
        if (token.getResourceAccess() != null) {
            token.getResourceAccess().forEach((clientId, access) -> {
                if (access.getRoles() == null) {
                    return;
                }
                for (String name : access.getRoles()) {
                    if (granted.stream()
                            .noneMatch(role -> role.isClientRole()
                                    && role.getName().equals(name)
                                    && role.getContainer() instanceof ClientModel owner
                                    && owner.getClientId().equals(clientId))) {
                        throw notGranted(clientId + "." + name);
                    }
                }
            });
        }
    }

    private CorsErrorResponseException notGranted(String role) {
        String description = "the token holds the role " + role + ", which the delegation does not grant";
        event.detail(Details.REASON, description);
        event.error(Errors.INVALID_CONFIG);
        return new CorsErrorResponseException(
                cors, OAuthErrorException.SERVER_ERROR, description, Response.Status.INTERNAL_SERVER_ERROR);
    }

    /** RFC 8693 §2.2.2: a subject_token that fails validation is an invalid_request. */
    private CorsErrorResponseException refuse(String error, String eventError, String description) {
        event.detail(Details.REASON, description);
        event.error(eventError);
        return new CorsErrorResponseException(cors, error, description, Response.Status.BAD_REQUEST);
    }
}
