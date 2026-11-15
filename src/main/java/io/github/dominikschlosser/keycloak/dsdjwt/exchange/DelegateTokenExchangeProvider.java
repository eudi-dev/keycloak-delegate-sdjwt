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
import io.github.dominikschlosser.keycloak.dsdjwt.idp.DelegateSdJwtIdentityProviderFactory;
import io.github.dominikschlosser.keycloak.dsdjwt.idp.TrustedIssuerKeys;
import io.github.dominikschlosser.keycloak.dsdjwt.mapper.DelegationGrant;
import io.github.dominikschlosser.keycloak.dsdjwt.mapper.DelegationMapper;
import io.github.dominikschlosser.keycloak.dsdjwt.nonce.NonceStore;
import io.github.dominikschlosser.keycloak.dsdjwt.status.HttpStatusListFetcher;
import io.github.dominikschlosser.keycloak.dsdjwt.status.StatusListChecker;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.common.util.Time;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderQuery;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.cors.Cors;
import org.keycloak.util.TokenUtil;

/**
 * Exchanges a dSD-JWT+KB (draft-ietf-oauth-delegate-sd-jwt-00 §5.1.1) for an access token of the
 * realm, as RFC 8693 describes. The principal of the credential becomes the subject and the agents
 * become the act claim (RFC 8693 §4.1). The provider builds the token itself, so only the mappers of
 * the identity provider shape it.
 */
public class DelegateTokenExchangeProvider implements TokenExchangeProvider {

    public static final String TOKEN_TYPE = "urn:eudi-dev:params:oauth:token-type:dsd-jwt-kb";

    private KeycloakSession session;
    private RealmModel realm;
    private ClientModel client;
    private EventBuilder event;
    private Cors cors;
    private TokenExchangeContext.Params params;

    /**
     * Claims every request with our token type, also the ones it cannot serve, so no other provider
     * treats a dSD-JWT+KB as a token of its own. exchange refuses those requests.
     */
    @Override
    public boolean supports(TokenExchangeContext context) {
        return TOKEN_TYPE.equals(context.getParams().getSubjectTokenType());
    }

    @Override
    public Response exchange(TokenExchangeContext context) {
        session = context.getSession();
        realm = context.getRealm();
        client = context.getClient();
        event = context.getEvent();
        cors = context.getCors();
        params = context.getParams();
        checkRequest(context);
        DelegateSdJwtIdentityProviderConfig config = identityProvider();
        // The chain parser also throws IllegalArgumentException on bad input, so a config error caught
        // later would hide a malformed request.
        try {
            config.validate(realm);
        } catch (IllegalArgumentException e) {
            throw misconfigured(e);
        }
        String realmIssuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        Delegation delegation;
        DelegationGrant grant;
        String subject;
        try {
            delegation = verify(config, realmIssuer);
            grant = grant(config, delegation);
            subject = subject(delegation);
        } catch (ChainException e) {
            throw refuse(OAuthErrorException.INVALID_REQUEST, Errors.INVALID_TOKEN, e.getMessage());
        } catch (ConfigurationException e) {
            throw misconfigured(e);
        }
        event.user(subject).detail(Details.USERNAME, delegation.principal());
        AccessToken token = token(realmIssuer, subject, delegation, grant);
        // The signature algorithm and the header type come from the client in the context.
        session.getContext().setClient(client);
        AccessTokenResponse response = new AccessTokenResponse();
        response.setToken(session.tokens().encode(token));
        response.setTokenType(TokenUtil.TOKEN_TYPE_BEARER);
        response.setExpiresIn(token.getExp() - Time.currentTime());
        response.setOtherClaims(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
        if (token.getAudience() != null) {
            event.detail(Details.AUDIENCE, String.join(" ", token.getAudience()));
        }
        event.success();
        return cors.add(Response.ok(response, MediaType.APPLICATION_JSON_TYPE));
    }

    private void checkRequest(TokenExchangeContext context) {
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
            if (context.getFormParams().getFirst(parameter) != null) {
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
        // The mappers alone decide what the token holds, so a scope could not narrow it.
        if (context.getFormParams().getFirst(OAuth2Constants.SCOPE) != null) {
            throw refuse(
                    OAuthErrorException.INVALID_SCOPE,
                    Errors.INVALID_SCOPE,
                    "the parameter scope is not supported with a Delegate SD-JWT");
        }
        String requested = params.getRequestedTokenType();
        if (requested != null && !OAuth2Constants.ACCESS_TOKEN_TYPE.equals(requested)) {
            throw refuse(
                    OAuthErrorException.INVALID_REQUEST,
                    Errors.INVALID_REQUEST,
                    "the requested_token_type " + requested + " is not supported with a Delegate SD-JWT");
        }
    }

    private DelegateSdJwtIdentityProviderConfig identityProvider() {
        List<DelegateSdJwtIdentityProviderConfig> matches = session.identityProviders()
                .getAllStream(IdentityProviderQuery.any())
                .filter(model -> DelegateSdJwtIdentityProviderFactory.PROVIDER_ID.equals(model.getProviderId()))
                .filter(model -> model.isEnabled())
                .map(DelegateSdJwtIdentityProviderConfig::new)
                .filter(config -> config.getClients().contains(client.getClientId()))
                .toList();
        if (matches.isEmpty()) {
            throw refuse(
                    OAuthErrorException.UNAUTHORIZED_CLIENT,
                    Errors.UNAUTHORIZED_CLIENT,
                    "no Delegate SD-JWT identity provider lists the client");
        }
        if (matches.size() > 1) {
            throw misconfigured(new ConfigurationException("the identity providers "
                    + matches.stream()
                            .map(DelegateSdJwtIdentityProviderConfig::getAlias)
                            .toList()
                    + " all list the client " + client.getClientId()));
        }
        return matches.get(0);
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

    private Delegation verify(DelegateSdJwtIdentityProviderConfig config, String realmIssuer) throws ChainException {
        TrustedIssuerKeys trust = new TrustedIssuerKeys(new DelegateSdJwtIdentityProvider(session, config));
        VerifiedChain chain = new ChainVerifier(trust).verify(params.getSubjectToken(), realmIssuer);
        Delegation delegation = new DelegationReader(new DelegationReader.Settings(
                        config.getPrincipalClaim(),
                        config.getCredentialActionsPath(),
                        config.getActionsPath(),
                        config.getAgentIdPath(),
                        config.getAudiencePath(),
                        config.getCredentialTypes(),
                        realmIssuer))
                .read(chain);
        NonceStore.consume(session, realm, client, chain.nonce());
        new StatusListChecker(
                        new HttpStatusListFetcher(
                                session.getProvider(HttpClientProvider.class).getHttpClient(),
                                HttpStatusListFetcher.DEFAULT_TIMEOUT,
                                HttpStatusListFetcher.DEFAULT_DEADLINE),
                        trust)
                .check(chain.credential());
        return delegation;
    }

    private DelegationGrant grant(DelegateSdJwtIdentityProviderConfig config, Delegation delegation)
            throws ChainException {
        DelegationGrant grant = new DelegationGrant();
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
        return grant;
    }

    private String subject(Delegation delegation) {
        String principal = delegation.principal();
        // The same issuer and principal always give the same subject. It is never the id of a stored
        // user: introspection and userinfo look up a token without sid as the user with the subject id,
        // and they would then report that user's own roles.
        String subject = UUID.nameUUIDFromBytes(
                        (delegation.issuer() + "|" + principal).getBytes(StandardCharsets.UTF_8))
                .toString();
        if (session.users().getUserById(realm, subject) != null) {
            throw new ConfigurationException("the stored user " + subject + " has the subject id of the principal "
                    + principal + ", so its own roles would apply to the token");
        }
        return subject;
    }

    private AccessToken token(String realmIssuer, String subject, Delegation delegation, DelegationGrant grant) {
        AccessToken token = new AccessToken();
        token.id(UUID.randomUUID().toString());
        token.issuer(realmIssuer);
        token.subject(subject);
        token.issuedFor(client.getClientId());
        token.type(TokenUtil.TOKEN_TYPE_BEARER);
        token.issuedNow();
        token.exp(Math.min(token.getIat() + lifespan(), delegation.expiresAt()));
        token.getOtherClaims().put(IDToken.ACT, delegation.actor());
        for (RoleModel role : RoleUtils.expandCompositeRoles(grant.roles())) {
            if (!role.isClientRole()) {
                if (token.getRealmAccess() == null) {
                    token.setRealmAccess(new AccessToken.Access());
                }
                token.getRealmAccess().addRole(role.getName());
            } else if (role.getContainer() instanceof ClientModel owner) {
                token.addAccess(owner.getClientId()).addRole(role.getName());
            }
        }
        audience(token);
        try {
            grant.applyClaims(token);
        } catch (ConfigurationException e) {
            throw misconfigured(e);
        }
        return token;
    }

    private long lifespan() {
        String lifespan = client.getAttribute(OIDCConfigAttributes.ACCESS_TOKEN_LIFESPAN);
        return lifespan == null || lifespan.isBlank()
                ? realm.getAccessTokenLifespan()
                : Long.parseLong(lifespan.trim());
    }

    /** The audience is each other client the token holds a role of, or the requested ones among them. */
    private void audience(AccessToken token) {
        Set<String> available = new LinkedHashSet<>(token.getResourceAccess().keySet());
        available.remove(client.getClientId());
        List<String> requested = params.getAudience();
        if (requested != null && !requested.isEmpty()) {
            for (String audience : requested) {
                if (!available.contains(audience)) {
                    throw refuse(
                            OAuthErrorException.INVALID_REQUEST,
                            Errors.INVALID_REQUEST,
                            "the delegation grants no role of the audience " + audience);
                }
            }
            available.retainAll(requested);
            token.getResourceAccess().keySet().retainAll(requested);
        }
        if (!available.isEmpty()) {
            token.audience(available.toArray(String[]::new));
        }
    }

    /** RFC 8693 §2.2.2: a subject_token that fails validation is an invalid_request. */
    private CorsErrorResponseException refuse(String error, String eventError, String description) {
        event.detail(Details.REASON, description);
        event.error(eventError);
        return new CorsErrorResponseException(cors, error, description, Response.Status.BAD_REQUEST);
    }

    @Override
    public void close() {}
}
