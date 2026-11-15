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

package io.github.dominikschlosser.keycloak.dsdjwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dominikschlosser.eudi.Credential;
import io.github.dominikschlosser.eudi.EudiWalletContainer;
import io.github.dominikschlosser.eudi.IssueRequest;
import io.github.dominikschlosser.eudi.WalletClient;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.MountableFile;

/**
 * Runs the token exchange against Keycloak with the provider JAR installed. An eudi-dev wallet
 * issues the credentials and signs the first delegation. The test acts as the agent.
 */
class DelegateTokenExchangeIT {

    private static final String TOKEN_TYPE = "urn:eudi-dev:params:oauth:token-type:dsd-jwt-kb";
    private static final String REALM = "acme";
    private static final String AGENT = "procurement-agent";
    private static final String ADMIN_AGENT = "admin-agent";
    private static final String UNLISTED_AGENT = "unlisted-agent";
    private static final String LEDGER_AGENT = "ledger-agent";
    private static final String FOREIGN_AGENT = "foreign-agent";
    private static final String FIXED_ROLE_AGENT = "fixed-role-agent";
    private static final String PUBLIC_AGENT = "public-agent";
    private static final String SHARED_AGENT = "shared-agent";
    private static final String DISABLED_IDP_AGENT = "disabled-idp-agent";
    private static final String STATUS_AGENT = "status-agent";
    private static final String KEYS_AGENT = "keys-agent";
    private static final String UNKNOWN_KEYS_AGENT = "unknown-keys-agent";
    private static final int NONCE_LIFESPAN = 10;
    private static final String API = "invoice-api";
    private static final String CLIENT_SECRET = UUID.randomUUID().toString();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    private static final String WALLET_ISSUER = "https://wallet:8086";
    private static final String UNREACHABLE_STATUS_LIST = "https://wallet:1/statuslist";
    private static final String POA = "urn:eudi-test:business:poa:1";
    private static final String COLLIDING_PRINCIPAL = "DEACME.HRB9";

    private static Network network;
    private static EudiWalletContainer wallet;
    private static WalletClient walletClient;
    private static GenericContainer<?> keycloak;
    private static String baseUrl;
    private static String realmIssuer;

    private static Credential acme;
    private static Credential bolt;
    private static Credential colliding;
    private static Credential withStatus;
    private static Credential revoked;
    private static Credential unreachableStatus;
    private static Credential untrusted;

    @BeforeAll
    @SuppressWarnings("resource")
    static void start() throws Exception {
        CryptoIntegration.init(DelegateTokenExchangeIT.class.getClassLoader());
        network = Network.newNetwork();
        wallet = new EudiWalletContainer()
                .withoutDefaultPid()
                .withStatusList()
                .withDelegateSdJwt()
                .withNetwork(network)
                .withNetworkAliases("wallet")
                .withBaseUrl("http://wallet:8085");
        wallet.start();
        walletClient = wallet.client();

        acme = issue(
                ChainBuilder.PRINCIPAL,
                "Acme Logistics GmbH",
                List.of("invoice.approve", "order.create", "fleet.sell", "realm.manage"),
                "");
        bolt = issue("NLBOLT.KVK1234", "Bolt Supplies B.V.", List.of("order.create"), "");
        colliding = issue(COLLIDING_PRINCIPAL, "Acme Logistics GmbH", List.of("invoice.approve"), "");
        withStatus = issue("DEACME.HRB4712", "Acme Logistics GmbH", List.of("invoice.approve"), null);
        revoked = issue("DEACME.HRB4713", "Acme Logistics GmbH", List.of("invoice.approve"), null);
        unreachableStatus =
                issue("DEACME.HRB4714", "Acme Logistics GmbH", List.of("invoice.approve"), UNREACHABLE_STATUS_LIST);
        KeyWrapper untrustedKey = ChainBuilder.ecKey();
        TestCertificates otherCa = new TestCertificates("Crate Test CA");
        untrusted = walletClient.issueCredential(
                request("DEACME.HRB4715", "Acme Logistics GmbH", List.of("invoice.approve"), "")
                        .signedBy(
                                TestCertificates.pem((PrivateKey) untrustedKey.getPrivateKey()),
                                TestCertificates.pem(otherCa.issue(
                                                "Acme Logistics GmbH",
                                                untrustedKey,
                                                TestCertificates.uri(WALLET_ISSUER),
                                                TestCertificates.dns("wallet")))
                                        + otherCa.pem()));

        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:" + System.getProperty("keycloak.version"))
                .withNetwork(network)
                .withCopyFileToContainer(
                        MountableFile.forHostPath(System.getProperty("provider.jar")),
                        "/opt/keycloak/providers/keycloak-delegate-sdjwt.jar")
                .withCopyToContainer(
                        Transferable.of(JsonSerialization.writeValueAsBytes(realm())),
                        "/opt/keycloak/data/import/" + REALM + ".json")
                .withCopyToContainer(
                        Transferable.of(walletClient.getTlsCertificatePem()), "/opt/keycloak/conf/wallet-tls.pem")
                .withCommand(
                        "start-dev",
                        "--import-realm",
                        "--features=oid4vc-vci",
                        "--truststore-paths=/opt/keycloak/conf/wallet-tls.pem",
                        "--spi-realm-restapi-extension--delegate-sd-jwt--nonce-lifespan=" + NONCE_LIFESPAN)
                .withExposedPorts(8080)
                .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).withStartupTimeout(Duration.ofMinutes(4)));
        keycloak.start();
        baseUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        realmIssuer = baseUrl + "/realms/" + REALM;
    }

    @AfterAll
    static void stop() {
        if (keycloak != null) {
            keycloak.stop();
        }
        if (wallet != null) {
            wallet.stop();
        }
        if (network != null) {
            network.close();
        }
    }

    @Test
    void walletNamesItsNetworkAliasInIssuerCertificateAndStatusList() throws Exception {
        assertEquals(WALLET_ISSUER, acme.claims().get("iss"));
        X509Certificate leaf = leaf(header(acme.raw()));
        assertTrue(
                leaf.getSubjectAlternativeNames().contains(List.of(6, WALLET_ISSUER)),
                leaf.getSubjectAlternativeNames().toString());
        assertTrue(
                JsonSerialization.mapper
                        .valueToTree(withStatus.claims())
                        .at("/status/status_list/uri")
                        .asText()
                        .startsWith(WALLET_ISSUER + "/"),
                withStatus.claims().toString());
    }

    @Test
    void exchangesChainForTokenWithRolesClaimsAndActor() throws Exception {
        for (int links : new int[] {1, 2, 4}) {
            String chain = delegate(acme, "invoice.approve", "order.create")
                    .toAgent(AGENT)
                    .links(links - 1, "invoice.approve", "order.create")
                    .build();

            JsonNode response = exchange(AGENT, chain, Map.of());

            assertEquals(200, response.get("status").asInt(), response.toString());
            assertEquals(
                    "urn:ietf:params:oauth:token-type:access_token",
                    response.get("issued_token_type").asText());
            assertEquals("Bearer", response.get("token_type").asText());
            assertFalse(response.has("refresh_token"), response.toString());
            assertFalse(response.has("id_token"), response.toString());
            JsonNode token = claims(response.get("access_token").asText());
            assertEquals(realmIssuer, token.get("iss").asText());
            assertEquals(
                    principalSubject(ChainBuilder.PRINCIPAL), token.get("sub").asText());
            assertEquals(AGENT, token.get("azp").asText());
            assertEquals(API, token.get("aud").asText());
            assertEquals("Bearer", token.get("typ").asText());
            assertFalse(token.get("jti").asText().isEmpty(), token.toString());
            assertEquals(300, token.get("exp").asLong() - token.get("iat").asLong());
            for (String absent : List.of("sid", "scope", "preferred_username", "acr", "allowed-origins")) {
                assertFalse(token.has(absent), token.toString());
            }
            assertEquals(
                    List.of("invoice-approver", "order-creator"),
                    sorted(token.at("/resource_access/" + API + "/roles")));
            assertEquals("EUR", token.at("/approval_limit/currency").asText());
            assertEquals("2500.00", token.at("/approval_limit/amount").asText());
            assertEquals(JsonSerialization.mapper.valueToTree(actor(links)), token.get("act"));
        }
    }

    @Test
    void grantsOnlyRolesOfDelegatedActions() throws Exception {
        JsonNode response = exchange(AGENT, chain(AGENT, acme, "invoice.approve", "fleet.sell"), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        JsonNode token = claims(response.get("access_token").asText());
        assertEquals(List.of(API), fieldNames(token.get("resource_access")));
        assertEquals(List.of("invoice-approver"), sorted(token.at("/resource_access/" + API + "/roles")));
        assertFalse(token.has("realm_access"), token.toString());
    }

    @Test
    void ignoresProtocolMappersOfTheClient() throws Exception {
        JsonNode response = exchange(FIXED_ROLE_AGENT, chain(FIXED_ROLE_AGENT, acme, "invoice.approve"), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        JsonNode token = claims(response.get("access_token").asText());
        assertEquals(List.of("invoice-approver"), sorted(token.at("/resource_access/" + API + "/roles")));
        assertFalse(token.has("tenant"), token.toString());
    }

    @Test
    void grantsOnlyActionsTheCredentialAllows() throws Exception {
        JsonNode response = exchange(AGENT, chain(AGENT, bolt, "invoice.approve", "order.create"), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        JsonNode token = claims(response.get("access_token").asText());
        assertEquals(List.of("order-creator"), sorted(token.at("/resource_access/" + API + "/roles")));
    }

    @Test
    void issuesTokenForRequestedAudience() throws Exception {
        JsonNode response = exchange(AGENT, chain(AGENT, acme, "invoice.approve"), Map.of("audience", API));

        assertEquals(200, response.get("status").asInt(), response.toString());
        JsonNode audience = claims(response.get("access_token").asText()).get("aud");
        assertEquals(API, audience.isArray() ? audience.get(0).asText() : audience.asText());
    }

    @Test
    void refusesAudienceTheDelegationGrantsNoRoleOf() throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT, acme, "invoice.approve"), Map.of("audience", LEDGER_AGENT)),
                400,
                "invalid_request",
                "the delegation grants no role of the audience " + LEDGER_AGENT);
    }

    @Test
    void refusesMapperThatCannotMapADelegation() throws Exception {
        assertRefused(
                exchange(FOREIGN_AGENT, chain(FOREIGN_AGENT, acme, "invoice.approve"), Map.of()),
                500,
                "server_error",
                "the Delegate SD-JWT identity provider is misconfigured: the mapper fixed role of type"
                        + " hardcoded-role-idp-mapper cannot map a delegation");
    }

    @Test
    void introspectionReportsTheTokenInactive() throws Exception {
        JsonNode response = exchange(AGENT, chain(AGENT, acme, "invoice.approve"), Map.of());
        assertEquals(200, response.get("status").asInt(), response.toString());

        JsonNode introspection = post(
                "/realms/" + REALM + "/protocol/openid-connect/token/introspect",
                Map.of(
                        "client_id",
                        API,
                        "client_secret",
                        CLIENT_SECRET,
                        "token",
                        response.get("access_token").asText()));

        assertEquals(200, introspection.get("status").asInt(), introspection.toString());
        assertFalse(introspection.get("active").asBoolean(), introspection.toString());
    }

    @Test
    void userinfoRefusesExchangedToken() throws Exception {
        JsonNode exchanged = exchange(AGENT, chain(AGENT, acme, "invoice.approve"), Map.of());
        assertEquals(200, exchanged.get("status").asInt(), exchanged.toString());
        HttpRequest request = HttpRequest.newBuilder(URI.create(realmIssuer + "/protocol/openid-connect/userinfo"))
                .header(
                        "Authorization",
                        "Bearer " + exchanged.get("access_token").asText())
                .GET()
                .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());

        assertTrue(response.statusCode() == 401 || response.statusCode() == 403, response.toString());
        assertFalse(response.body().contains("invoice-approver"), response.body());
    }

    @Test
    void refusesPrincipalWhoseSubjectIsAStoredUserId() throws Exception {
        JsonNode response = exchange(AGENT, chain(AGENT, colliding, "invoice.approve"), Map.of());

        assertRefused(response, 500, "server_error", null);
        assertTrue(response.get("error_description").asText().contains("own roles"), response.toString());
    }

    @Test
    void capsTokenLifetimeAtChainExpiry() throws Exception {
        Delegation delegation = delegate(acme, "invoice.approve");
        long expiry = now() + 60;
        delegation.payload.put("exp", expiry);

        JsonNode response = exchange(AGENT, delegation.toAgent(AGENT).build(), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        assertTrue(response.get("expires_in").asLong() <= 60, response.toString());
        assertTrue(claims(response.get("access_token").asText()).get("exp").asLong() <= expiry);
    }

    @Test
    void refusesMalformedSubjectTokens() throws Exception {
        String[] parts = chain(AGENT, acme, "invoice.approve").split("~", -1);
        parts[1] = "!!not-base64!!";

        for (String token : List.of("x", "a.b.c~", String.join("~", parts))) {
            assertRefused(exchange(AGENT, token, Map.of()), 400, "invalid_request", null);
        }
    }

    @Test
    void refusesCredentialWithUnreachableStatusList() throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT, unreachableStatus, "invoice.approve"), Map.of()),
                400,
                "invalid_request",
                "the status list at " + UNREACHABLE_STATUS_LIST + " could not be loaded");
    }

    @Test
    void refusesRevokedCredential() throws Exception {
        Delegation delegation = delegate(revoked, "invoice.approve");
        JsonNode before =
                exchange(STATUS_AGENT, delegation.toAgent(STATUS_AGENT).build(), Map.of());
        assertEquals(200, before.get("status").asInt(), before.toString());

        walletClient.revokeCredential(revoked.id());

        assertRefused(
                exchange(STATUS_AGENT, delegation.toAgent(STATUS_AGENT).build(), Map.of()),
                400,
                "invalid_request",
                "the credential is invalid (status 1)");
        JsonNode other = exchange(STATUS_AGENT, chain(STATUS_AGENT, withStatus, "invoice.approve"), Map.of());
        assertEquals(200, other.get("status").asInt(), other.toString());
    }

    @Test
    void acceptsCredentialWithValidStatus() throws Exception {
        JsonNode response = exchange(STATUS_AGENT, chain(STATUS_AGENT, withStatus, "invoice.approve"), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
    }

    @Test
    void refusesReplayedNonce() throws Exception {
        String chain = chain(AGENT, acme, "invoice.approve");

        assertEquals(200, exchange(AGENT, chain, Map.of()).get("status").asInt());
        assertRefused(
                exchange(AGENT, chain, Map.of()),
                400,
                "invalid_request",
                "the nonce of the Key Binding JWT is unknown, expired, already used or issued to another client");
    }

    @Test
    void refusesExpiredNonce() throws Exception {
        String chain = chain(AGENT, acme, "invoice.approve");

        Thread.sleep(Duration.ofSeconds(NONCE_LIFESPAN + 2));

        assertRefused(
                exchange(AGENT, chain, Map.of()),
                400,
                "invalid_request",
                "the nonce of the Key Binding JWT is unknown, expired, already used or issued to another client");
    }

    @Test
    void refusesNonceOfAnotherClientAndKeepsItForItsOwner() throws Exception {
        Delegation delegation = delegate(acme, "invoice.approve").presented();
        String nonce = nonce(LEDGER_AGENT);

        assertRefused(
                exchange(AGENT, delegation.withNonce(nonce).build(), Map.of()),
                400,
                "invalid_request",
                "the nonce of the Key Binding JWT is unknown, expired, already used or issued to another client");
        JsonNode response = exchange(LEDGER_AGENT, delegation.withNonce(nonce).build(), Map.of());
        assertEquals(200, response.get("status").asInt(), response.toString());
    }

    @Test
    void keepsTheNonceWhenTheChainHidesThePrincipal() throws Exception {
        Delegation hidden = delegate(bolt, "order.create").hidingPrincipal().presented();
        Delegation shown = delegate(bolt, "order.create").presented();
        String nonce = nonce(AGENT);

        assertRefused(
                exchange(AGENT, hidden.withNonce(nonce).build(), Map.of()),
                400,
                "invalid_request",
                "the credential has no text claim euid_reference for the principal");
        JsonNode response = exchange(AGENT, shown.withNonce(nonce).build(), Map.of());
        assertEquals(200, response.get("status").asInt(), response.toString());
    }

    @Test
    void refusesADelegationWithoutTheValueOfARequiredClaimMapper() throws Exception {
        Delegation delegation = delegate(acme, "invoice.approve");
        delegation.payload.withObjectProperty("mandate").remove("limit");

        assertRefused(
                exchange(LEDGER_AGENT, delegation.toAgent(LEDGER_AGENT).build(), Map.of()),
                400,
                "invalid_request",
                "the first Delegate Payload has no mandate.limit, which mapper limit requires");
    }

    @Test
    void acceptsAnIssuerCertificateThatNamesTheIssuer() throws Exception {
        JsonNode response = exchange(LEDGER_AGENT, chain(LEDGER_AGENT, acme, "invoice.approve"), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        assertEquals(
                principalSubject(ChainBuilder.PRINCIPAL),
                claims(response.get("access_token").asText()).get("sub").asText());
    }

    @Test
    void refusesAnIssuerCertificateOfAnotherCaWithoutFallingBackToKeys() throws Exception {
        JsonNode response = exchange(AGENT, chain(AGENT, untrusted, "invoice.approve"), Map.of());

        assertRefused(response, 400, "invalid_request", null);
        assertTrue(
                response.get("error_description")
                        .asText()
                        .startsWith("the x5c certificate chain of the issuer is not trusted: "),
                response.toString());
    }

    @Test
    void refusesAnIssuerKeyThatIsNotTrusted() throws Exception {
        assertEquals(WALLET_ISSUER, untrusted.claims().get("iss"));

        assertRefused(
                exchange(STATUS_AGENT, chain(STATUS_AGENT, untrusted, "invoice.approve"), Map.of()),
                400,
                "invalid_request",
                "no trusted key of the credential issuer was found");
    }

    @Test
    void acceptsIssuerKeysOfATrustProviderThatNamesTheIssuer() throws Exception {
        for (Credential credential : List.of(acme, untrusted)) {
            JsonNode response = exchange(KEYS_AGENT, chain(KEYS_AGENT, credential, "invoice.approve"), Map.of());

            assertEquals(200, response.get("status").asInt(), response.toString());
        }
    }

    @Test
    void ignoresIssuerKeysOfTrustProvidersThatAreDisabledOrNameAnotherIssuer() throws Exception {
        assertRefused(
                exchange(UNKNOWN_KEYS_AGENT, chain(UNKNOWN_KEYS_AGENT, acme, "invoice.approve"), Map.of()),
                400,
                "invalid_request",
                "no trusted key of the credential issuer was found");
    }

    @Test
    void refusesDelegationWithoutMappedAction() throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT, acme, "fleet.sell"), Map.of()),
                400,
                "invalid_request",
                "the delegation allows no action that a mapper grants a role for");
    }

    @ParameterizedTest
    @ValueSource(strings = {"openid", "profile"})
    void refusesScope(String scope) throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT, acme, "invoice.approve"), Map.of("scope", scope)),
                400,
                "invalid_scope",
                "the parameter scope is not supported with a Delegate SD-JWT");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"urn:ietf:params:oauth:token-type:refresh_token", "urn:ietf:params:oauth:token-type:id_token"})
    void refusesOtherTokenTypesThanAccessToken(String type) throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT, acme, "invoice.approve"), Map.of("requested_token_type", type)),
                400,
                "invalid_request",
                "the requested_token_type " + type + " is not supported with a Delegate SD-JWT");
    }

    @ParameterizedTest
    @ValueSource(strings = {"actor_token", "requested_subject", "requested_issuer", "subject_issuer"})
    void refusesParametersTheChainReplaces(String parameter) throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT, acme, "invoice.approve"), Map.of(parameter, "x")),
                400,
                "invalid_request",
                "the parameter " + parameter + " is not supported with a Delegate SD-JWT");
    }

    @Test
    void reportsTwoIdentityProvidersForOneClientAsServerError() throws Exception {
        JsonNode response = exchange(SHARED_AGENT, "x", Map.of());

        assertRefused(response, 500, "server_error", null);
        assertTrue(
                response.get("error_description").asText().endsWith(" all list the client " + SHARED_AGENT),
                response.toString());
    }

    @Test
    void ignoresADisabledIdentityProvider() throws Exception {
        assertRefused(
                exchange(DISABLED_IDP_AGENT, "x", Map.of()),
                400,
                "unauthorized_client",
                "no Delegate SD-JWT identity provider lists the client");
    }

    @Test
    void refusesClientWithoutIdentityProvider() throws Exception {
        assertRefused(
                exchange(UNLISTED_AGENT, "x", Map.of()),
                400,
                "unauthorized_client",
                "no Delegate SD-JWT identity provider lists the client");
    }

    @Test
    void refusesPublicClient() throws Exception {
        JsonNode nonce = post("/realms/" + REALM + "/delegate-sd-jwt/nonce", Map.of("client_id", PUBLIC_AGENT));
        assertRefused(nonce, 400, "invalid_client", "a public client cannot exchange a Delegate SD-JWT");

        assertRefused(
                exchange(
                        PUBLIC_AGENT,
                        delegate(acme, "invoice.approve").withNonce("unused").build(),
                        Map.of()),
                400,
                "invalid_client",
                "a public client cannot exchange a Delegate SD-JWT");
    }

    @Test
    void refusesNonceRequestWithoutClientAuthentication() throws Exception {
        JsonNode response = post(
                "/realms/" + REALM + "/delegate-sd-jwt/nonce", Map.of("client_id", AGENT, "client_secret", "wrong"));

        assertEquals(401, response.get("status").asInt(), response.toString());
    }

    @Test
    void reportsAdminRoleMapperAsServerError() throws Exception {
        JsonNode response = exchange(ADMIN_AGENT, chain(ADMIN_AGENT, acme, "realm.manage"), Map.of());

        assertRefused(response, 500, "server_error", null);
        assertTrue(response.get("error_description").asText().contains("admin role"), response.toString());
    }

    @Test
    void nonceResponseIsNotCached() throws Exception {
        HttpResponse<String> response = HTTP.send(
                HttpRequest.newBuilder(URI.create(baseUrl + "/realms/" + REALM + "/delegate-sd-jwt/nonce"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                form(Map.of("client_id", AGENT, "client_secret", CLIENT_SECRET))))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode(), response.body());
        assertTrue(response.headers().firstValue("Cache-Control").orElse("").contains("no-store"));
        JsonNode body = JsonSerialization.mapper.readTree(response.body());
        assertEquals(NONCE_LIFESPAN, body.get("expires_in").asInt());
        assertNotEquals("", body.get("nonce").asText());
    }

    /** A delegation from the principal to a fresh agent key. The wallet signs it when the test presents it. */
    private static final class Delegation {

        final ObjectNode payload = ChainBuilder.object();
        private final KeyWrapper agent = ChainBuilder.ecKey();
        private final Credential credential;
        private final ArrayNode claims = JsonSerialization.mapper.createArrayNode();
        private String chain;

        Delegation(Credential credential, String... actions) {
            this.credential = credential;
            payload.put("vct", "urn:eudi-test:business:agent-mandate:1");
            payload.putObject("agent")
                    .put("id", "urn:eudi-test:agent:procurement-1")
                    .put("name", "Procurement agent of Alice");
            ObjectNode mandate = payload.putObject("mandate");
            ArrayNode delegated = mandate.putArray("actions");
            List.of(actions).forEach(delegated::add);
            mandate.putObject("limit").put("amount", "2500.00").put("currency", "EUR");
            mandate.put("purpose", "Approve supplier invoices");
            mandate.putArray("audiences").add(realmIssuer);
            payload.putObject("cnf").set("jwk", JsonSerialization.mapper.valueToTree(ChainBuilder.publicJwk(agent)));
            claims.addObject().putArray("path").add("legal_name");
            ObjectNode principal = claims.addObject();
            principal.putArray("path").add("euid_reference");
            principal.putArray("values").add((String) credential.claims().get("euid_reference"));
            claims.addObject()
                    .putArray("path")
                    .add("authorisation")
                    .add("actions")
                    .addNull();
        }

        /** Selects the credential by its legal name and keeps euid_reference undisclosed. */
        Delegation hidingPrincipal() {
            claims.remove(1);
            ((ObjectNode) claims.get(0)).putArray("values").add((String)
                    credential.claims().get("legal_name"));
            return this;
        }

        /**
         * Presents the credential in an OpenID4VP request with a delegate transaction data entry. The
         * wallet signs the first delegation and keeps the chain.
         */
        Delegation presented() throws Exception {
            if (chain != null) {
                return this;
            }
            ObjectNode request = ChainBuilder.object();
            request.put("type", "custom");
            ObjectNode query = request.putObject("dcql_query")
                    .putArray("credentials")
                    .addObject()
                    .put("id", "poa")
                    .put("format", "dc+sd-jwt");
            query.putObject("meta").putArray("vct_values").add(POA);
            query.set("claims", claims);
            ObjectNode delegate = request.putArray("transaction_data").addObject();
            delegate.put("type", "delegate");
            delegate.putArray("credential_ids").add("poa");
            delegate.put("format", "dSD-JWT+KB");
            delegate.set("delegate_payload", payload);
            HttpResponse<String> created = HTTP.send(
                    HttpRequest.newBuilder(URI.create(wallet.getBaseUrl() + "/verifier/api/requests"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(JsonSerialization.writeValueAsString(request)))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(201, created.statusCode(), created.body());

            String presented = walletClient
                    .acceptPresentationRequest(JsonSerialization.mapper
                            .readTree(created.body())
                            .get("scheme_uri")
                            .asText())
                    .status();
            assertEquals("submitted", presented);
            // The wallet keeps every delegation of a credential. The agent key identifies this one.
            String agentX = JsonSerialization.mapper
                    .valueToTree(ChainBuilder.publicJwk(agent))
                    .get("x")
                    .asText();
            chain = walletClient.getDelegations(credential.id()).stream()
                    .filter(record ->
                            agentX.equals(record.delegates().get(0).jwk().get("x")))
                    .findFirst()
                    .orElseThrow()
                    .chain();
            return this;
        }

        ChainBuilder withNonce(String nonce) throws Exception {
            return ChainBuilder.fromWallet(presented().chain, agent, now(), realmIssuer, nonce);
        }

        ChainBuilder toAgent(String clientId) throws Exception {
            return withNonce(nonce(clientId));
        }
    }

    private static Delegation delegate(Credential credential, String... actions) {
        return new Delegation(credential, actions);
    }

    private static String chain(String clientId, Credential credential, String... actions) throws Exception {
        return delegate(credential, actions).toAgent(clientId).build();
    }

    /** An empty status list URI makes the wallet leave out the status claim. Null takes the wallet status list. */
    private static Credential issue(String principal, String legalName, List<String> actions, String statusList) {
        return walletClient.issueCredential(request(principal, legalName, actions, statusList));
    }

    private static IssueRequest request(String principal, String legalName, List<String> actions, String statusList) {
        IssueRequest request = IssueRequest.sdJwt(POA)
                .claims(Map.of(
                        "legal_name", legalName,
                        "euid_reference", principal,
                        "authorisation", Map.of("actions", actions)));
        return statusList == null ? request : request.statusList(statusList, 0);
    }

    private static JsonNode header(String jwt) throws Exception {
        return JsonSerialization.mapper.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[0]));
    }

    private static X509Certificate leaf(JsonNode header) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(
                        Base64.getDecoder().decode(header.get("x5c").get(0).asText())));
    }

    /** The key of the x5c leaf of the JWT, with the kid of its header. */
    private static JWK headerKey(String jwt) throws Exception {
        JsonNode header = header(jwt);
        return JWKBuilder.create()
                .kid(header.path("kid").asText(null))
                .algorithm("ES256")
                .ec(leaf(header).getPublicKey());
    }

    private static String principalSubject(String principal) {
        return UUID.nameUUIDFromBytes((WALLET_ISSUER + "|" + principal).getBytes(StandardCharsets.UTF_8))
                .toString();
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    private static List<String> fieldNames(JsonNode object) {
        List<String> names = new ArrayList<>();
        object.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private static Map<String, Object> actor(int links) {
        Map<String, Object> actor = null;
        for (int i = 1; i <= links; i++) {
            Map<String, Object> act = new LinkedHashMap<>();
            act.put("sub", "urn:eudi-test:agent:procurement-" + i);
            if (actor != null) {
                act.put("act", actor);
            }
            actor = act;
        }
        return actor;
    }

    private static void assertRefused(JsonNode response, int status, String error, String description) {
        assertEquals(status, response.get("status").asInt(), response.toString());
        assertEquals(error, response.get("error").asText(), response.toString());
        if (description != null) {
            assertEquals(description, response.get("error_description").asText());
        }
    }

    private static String nonce(String clientId) throws Exception {
        JsonNode response = post(
                "/realms/" + REALM + "/delegate-sd-jwt/nonce",
                Map.of("client_id", clientId, "client_secret", CLIENT_SECRET));
        assertEquals(200, response.get("status").asInt(), response.toString());
        return response.get("nonce").asText();
    }

    private static JsonNode exchange(String clientId, String subjectToken, Map<String, String> extra) throws Exception {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        form.put("client_id", clientId);
        form.put("client_secret", CLIENT_SECRET);
        form.put("subject_token", subjectToken);
        form.put("subject_token_type", TOKEN_TYPE);
        form.putAll(extra);
        return post("/realms/" + REALM + "/protocol/openid-connect/token", form);
    }

    private static JsonNode claims(String jwt) throws Exception {
        return JsonSerialization.mapper.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
    }

    private static List<String> sorted(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(value -> values.add(value.asText()));
        return values.stream().sorted().toList();
    }

    private static ObjectNode realm() throws Exception {
        ObjectNode realm = ChainBuilder.object();
        realm.put("realm", REALM);
        realm.put("enabled", true);
        realm.put("sslRequired", "none");

        ArrayNode clients = realm.putArray("clients");
        ObjectNode api = clients.addObject();
        api.put("clientId", API);
        // The API introspects tokens, so it is a confidential client.
        api.put("publicClient", false);
        api.put("secret", CLIENT_SECRET);
        api.put("standardFlowEnabled", false);
        for (String clientId : List.of(
                AGENT,
                ADMIN_AGENT,
                UNLISTED_AGENT,
                LEDGER_AGENT,
                FOREIGN_AGENT,
                FIXED_ROLE_AGENT,
                PUBLIC_AGENT,
                SHARED_AGENT,
                DISABLED_IDP_AGENT,
                STATUS_AGENT,
                KEYS_AGENT,
                UNKNOWN_KEYS_AGENT)) {
            ObjectNode client = clients.addObject();
            client.put("clientId", clientId);
            client.put("publicClient", clientId.equals(PUBLIC_AGENT));
            client.put("secret", CLIENT_SECRET);
            client.put("standardFlowEnabled", false);
            client.put("directAccessGrantsEnabled", false);
            client.putObject("attributes").put("standard.token.exchange.enabled", "true");
            if (clientId.equals(FIXED_ROLE_AGENT)) {
                ArrayNode protocolMappers = client.putArray("protocolMappers");
                ObjectNode fixedRole = protocolMappers.addObject();
                fixedRole.put("name", "fixed role");
                fixedRole.put("protocol", "openid-connect");
                fixedRole.put("protocolMapper", "oidc-hardcoded-role-mapper");
                fixedRole.putObject("config").put("role", API + ".order-creator");
                ObjectNode fixedClaim = protocolMappers.addObject();
                fixedClaim.put("name", "fixed claim");
                fixedClaim.put("protocol", "openid-connect");
                fixedClaim.put("protocolMapper", "oidc-hardcoded-claim-mapper");
                fixedClaim
                        .putObject("config")
                        .put("claim.name", "tenant")
                        .put("claim.value", "acme")
                        .put("access.token.claim", "true");
            }
        }

        ObjectNode roles = realm.putObject("roles");
        ArrayNode apiRoles = roles.putObject("client").putArray(API);
        apiRoles.addObject().put("name", "invoice-approver");
        apiRoles.addObject().put("name", "order-creator");

        ObjectNode carol = realm.putArray("users").addObject();
        carol.put("id", principalSubject(COLLIDING_PRINCIPAL));
        carol.put("username", "carol");
        carol.put("enabled", true);

        JWK issuerKey = headerKey(acme.raw());
        JWK untrustedKey = headerKey(untrusted.raw());
        ArrayNode idps = realm.putArray("identityProviders");
        trustProvider(
                idps,
                "wallet-ca",
                null,
                Map.of("useX509", "true", "trustedCertificates", walletClient.getCaCertificatePem()));
        trustProvider(idps, "wallet-keys", WALLET_ISSUER, jwks(issuerKey, untrustedKey));
        trustProvider(idps, "unnamed-keys", null, jwks(issuerKey));
        trustProvider(idps, "other-issuer-keys", "https://register.crate.example", jwks(issuerKey));
        trustProvider(idps, "disabled-keys", WALLET_ISSUER, jwks(issuerKey)).put("enabled", false);

        Map<String, String> walletCa = Map.of("trustMaterialIdps", "wallet-ca");
        // The certificate of the wallet status list names no issuer. X.509 trust refuses that list,
        // so the status cases trust the keys.
        Map<String, String> walletKeys = Map.of(
                "trustedIssuerJwks",
                JsonSerialization.writeValueAsString(Map.of(
                        WALLET_ISSUER,
                        Map.of(
                                "keys",
                                List.of(
                                        issuerKey,
                                        headerKey(walletClient.getStatusList().strip()))))));
        identityProvider(idps, "delegation", AGENT, Map.of("trustMaterialIdps", "wallet-ca,wallet-keys"));
        identityProvider(idps, "delegation-admin", ADMIN_AGENT, walletCa);
        identityProvider(idps, "delegation-ledger", LEDGER_AGENT, walletCa);
        identityProvider(idps, "delegation-foreign", FOREIGN_AGENT, walletCa);
        identityProvider(idps, "delegation-fixed-role", FIXED_ROLE_AGENT, walletCa);
        identityProvider(idps, "delegation-public", PUBLIC_AGENT, walletCa);
        identityProvider(idps, "delegation-shared-1", SHARED_AGENT, walletCa);
        identityProvider(idps, "delegation-shared-2", SHARED_AGENT, walletCa);
        identityProvider(idps, "delegation-disabled", DISABLED_IDP_AGENT, walletCa)
                .put("enabled", false);
        identityProvider(idps, "delegation-status", STATUS_AGENT, walletKeys);
        identityProvider(idps, "delegation-keys", KEYS_AGENT, Map.of("trustMaterialIdps", "wallet-keys"));
        identityProvider(
                idps,
                "delegation-unknown-keys",
                UNKNOWN_KEYS_AGENT,
                Map.of("trustMaterialIdps", "unnamed-keys,other-issuer-keys,disabled-keys"));

        ArrayNode mappers = realm.putArray("identityProviderMappers");
        for (String alias : List.of(
                "delegation",
                "delegation-ledger",
                "delegation-foreign",
                "delegation-fixed-role",
                "delegation-status",
                "delegation-keys",
                "delegation-unknown-keys")) {
            mapper(
                    mappers,
                    alias,
                    "approve",
                    "delegate-sd-jwt-action-role-mapper",
                    Map.of("action", "invoice.approve", "role", API + ".invoice-approver"));
        }
        mapper(
                mappers,
                "delegation",
                "order",
                "delegate-sd-jwt-action-role-mapper",
                Map.of("action", "order.create", "role", API + ".order-creator"));
        mapper(
                mappers,
                "delegation",
                "limit",
                "delegate-sd-jwt-claim-mapper",
                Map.of("source", "mandate.limit", "claim.name", "approval_limit"));
        mapper(
                mappers,
                "delegation-ledger",
                "limit",
                "delegate-sd-jwt-claim-mapper",
                Map.of("source", "mandate.limit", "claim.name", "approval_limit", "required", "true"));
        mapper(
                mappers,
                "delegation-foreign",
                "fixed role",
                "hardcoded-role-idp-mapper",
                Map.of("role", API + ".order-creator", "syncMode", "INHERIT"));
        mapper(
                mappers,
                "delegation-admin",
                "manage",
                "delegate-sd-jwt-action-role-mapper",
                Map.of("action", "realm.manage", "role", "realm-management.realm-admin"));

        return realm;
    }

    private static Map<String, String> jwks(JWK... keys) throws Exception {
        return Map.of(
                "publicKeySignatureVerifier",
                JsonSerialization.writeValueAsString(Map.of("keys", List.of(keys))),
                "useJwksUrl",
                "false");
    }

    private static ObjectNode trustProvider(ArrayNode idps, String alias, String issuer, Map<String, String> config) {
        ObjectNode idp = idps.addObject();
        idp.put("alias", alias);
        idp.put("providerId", "default-trust");
        idp.put("enabled", true);
        ObjectNode values = idp.putObject("config");
        if (issuer != null) {
            values.put("issuer", issuer);
        }
        config.forEach(values::put);
        return idp;
    }

    private static ObjectNode identityProvider(
            ArrayNode idps, String alias, String clientId, Map<String, String> trust) {
        ObjectNode idp = idps.addObject();
        idp.put("alias", alias);
        idp.put("providerId", "delegate-sd-jwt");
        idp.put("enabled", true);
        ObjectNode config = idp.putObject("config");
        config.put("clients", clientId);
        config.put("principalClaim", "euid_reference");
        config.put("credentialTypes", POA);
        config.put("credentialActionsPath", "authorisation.actions");
        config.put("audiencePath", "mandate.audiences");
        trust.forEach(config::put);
        return idp;
    }

    private static void mapper(ArrayNode mappers, String alias, String name, String type, Map<String, String> config) {
        ObjectNode mapper = mappers.addObject();
        mapper.put("name", name);
        mapper.put("identityProviderAlias", alias);
        mapper.put("identityProviderMapper", type);
        ObjectNode values = mapper.putObject("config");
        config.forEach(values::put);
    }

    private static JsonNode post(String path, Map<String, String> form) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form(form)))
                .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        ObjectNode result = response.body().isBlank() || !response.body().trim().startsWith("{")
                ? ChainBuilder.object()
                : (ObjectNode) JsonSerialization.mapper.readTree(response.body());
        result.put("status", response.statusCode());
        return result;
    }

    private static String form(Map<String, String> values) {
        return values.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }
}
