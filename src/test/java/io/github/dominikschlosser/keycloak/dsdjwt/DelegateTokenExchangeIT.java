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
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
import org.keycloak.util.JsonSerialization;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.MountableFile;

/** Runs the token exchange against Keycloak with the provider JAR installed. */
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
    private static final String X509_AGENT = "x509-agent";
    private static final int NONCE_LIFESPAN = 10;
    private static final String UNREACHABLE_STATUS_LIST = "https://localhost:1/status/1";
    private static final String API = "invoice-api";
    private static final String CLIENT_SECRET = UUID.randomUUID().toString();
    private static final KeyWrapper ISSUER = ChainBuilder.ecKey();
    private static final TestCertificates ISSUER_CA = new TestCertificates("Register CA");
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    private static GenericContainer<?> keycloak;
    private static StatusListServer statusList;
    private static String baseUrl;
    private static String realmIssuer;
    private static final String COLLIDING_PRINCIPAL = "BOLT.HRB9";

    @BeforeAll
    @SuppressWarnings("resource")
    static void startKeycloak() throws Exception {
        CryptoIntegration.init(DelegateTokenExchangeIT.class.getClassLoader());
        statusList = new StatusListServer("host.testcontainers.internal", ISSUER);
        Testcontainers.exposeHostPorts(statusList.port());
        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:" + System.getProperty("keycloak.version"))
                .withCopyFileToContainer(
                        MountableFile.forHostPath(System.getProperty("provider.jar")),
                        "/opt/keycloak/providers/keycloak-delegate-sdjwt.jar")
                .withCopyToContainer(
                        Transferable.of(JsonSerialization.writeValueAsBytes(realm())),
                        "/opt/keycloak/data/import/" + REALM + ".json")
                .withCopyToContainer(Transferable.of(statusList.certificatePem()), "/opt/keycloak/conf/status-list.pem")
                .withCommand(
                        "start-dev",
                        "--import-realm",
                        "--features=oid4vc-vci",
                        "--truststore-paths=/opt/keycloak/conf/status-list.pem",
                        "--spi-realm-restapi-extension--delegate-sd-jwt--nonce-lifespan=" + NONCE_LIFESPAN)
                .withExposedPorts(8080)
                .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).withStartupTimeout(Duration.ofMinutes(4)));
        keycloak.start();
        baseUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        realmIssuer = baseUrl + "/realms/" + REALM;
    }

    @AfterAll
    static void stopKeycloak() {
        if (keycloak != null) {
            keycloak.stop();
        }
        if (statusList != null) {
            statusList.close();
        }
    }

    @Test
    void exchangesChainForTokenWithRolesClaimsAndActor() throws Exception {
        for (int links : new int[] {1, 2, 4}) {
            ChainBuilder chain = chain(AGENT).links(links, "invoice.approve", "order.create");

            JsonNode response = exchange(AGENT, chain.build(), Map.of());

            assertEquals(200, response.get("status").asInt(), response.toString());
            assertEquals(
                    "urn:ietf:params:oauth:token-type:access_token",
                    response.get("issued_token_type").asText());
            assertEquals("Bearer", response.get("token_type").asText());
            assertFalse(response.has("refresh_token"), response.toString());
            assertFalse(response.has("id_token"), response.toString());
            JsonNode token = claims(response.get("access_token").asText());
            assertEquals(realmIssuer, token.get("iss").asText());
            assertEquals(principalSubject(), token.get("sub").asText());
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
            assertTrue(token.get("exp").asLong() <= chain.now + 3600);
        }
    }

    @Test
    void grantsOnlyRolesOfDelegatedActions() throws Exception {
        JsonNode response = exchange(
                AGENT, chain(AGENT).links(1, "invoice.approve", "fleet.sell").build(), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        JsonNode token = claims(response.get("access_token").asText());
        assertEquals(List.of(API), fieldNames(token.get("resource_access")));
        assertEquals(List.of("invoice-approver"), sorted(token.at("/resource_access/" + API + "/roles")));
        assertFalse(token.has("realm_access"), token.toString());
    }

    @Test
    void ignoresProtocolMappersOfTheClient() throws Exception {
        JsonNode response = exchange(
                FIXED_ROLE_AGENT,
                chain(FIXED_ROLE_AGENT).links(1, "invoice.approve").build(),
                Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        JsonNode token = claims(response.get("access_token").asText());
        assertEquals(List.of("invoice-approver"), sorted(token.at("/resource_access/" + API + "/roles")));
        assertFalse(token.has("tenant"), token.toString());
    }

    @Test
    void grantsOnlyActionsTheCredentialAllows() throws Exception {
        ChainBuilder chain = chain(AGENT).links(1, "invoice.approve", "order.create");
        chain.credentialActions.removeAll().add("order.create");

        JsonNode response = exchange(AGENT, chain.build(), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        JsonNode token = claims(response.get("access_token").asText());
        assertEquals(List.of("order-creator"), sorted(token.at("/resource_access/" + API + "/roles")));
    }

    @Test
    void issuesTokenForRequestedAudience() throws Exception {
        JsonNode response =
                exchange(AGENT, chain(AGENT).links(1, "invoice.approve").build(), Map.of("audience", API));

        assertEquals(200, response.get("status").asInt(), response.toString());
        JsonNode audience = claims(response.get("access_token").asText()).get("aud");
        assertEquals(API, audience.isArray() ? audience.get(0).asText() : audience.asText());
    }

    @Test
    void refusesAudienceTheDelegationGrantsNoRoleOf() throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT).links(1, "invoice.approve").build(), Map.of("audience", LEDGER_AGENT)),
                400,
                "invalid_request",
                "the delegation grants no role of the audience " + LEDGER_AGENT);
    }

    @Test
    void refusesMapperThatCannotMapADelegation() throws Exception {
        assertRefused(
                exchange(
                        FOREIGN_AGENT,
                        chain(FOREIGN_AGENT).links(1, "invoice.approve").build(),
                        Map.of()),
                500,
                "server_error",
                "the Delegate SD-JWT identity provider is misconfigured: the mapper fixed role of type"
                        + " hardcoded-role-idp-mapper cannot map a delegation");
    }

    @Test
    void introspectionReportsTheTokenInactive() throws Exception {
        JsonNode response =
                exchange(AGENT, chain(AGENT).links(1, "invoice.approve").build(), Map.of());
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
        JsonNode exchanged =
                exchange(AGENT, chain(AGENT).links(1, "invoice.approve").build(), Map.of());
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
        ChainBuilder chain = chain(AGENT).links(1, "invoice.approve");
        chain.credentialDisclosures.put("euid_reference", ChainBuilder.text(COLLIDING_PRINCIPAL));

        JsonNode response = exchange(AGENT, chain.build(), Map.of());

        assertRefused(response, 500, "server_error", null);
        assertTrue(response.get("error_description").asText().contains("own roles"), response.toString());
    }

    @Test
    void capsTokenLifetimeAtChainExpiry() throws Exception {
        ChainBuilder chain = chain(AGENT).links(1, "invoice.approve");
        chain.link(1).delegatePayload.put("exp", chain.now + 60);

        JsonNode response = exchange(AGENT, chain.build(), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        assertTrue(response.get("expires_in").asLong() <= 60, response.toString());
        assertTrue(claims(response.get("access_token").asText()).get("exp").asLong() <= chain.now + 60);
    }

    @Test
    void refusesMalformedSubjectTokens() throws Exception {
        String chain = chain(AGENT).links(1, "invoice.approve").build();
        String[] parts = chain.split("~", -1);
        parts[1] = "!!not-base64!!";

        for (String token : List.of("x", "a.b.c~", String.join("~", parts))) {
            assertRefused(exchange(AGENT, token, Map.of()), 400, "invalid_request", null);
        }
    }

    @Test
    void refusesCredentialWithUnreachableStatusList() throws Exception {
        ChainBuilder chain = chain(AGENT).links(1, "invoice.approve");
        statusListEntry(chain, UNREACHABLE_STATUS_LIST, 7);

        assertRefused(
                exchange(AGENT, chain.build(), Map.of()),
                400,
                "invalid_request",
                "the status list at " + UNREACHABLE_STATUS_LIST + " could not be loaded");
    }

    @Test
    void refusesInvalidCredential() throws Exception {
        ChainBuilder chain = chain(AGENT).links(1, "invoice.approve");
        statusListEntry(chain, statusList.uri(), StatusListServer.INVALID_INDEX);

        assertRefused(
                exchange(AGENT, chain.build(), Map.of()),
                400,
                "invalid_request",
                "the credential is invalid (status 1)");
    }

    @Test
    void acceptsCredentialWithValidStatus() throws Exception {
        ChainBuilder chain = chain(AGENT).links(1, "invoice.approve");
        statusListEntry(chain, statusList.uri(), StatusListServer.VALID_INDEX);

        JsonNode response = exchange(AGENT, chain.build(), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
    }

    @Test
    void refusesReplayedNonce() throws Exception {
        String chain = chain(AGENT).links(1, "invoice.approve").build();

        assertEquals(200, exchange(AGENT, chain, Map.of()).get("status").asInt());
        assertRefused(
                exchange(AGENT, chain, Map.of()),
                400,
                "invalid_request",
                "the nonce of the Key Binding JWT is unknown, expired, already used or issued to another client");
    }

    @Test
    void refusesExpiredNonce() throws Exception {
        String chain = chain(AGENT).links(1, "invoice.approve").build();

        Thread.sleep(Duration.ofSeconds(NONCE_LIFESPAN + 2));

        assertRefused(
                exchange(AGENT, chain, Map.of()),
                400,
                "invalid_request",
                "the nonce of the Key Binding JWT is unknown, expired, already used or issued to another client");
    }

    @Test
    void refusesNonceOfAnotherClientAndKeepsItForItsOwner() throws Exception {
        String nonce = nonce(LEDGER_AGENT);
        ChainBuilder chain = chain(AGENT).links(1, "invoice.approve");
        chain.keyBindingClaims.put("nonce", nonce);

        assertRefused(
                exchange(AGENT, chain.build(), Map.of()),
                400,
                "invalid_request",
                "the nonce of the Key Binding JWT is unknown, expired, already used or issued to another client");
        ChainBuilder own = new ChainBuilder(now(), realmIssuer, nonce, ISSUER).links(1, "invoice.approve");
        assertEquals(
                200, exchange(LEDGER_AGENT, own.build(), Map.of()).get("status").asInt());
    }

    @Test
    void keepsTheNonceWhenTheChainHidesThePrincipal() throws Exception {
        String nonce = nonce(AGENT);
        ChainBuilder hidden = new ChainBuilder(now(), realmIssuer, nonce, ISSUER).links(1, "invoice.approve");
        hidden.credentialDisclosures.remove("euid_reference");

        assertRefused(
                exchange(AGENT, hidden.build(), Map.of()),
                400,
                "invalid_request",
                "the credential has no text claim euid_reference for the principal");
        ChainBuilder shown = new ChainBuilder(now(), realmIssuer, nonce, ISSUER).links(1, "invoice.approve");
        assertEquals(200, exchange(AGENT, shown.build(), Map.of()).get("status").asInt());
    }

    @Test
    void refusesADelegationWithoutTheValueOfARequiredClaimMapper() throws Exception {
        ChainBuilder chain = chain(LEDGER_AGENT).links(1, "invoice.approve");
        chain.link(1).delegatePayload.withObjectProperty("mandate").remove("limit");

        assertRefused(
                exchange(LEDGER_AGENT, chain.build(), Map.of()),
                400,
                "invalid_request",
                "the first Delegate Payload has no mandate.limit, which mapper limit requires");
    }

    @Test
    void refusesARequiredValueWhoseNestedDisclosureTheAgentLeavesOut() throws Exception {
        ChainBuilder chain = chain(LEDGER_AGENT).links(1, "invoice.approve");
        ChainBuilder.discloseSeparately(
                chain.link(1).delegatePayload.withObjectProperty("mandate").withObjectProperty("limit"), "amount");

        assertRefused(
                exchange(LEDGER_AGENT, chain.build(), Map.of()),
                400,
                "invalid_request",
                "the first Delegate Payload has no mandate.limit, which mapper limit requires");
    }

    @Test
    void mapsARequiredValueWithItsNestedDisclosure() throws Exception {
        ChainBuilder chain = chain(LEDGER_AGENT).links(1, "invoice.approve");
        chain.link(1)
                .extraDisclosures
                .add(ChainBuilder.discloseSeparately(
                        chain.link(1)
                                .delegatePayload
                                .withObjectProperty("mandate")
                                .withObjectProperty("limit"),
                        "amount"));

        JsonNode response = exchange(LEDGER_AGENT, chain.build(), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        assertEquals(
                "2500.00",
                claims(response.get("access_token").asText())
                        .at("/approval_limit/amount")
                        .asText());
    }

    @Test
    void acceptsAnIssuerCertificateThatNamesTheIssuer() throws Exception {
        KeyWrapper key = ChainBuilder.ecKey();
        ChainBuilder chain = new ChainBuilder(now(), realmIssuer, nonce(X509_AGENT), key).links(1, "invoice.approve");
        chain.credentialX5c =
                List.of(ISSUER_CA.issue("Acme Logistics GmbH", key, TestCertificates.uri("https://register.example")));

        JsonNode response = exchange(X509_AGENT, chain.build(), Map.of());

        assertEquals(200, response.get("status").asInt(), response.toString());
        assertEquals(
                principalSubject(),
                claims(response.get("access_token").asText()).get("sub").asText());
    }

    @Test
    void refusesUntrustedIssuer() throws Exception {
        ChainBuilder chain = new ChainBuilder(now(), realmIssuer, nonce(AGENT)).links(1, "invoice.approve");

        assertRefused(
                exchange(AGENT, chain.build(), Map.of()),
                400,
                "invalid_request",
                "the SD-JWT: Invalid Issuer-Signed JWT: Signature could not be verified");
    }

    @Test
    void refusesDelegationWithoutMappedAction() throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT).links(1, "fleet.sell").build(), Map.of()),
                400,
                "invalid_request",
                "the delegation allows no action that a mapper grants a role for");
    }

    @ParameterizedTest
    @ValueSource(strings = {"openid", "profile"})
    void refusesScope(String scope) throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT).links(1, "invoice.approve").build(), Map.of("scope", scope)),
                400,
                "invalid_scope",
                "the parameter scope is not supported with a Delegate SD-JWT");
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"urn:ietf:params:oauth:token-type:refresh_token", "urn:ietf:params:oauth:token-type:id_token"})
    void refusesOtherTokenTypesThanAccessToken(String type) throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT).links(1, "invoice.approve").build(), Map.of("requested_token_type", type)),
                400,
                "invalid_request",
                "the requested_token_type " + type + " is not supported with a Delegate SD-JWT");
    }

    @ParameterizedTest
    @ValueSource(strings = {"actor_token", "requested_subject", "requested_issuer", "subject_issuer"})
    void refusesParametersTheChainReplaces(String parameter) throws Exception {
        assertRefused(
                exchange(AGENT, chain(AGENT).links(1, "invoice.approve").build(), Map.of(parameter, "x")),
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

        ChainBuilder chain = new ChainBuilder(now(), realmIssuer, "unused", ISSUER).links(1, "invoice.approve");
        assertRefused(
                exchange(PUBLIC_AGENT, chain.build(), Map.of()),
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
        JsonNode response = exchange(
                ADMIN_AGENT, chain(ADMIN_AGENT).links(1, "realm.manage").build(), Map.of());

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

    private static ChainBuilder chain(String clientId) throws Exception {
        return new ChainBuilder(now(), realmIssuer, nonce(clientId), ISSUER);
    }

    private static String principalSubject() {
        return principalSubject(ChainBuilder.PRINCIPAL);
    }

    private static String principalSubject(String principal) {
        return UUID.nameUUIDFromBytes(("https://register.example|" + principal).getBytes(StandardCharsets.UTF_8))
                .toString();
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    private static void statusListEntry(ChainBuilder chain, String uri, int index) {
        chain.credentialClaims
                .putObject("status")
                .putObject("status_list")
                .put("idx", index)
                .put("uri", uri);
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
                X509_AGENT)) {
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

        ObjectNode colliding = realm.putArray("users").addObject();
        colliding.put("id", principalSubject(COLLIDING_PRINCIPAL));
        colliding.put("username", "carol");
        colliding.put("enabled", true);

        String jwks = JsonSerialization.writeValueAsString(
                Map.of("https://register.example", Map.of("keys", List.of(ChainBuilder.publicJwk(ISSUER)))));
        ArrayNode idps = realm.putArray("identityProviders");
        identityProvider(idps, "delegation", AGENT, jwks, Map.of());
        identityProvider(idps, "delegation-admin", ADMIN_AGENT, jwks, Map.of());
        identityProvider(idps, "delegation-ledger", LEDGER_AGENT, jwks, Map.of());
        identityProvider(idps, "delegation-foreign", FOREIGN_AGENT, jwks, Map.of());
        identityProvider(idps, "delegation-fixed-role", FIXED_ROLE_AGENT, jwks, Map.of());
        identityProvider(idps, "delegation-public", PUBLIC_AGENT, jwks, Map.of());
        identityProvider(idps, "delegation-shared-1", SHARED_AGENT, jwks, Map.of());
        identityProvider(idps, "delegation-shared-2", SHARED_AGENT, jwks, Map.of());
        identityProvider(idps, "delegation-disabled", DISABLED_IDP_AGENT, jwks, Map.of());
        ((ObjectNode) idps.get(idps.size() - 1)).put("enabled", false);
        ObjectNode issuerCa = idps.addObject();
        issuerCa.put("alias", "issuer-ca");
        issuerCa.put("providerId", "default-trust");
        issuerCa.put("enabled", true);
        issuerCa.putObject("config").put("useX509", "true").put("trustedCertificates", ISSUER_CA.pem());
        identityProvider(idps, "delegation-x509", X509_AGENT, null, Map.of("trustMaterialIdps", "issuer-ca"));

        ArrayNode mappers = realm.putArray("identityProviderMappers");
        for (String alias : List.of(
                "delegation", "delegation-ledger", "delegation-foreign", "delegation-fixed-role", "delegation-x509")) {
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

    private static void identityProvider(
            ArrayNode idps, String alias, String clientId, String jwks, Map<String, String> extra) {
        ObjectNode idp = idps.addObject();
        idp.put("alias", alias);
        idp.put("providerId", "delegate-sd-jwt");
        idp.put("enabled", true);
        ObjectNode config = idp.putObject("config");
        config.put("clients", clientId);
        if (jwks != null) {
            config.put("trustedIssuerJwks", jwks);
        }
        config.put("principalClaim", "euid_reference");
        config.put("credentialTypes", "urn:eudi-test:business:poa:1");
        config.put("credentialActionsPath", "authorisation.actions");
        config.put("audiencePath", "mandate.audiences");
        extra.forEach(config::put);
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
