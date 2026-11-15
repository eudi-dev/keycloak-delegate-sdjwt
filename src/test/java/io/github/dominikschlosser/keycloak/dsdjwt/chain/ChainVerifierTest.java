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

package io.github.dominikschlosser.keycloak.dsdjwt.chain;

import static io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder.AUDIENCE;
import static io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder.NONCE;
import static io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder.NOW;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder;
import io.github.dominikschlosser.keycloak.dsdjwt.TestVectors;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.util.JsonSerialization;

class ChainVerifierTest {

    @BeforeAll
    static void crypto() {
        CryptoIntegration.init(ChainVerifierTest.class.getClassLoader());
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 4})
    void acceptsTheGoVectors(int links) throws Exception {
        JsonNode vector = TestVectors.read("chain-" + links + "-links.json");

        VerifiedChain chain = verifier(
                        TestVectors.jwk(vector.get("issuer_jwk")),
                        vector.get("now").asLong())
                .verify(vector.get("chain").asText(), vector.get("audience").asText());

        assertEquals(links, chain.links().size());
        assertEquals(vector.get("nonce").asText(), chain.nonce());
        assertEquals("DEACME.HRB4711", chain.credential().get("euid_reference").asText());
        List<String> agents = new ArrayList<>();
        chain.links()
                .forEach(link ->
                        agents.add(link.delegatePayload().at("/agent/id").asText()));
        assertEquals(agentsOf(vector), agents);
        assertEquals(
                "Pay supplier invoices of Bolt Supplies B.V.",
                chain.links().get(0).delegatePayload().at("/mandate/purpose").asText());
    }

    @Test
    void refusesTheGoVectorWith5Links() {
        JsonNode vector = TestVectors.read("chain-5-links.json");

        ChainException e = assertThrows(ChainException.class, () -> verifier(
                        TestVectors.jwk(vector.get("issuer_jwk")),
                        vector.get("now").asLong())
                .verify(vector.get("chain").asText(), vector.get("audience").asText()));

        assertEquals("the chain has 5 KB-SD-JWTs, but at most 4 are accepted", e.getMessage());
    }

    @Test
    void acceptsTheGoldenVectorOfEudiBusiness() throws Exception {
        JsonNode vector = TestVectors.read("golden-chain.json");
        JsonNode expected = vector.at("/verifier");

        VerifiedChain chain = verifier(
                        TestVectors.jwk(vector.at("/keys/issuer")),
                        expected.get("time").asLong())
                .verify(vector.get("token").asText(), expected.get("audience").asText());

        assertEquals(expected.get("nonce").asText(), chain.nonce());
        assertEquals(1, chain.links().size());
        assertEquals(
                "DETEST.HRB900001", chain.credential().get("euid_reference").asText());
        assertEquals(
                "order.create",
                chain.links().get(0).delegatePayload().at("/mandate/actions/0").asText());
        assertEquals(
                expected.get("audience").asText(),
                chain.links()
                        .get(0)
                        .delegatePayload()
                        .at("/mandate/audiences/0")
                        .asText());
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 4})
    void acceptsChainsOfTheJavaBuilder(int links) throws Exception {
        ChainBuilder builder = new ChainBuilder().links(links, "invoice.approve");
        builder.link(1).issuerJwtHash = links > 1;

        VerifiedChain chain = verify(builder);

        assertEquals(links, chain.links().size());
        assertEquals(NONCE, chain.nonce());
        assertEquals(NOW + 3600, chain.expiresAt());
    }

    @Test
    void refusesAKbSdJwtThatThePrecedingKeyDidNotSign() {
        assertRefused(
                b -> b.links(2, "invoice.approve").link(2).signer = ChainBuilder.ecKey(),
                "the signature of KB-SD-JWT 2 does not verify with the cnf key of the Delegate Payload of KB-SD-JWT 1");
    }

    @Test
    void refusesAKeyBindingJwtThatTheLastAgentDidNotSign() {
        assertRefused(
                b -> {
                    b.links(2, "invoice.approve");
                    b.keyBindingSigner = b.link(1).agent;
                },
                "the signature of the Key Binding JWT does not verify with the cnf key of the Delegate Payload of the last KB-SD-JWT");
    }

    @Test
    void refusesACredentialFromAnUntrustedIssuer() {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        JWK other = ChainBuilder.publicJwk(ChainBuilder.ecKey());

        ChainException e =
                assertThrows(ChainException.class, () -> verifier(other, NOW).verify(builder.build(), AUDIENCE));

        assertEquals("the signature of the SD-JWT does not verify with a trusted issuer key", e.getMessage());
    }

    @Test
    void refusesWhenNoIssuerKeyIsTrusted() {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        ChainVerifier verifier = new ChainVerifier((header, iss) -> List.of(), clock(NOW));

        ChainException e = assertThrows(ChainException.class, () -> verifier.verify(builder.build(), AUDIENCE));

        assertEquals("no trusted key of the credential issuer was found", e.getMessage());
    }

    @Test
    void refusesATamperedDisclosure() {
        assertRefused(
                b -> {
                    b.links(1, "invoice.approve");
                    String forged = ChainBuilder.disclosure(
                            ChainBuilder.text("c2FsdA"),
                            ChainBuilder.text("euid_reference"),
                            ChainBuilder.text("DEX.HRB1"));
                    b.credentialDisclosureOverride = List.of(forged);
                },
                "the SD-JWT: At least one disclosure is not protected by digest");
    }

    @Test
    void refusesABadSdHashOfAKbSdJwt() {
        assertRefused(
                b -> b.links(2, "invoice.approve").link(2).precedingHash = ChainBuilder.digest("other"),
                "the sd_hash of KB-SD-JWT 2 does not match the preceding component");
    }

    @Test
    void refusesABadIssuerJwtHash() {
        assertRefused(
                b -> {
                    ChainBuilder.Link link = b.links(1, "invoice.approve").link(1);
                    link.issuerJwtHash = true;
                    link.precedingHash = ChainBuilder.digest("other");
                },
                "the issuer_jwt_hash of KB-SD-JWT 1 does not match the preceding component");
    }

    @Test
    void refusesABadSdHashOfTheKeyBindingJwt() {
        assertRefused(
                b -> {
                    b.links(1, "invoice.approve");
                    b.keyBindingSdHash = ChainBuilder.digest("other");
                },
                "the sd_hash of the Key Binding JWT does not match the last KB-SD-JWT");
    }

    @Test
    void refusesAnExpiredDelegatePayload() {
        assertRefused(
                b -> b.links(2, "invoice.approve").link(2).delegatePayload.put("exp", NOW - 61),
                "the Delegate Payload of KB-SD-JWT 2 expired at " + (NOW - 61));
    }

    @Test
    void acceptsAnExpiryWithinTheClockSkew() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        builder.link(1).delegatePayload.put("exp", NOW - 59);

        assertEquals(NOW - 59, verify(builder).expiresAt());
    }

    @Test
    void refusesAnExpiredKbSdJwt() {
        assertRefused(
                b -> b.links(2, "invoice.approve").link(2).claims.put("exp", NOW - 61),
                "KB-SD-JWT 2 expired at " + (NOW - 61));
    }

    @Test
    void refusesAKbSdJwtBeforeItsNbf() {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).claims.put("nbf", NOW + 61),
                "KB-SD-JWT 1 is not valid before " + (NOW + 61));
    }

    @Test
    void refusesAKbSdJwtFromTheFuture() {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).claims.put("iat", NOW + 61),
                "KB-SD-JWT 1 has an iat in the future");
    }

    @Test
    void capsTheChainExpiryAtTheExpOfAKbSdJwt() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        builder.link(1).claims.put("exp", NOW + 600);

        assertEquals(NOW + 600, verify(builder).expiresAt());
    }

    @Test
    void refusesADelegatePayloadBeforeItsNbf() {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).delegatePayload.put("nbf", NOW + 61),
                "the Delegate Payload of KB-SD-JWT 1 is not valid before " + (NOW + 61));
    }

    @Test
    void refusesADelegatePayloadWithoutExp() {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).delegatePayload.remove("exp"),
                "the Delegate Payload of KB-SD-JWT 1 has no exp claim");
    }

    @Test
    void refusesAnExpiredCredential() {
        assertRefused(
                b -> b.links(1, "invoice.approve").credentialClaims.put("exp", NOW - 3600),
                "the SD-JWT expired at " + (NOW - 3600));
    }

    @Test
    void refusesACredentialBeforeItsNbf() {
        assertRefused(
                b -> b.links(1, "invoice.approve").credentialClaims.put("nbf", NOW + 3600),
                "the SD-JWT is not valid before " + (NOW + 3600));
    }

    @Test
    void refusesACredentialFromTheFuture() {
        assertRefused(
                b -> b.links(1, "invoice.approve").credentialClaims.put("iat", NOW + 3600),
                "the SD-JWT has an iat in the future");
    }

    @ParameterizedTest
    @ValueSource(strings = {"aud", "nonce"})
    void refusesAKbSdJwtWithoutAudOrNonce(String claim) {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).claims.remove(claim),
                "KB-SD-JWT 1 has no " + claim + " string");
    }

    @Test
    void refusesAKbSdJwtWithoutAHashOfThePrecedingComponent() {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).withPrecedingHash = false,
                "KB-SD-JWT 1 has neither sd_hash nor issuer_jwt_hash");
    }

    @Test
    void refusesAnEmptyDelegatePayloadArray() {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).delegatePayloadArray =
                        JsonSerialization.mapper.createArrayNode(),
                "KB-SD-JWT 1 has no non-empty delegate_payload array");
    }

    @Test
    void refusesADelegatePayloadThatIsNotAnObject() {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).disclosedDelegatePayload = ChainBuilder.text("pay"),
                "the disclosed delegate_payload element of KB-SD-JWT 1 is not a JSON object");
    }

    @Test
    void refusesAKbSdJwtSignedOnAnotherCurveThanTheCnfKey() {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).signer = ChainBuilder.ecKey("P-384"),
                "KB-SD-JWT 1: the key cannot verify the JWS algorithm ES384");
    }

    @Test
    void refusesAKeyBindingJwtOlderThanTheMaxAge() {
        assertRefused(
                b -> b.links(1, "invoice.approve").keyBindingClaims.put("iat", NOW - 361),
                "the Key Binding JWT is older than 300 seconds");
    }

    @Test
    void refusesAKeyBindingJwtFromTheFuture() {
        assertRefused(
                b -> b.links(1, "invoice.approve").keyBindingClaims.put("iat", NOW + 61),
                "the Key Binding JWT has an iat in the future");
    }

    @Test
    void refusesTheWrongAudience() {
        assertRefused(
                b -> b.links(1, "invoice.approve").keyBindingClaims.put("aud", "https://iam.bolt.example/realms/x"),
                "the Key Binding JWT has aud https://iam.bolt.example/realms/x, expected " + AUDIENCE);
    }

    @Test
    void refusesAKeyBindingJwtWithoutNonce() {
        assertRefused(
                b -> b.links(1, "invoice.approve").keyBindingClaims.remove("nonce"),
                "the Key Binding JWT has no nonce string");
    }

    @Test
    void refusesADsdJwtWithoutKeyBinding() {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        String chain = builder.build();
        String withoutKeyBinding = chain.substring(0, chain.lastIndexOf('~') + 1);

        ChainException e = assertThrows(
                ChainException.class, () -> verifier(builder.issuerJwk(), NOW).verify(withoutKeyBinding, AUDIENCE));

        assertEquals("subject_token is a dSD-JWT without Key Binding, expected a dSD-JWT+KB", e.getMessage());
    }

    @Test
    void refusesAPlainSdJwt() {
        ChainBuilder builder = new ChainBuilder();

        ChainException e = assertThrows(
                ChainException.class, () -> verifier(builder.issuerJwk(), NOW).verify(builder.build(), AUDIENCE));

        assertEquals("subject_token has no KB-SD-JWT, so it is not a Delegate SD-JWT", e.getMessage());
    }

    @Test
    void refusesTwoEmptyComponentsBetweenParts() {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        String chain = builder.build().replaceFirst("~~", "~~~");

        ChainException e = assertThrows(
                ChainException.class, () -> verifier(builder.issuerJwk(), NOW).verify(chain, AUDIENCE));

        assertEquals("more than 1 empty component separates 2 parts of the chain", e.getMessage());
    }

    @Test
    void refusesAKbSdJwtWithoutKeyBindingType() {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).type = "kb+sd-jwt",
                "KB-SD-JWT 1 has typ kb+sd-jwt, expected kb-sd-jwt+kb");
    }

    @Test
    void refusesADelegatePayloadWithoutCnf() {
        assertRefused(
                b -> b.links(1, "invoice.approve").link(1).withCnf = false,
                "the Delegate Payload of KB-SD-JWT 1 has no cnf claim with a jwk");
    }

    @Test
    void refusesADelegatePayloadArrayWithAPlainSecondElement() {
        assertRefused(
                b -> b.links(1, "invoice.approve")
                        .link(1)
                        .extraElements
                        .add(ChainBuilder.object().put("vct", "x")),
                "KB-SD-JWT 1 has a delegate_payload with more than 1 element that is not a digest");
    }

    @ParameterizedTest
    @ValueSource(strings = {"none", "HS256"})
    void refusesAKeyBindingJwtWithAnUnacceptedAlgorithm(String alg) throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        String chain = builder.build();
        int start = chain.lastIndexOf('~') + 1;
        String[] parts = chain.substring(start).split("\\.", -1);
        String header =
                Base64Url.encode(("{\"alg\":\"" + alg + "\",\"typ\":\"kb+jwt\"}").getBytes(StandardCharsets.UTF_8));
        String signature = "none".equals(alg) ? "" : parts[2];
        String forged = chain.substring(0, start) + header + "." + parts[1] + "." + signature;

        ChainException e = assertThrows(
                ChainException.class, () -> verifier(builder.issuerJwk(), NOW).verify(forged, AUDIENCE));

        assertEquals("the Key Binding JWT: the JWS algorithm " + alg + " is not accepted", e.getMessage());
    }

    @Test
    void refusesAKeyBindingJwtWithTheWrongType() {
        assertRefused(
                b -> b.links(1, "invoice.approve").keyBindingType = "JWT",
                "the Key Binding JWT has typ JWT, expected kb+jwt");
    }

    @Test
    void refusesAKbSdJwtThatDisclosesTwoDelegatePayloads() {
        assertRefused(
                b -> b.links(1, "invoice.approve")
                        .link(1)
                        .extraDelegatePayloads
                        .add(ChainBuilder.object().put("vct", "urn:eudi-test:business:agent-mandate:1")),
                "KB-SD-JWT 1 must disclose exactly 1 element of delegate_payload");
    }

    @Test
    void refusesAPrivateKeyInCnf() {
        assertRefused(
                b -> {
                    ChainBuilder.Link link = b.links(1, "invoice.approve").link(1);
                    link.withCnf = false;
                    JsonNode jwk = JsonSerialization.mapper.valueToTree(ChainBuilder.publicJwk(link.agent));
                    ((ObjectNode) jwk).put("d", "c2VjcmV0");
                    link.delegatePayload.putObject("cnf").set("jwk", jwk);
                },
                "the Delegate Payload of KB-SD-JWT 1 has a private key in its cnf claim");
    }

    @Test
    void refusesAnRsaKeyShorterThan2048Bits() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        JWK jwk = JWKBuilder.create()
                .rsa((RSAPublicKey) generator.generateKeyPair().getPublic());

        ChainException e = assertThrows(ChainException.class, () -> JwkVerifiers.forKey(jwk, "RS256"));

        assertEquals("the RSA key is shorter than 2048 bits", e.getMessage());
    }

    @Test
    void refusesTheWrongCredentialType() {
        assertRefused(
                b -> b.links(1, "invoice.approve").credentialType = "JWT",
                "the SD-JWT has typ JWT, expected dc+sd-jwt or vc+sd-jwt");
    }

    @ParameterizedTest
    @ValueSource(strings = {"exp", "nbf", "status", "vct#integrity", "aka_vcts"})
    void refusesACredentialThatDisclosesAClaimOfTheSignedPayload(String claim) {
        assertRefused(
                b -> {
                    b.links(1, "invoice.approve");
                    b.credentialClaims.remove(claim);
                    JsonNode value =
                            switch (claim) {
                                case "exp" ->
                                    JsonSerialization.mapper.getNodeFactory().numberNode(NOW + 86400);
                                case "nbf" ->
                                    JsonSerialization.mapper.getNodeFactory().numberNode(NOW - 100);
                                case "vct#integrity" -> ChainBuilder.text("sha256-WmQyMWUxNzgzZjRkMGUyNTY");
                                case "aka_vcts" ->
                                    JsonSerialization.mapper.createArrayNode().add("urn:eudi-test:business:poa:0");
                                default ->
                                    ChainBuilder.object()
                                            .set(
                                                    "status_list",
                                                    ChainBuilder.object()
                                                            .put("idx", 0)
                                                            .put("uri", "https://register.example/status/1"));
                            };
                    b.credentialDisclosures.put(claim, value);
                },
                "the SD-JWT has " + claim + " in a Disclosure, but it must be in the signed payload");
    }

    @ParameterizedTest
    @ValueSource(strings = {"exp", "nbf"})
    void refusesAKbSdJwtThatDisclosesATimeClaim(String claim) {
        assertRefused(
                b -> b.links(1, "invoice.approve")
                        .link(1)
                        .disclosedClaims
                        .put(claim, JsonSerialization.mapper.getNodeFactory().numberNode(NOW + 600)),
                "KB-SD-JWT 1 has " + claim + " in a Disclosure, but it must be in the signed payload");
    }

    @Test
    void refusesACredentialWithoutIss() {
        assertRefused(
                b -> b.links(1, "invoice.approve").credentialClaims.remove("iss"), "the SD-JWT has no iss string");
    }

    @ParameterizedTest
    @ValueSource(strings = {"nbf", "iat", "exp"})
    void refusesADelegatePayloadThatDisclosesATimeClaimInANestedDisclosure(String claim) {
        assertRefused(
                b -> {
                    ChainBuilder.Link link = b.links(1, "invoice.approve").link(1);
                    link.delegatePayload.remove(claim);
                    link.nestedDelegateDisclosures.put(
                            claim, JsonSerialization.mapper.getNodeFactory().numberNode(NOW - 10));
                },
                "the Delegate Payload of KB-SD-JWT 1 has " + claim
                        + " in a nested Disclosure, but it must be in the Delegate Payload itself");
    }

    @Test
    void acceptsADelegatePayloadWithANestedDisclosure() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        builder.link(1).nestedDelegateDisclosures.put("cost_centre", ChainBuilder.text("CC-4711"));

        VerifiedChain chain = verify(builder);

        assertEquals(
                "CC-4711",
                chain.links().get(0).delegatePayload().get("cost_centre").asText());
    }

    @Test
    void reportsAnObjectWithANestedDisclosureTheAgentLeavesOut() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        ChainBuilder.discloseSeparately(limit(builder), "amount");

        VerifiedChain chain = verify(builder);

        assertEquals(
                "{\"currency\":\"EUR\"}",
                chain.links().get(0).delegatePayload().at("/mandate/limit").toString());
        assertEquals(Set.of(List.of("mandate", "limit")), chain.firstWithheld());
    }

    @Test
    void reportsNothingWithheldWhenTheAgentPresentsTheNestedDisclosure() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        builder.link(1).extraDisclosures.add(ChainBuilder.discloseSeparately(limit(builder), "amount"));

        VerifiedChain chain = verify(builder);

        assertEquals(
                "5000.00",
                chain.links()
                        .get(0)
                        .delegatePayload()
                        .at("/mandate/limit/amount")
                        .asText());
        assertEquals(Set.of(), chain.firstWithheld());
    }

    @Test
    void reportsAWithheldDisclosureInsideAPresentedOne() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve");
        ChainBuilder.discloseSeparately(limit(builder), "amount");
        builder.link(1)
                .extraDisclosures
                .add(ChainBuilder.discloseSeparately(
                        builder.link(1).delegatePayload.withObjectProperty("mandate"), "limit"));

        VerifiedChain chain = verify(builder);

        assertEquals(Set.of(List.of("mandate", "limit")), chain.firstWithheld());
    }

    @Test
    void reportsAnArrayWithAnElementTheAgentLeavesOut() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice.approve", "invoice.read");
        ChainBuilder.discloseSeparately(
                builder.link(1).delegatePayload.withObjectProperty("mandate").withArray("actions"), 1);

        VerifiedChain chain = verify(builder);

        assertEquals(
                "[\"invoice.approve\"]",
                chain.links().get(0).delegatePayload().at("/mandate/actions").toString());
        assertEquals(Set.of(List.of("mandate", "actions")), chain.firstWithheld());
    }

    @Test
    void refusesAnUnacceptedSdAlg() {
        assertRefused(
                b -> b.links(1, "invoice.approve").credentialSdAlg = "md5",
                "the SD-JWT has the _sd_alg md5, which is not accepted");
    }

    @Test
    void refusesAnOversizedToken() {
        ChainException e = assertThrows(ChainException.class, () -> verifier(new ChainBuilder().issuerJwk(), NOW)
                .verify("a".repeat(ChainVerifier.MAX_TOKEN_LENGTH + 1), AUDIENCE));

        assertTrue(e.getMessage().startsWith("subject_token is longer than"));
    }

    private static void assertRefused(Consumer<ChainBuilder> breaker, String message) {
        ChainBuilder builder = new ChainBuilder();
        breaker.accept(builder);

        ChainException e = assertThrows(ChainException.class, () -> verify(builder));

        assertEquals(message, e.getMessage());
    }

    private static VerifiedChain verify(ChainBuilder builder) throws ChainException {
        return verifier(builder.issuerJwk(), NOW).verify(builder.build(), AUDIENCE);
    }

    private static ObjectNode limit(ChainBuilder builder) {
        return builder.link(1).delegatePayload.withObjectProperty("mandate").withObjectProperty("limit");
    }

    static ChainVerifier verifier(JWK issuer, long now) {
        return new ChainVerifier(
                (header, iss) -> List.of(JwkVerifiers.forKey(issuer, header.getRawAlgorithm())), clock(now));
    }

    static Clock clock(long now) {
        return Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC);
    }

    private static List<String> agentsOf(JsonNode vector) {
        List<String> agents = new ArrayList<>();
        vector.get("agents").forEach(agent -> agents.add(agent.asText()));
        return agents;
    }
}
