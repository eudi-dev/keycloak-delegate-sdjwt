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

package io.github.dominikschlosser.keycloak.dsdjwt.delegation;

import static io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder.AUDIENCE;
import static io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder.NOW;
import static io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder.PRINCIPAL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dominikschlosser.keycloak.dsdjwt.ChainBuilder;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainVerifier;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.JwkVerifiers;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;

class DelegationReaderTest {

    private static final ClaimPath AUDIENCES = ClaimPath.parse("mandate.audiences");
    private static final Set<String> CREDENTIAL_TYPES = Set.of("urn:eudi-test:business:poa:1");

    @BeforeAll
    static void crypto() {
        CryptoIntegration.init(DelegationReaderTest.class.getClassLoader());
    }

    @Test
    void readsPrincipalActionsAndActorOfTwoLinks() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice:pay", "order:create");
        builder.links(1, "invoice:pay", "report:read");

        Delegation delegation = read(builder, settings(AUDIENCES, CREDENTIAL_TYPES, Set.of()));

        assertEquals("https://register.example", delegation.issuer());
        assertEquals(PRINCIPAL, delegation.principal());
        assertEquals(Set.of("invoice:pay"), delegation.actions());
        assertEquals(
                Map.of(
                        "sub",
                        "urn:eudi-test:agent:procurement-2",
                        "act",
                        Map.of("sub", "urn:eudi-test:agent:procurement-1")),
                delegation.actor());
        assertEquals(NOW + 3600, delegation.expiresAt());
        assertEquals(2, delegation.delegatePayloads().size());
    }

    @Test
    void acceptsSingleTextAction() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice:pay");
        builder.link(1).delegatePayload.withObjectProperty("mandate").put("actions", "invoice:pay");

        assertEquals(Set.of("invoice:pay"), read(builder, defaults()).actions());
    }

    @Test
    void treatsMissingActionsAsNone() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice:pay");
        builder.link(1).delegatePayload.withObjectProperty("mandate").remove("actions");

        assertEquals(Set.of(), read(builder, defaults()).actions());
    }

    @Test
    void keepsOnlyTheActionsTheCredentialAllows() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice:pay", "order:create");
        builder.credentialActions.removeAll().add("invoice:pay");

        assertEquals(Set.of("invoice:pay"), read(builder, defaults()).actions());
    }

    @Test
    void treatsMissingCredentialActionsAsNone() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice:pay");
        builder.credentialDisclosures.remove("authorisation");

        assertEquals(Set.of(), read(builder, defaults()).actions());
    }

    @Test
    void refusesActionsThatAreNotTexts() {
        ChainBuilder builder = new ChainBuilder().links(1);
        builder.link(1)
                .delegatePayload
                .withObjectProperty("mandate")
                .putArray("actions")
                .add(7);

        ChainException e = assertThrows(ChainException.class, () -> read(builder, defaults()));

        assertEquals(
                "the Delegate Payload of KB-SD-JWT 1 has a mandate.actions with an element that is not a text",
                e.getMessage());
    }

    @Test
    void usesKeyThumbprintWithoutAgentId() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice:pay");
        builder.link(1).delegatePayload.remove("agent");

        Delegation delegation = read(builder, defaults());

        assertEquals(
                JwkVerifiers.thumbprintUri(ChainBuilder.publicJwk(builder.link(1).agent)),
                delegation.actor().get("sub"));
    }

    @Test
    void refusesMissingPrincipal() {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice:pay");
        builder.credentialDisclosures.remove("euid_reference");

        ChainException e = assertThrows(ChainException.class, () -> read(builder, defaults()));

        assertEquals("the credential has no text claim euid_reference for the principal", e.getMessage());
    }

    @Test
    void refusesDelegatePayloadWithoutRealmAudience() {
        ChainBuilder builder = new ChainBuilder().links(2, "invoice:pay");
        builder.link(2)
                .delegatePayload
                .withObjectProperty("mandate")
                .putArray("audiences")
                .add("https://erp.bolt.example");

        ChainException e = assertThrows(
                ChainException.class, () -> read(builder, settings(AUDIENCES, CREDENTIAL_TYPES, Set.of())));

        assertEquals(
                "the Delegate Payload of KB-SD-JWT 2 does not list " + AUDIENCE + " in mandate.audiences",
                e.getMessage());
    }

    @Test
    void skipsAudienceCheckWithoutAudiencePath() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice:pay");
        builder.link(1).delegatePayload.withObjectProperty("mandate").remove("audiences");

        assertEquals(Set.of("invoice:pay"), read(builder, defaults()).actions());
    }

    @Test
    void refusesUnacceptedCredentialType() {
        ChainBuilder builder = new ChainBuilder().links(1, "invoice:pay");

        ChainException e = assertThrows(
                ChainException.class,
                () -> read(builder, settings(null, Set.of("urn:eudi-test:business:lpid:1"), Set.of())));

        assertEquals("the credential has vct \"urn:eudi-test:business:poa:1\", which is not accepted", e.getMessage());
    }

    @Test
    void refusesUnacceptedDelegatePayloadType() {
        ChainBuilder builder = new ChainBuilder().links(2, "invoice:pay");
        builder.link(2).delegatePayload.put("vct", "urn:eudi-test:business:other:1");

        ChainException e = assertThrows(
                ChainException.class,
                () -> read(
                        builder, settings(null, CREDENTIAL_TYPES, Set.of("urn:eudi-test:business:agent-mandate:1"))));

        assertEquals(
                "the Delegate Payload of KB-SD-JWT 2 has vct \"urn:eudi-test:business:other:1\", which is not accepted",
                e.getMessage());
    }

    @Test
    void claimTakesTheValueOfTheFirstLink() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(2, "invoice:pay");
        builder.link(2).delegatePayload.withObjectProperty("mandate").remove("limit");

        Delegation delegation = read(builder, defaults());

        assertEquals(
                "5000.00",
                delegation
                        .claim(ClaimPath.parse("mandate.limit.amount"))
                        .orElseThrow()
                        .textValue());
        assertEquals(Optional.empty(), delegation.claim(ClaimPath.parse("mandate.limit.cap")));
    }

    @Test
    void claimRefusesALaterLinkWithAnotherValue() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(2, "invoice:pay");
        ((ObjectNode) builder.link(2)
                        .delegatePayload
                        .withObjectProperty("mandate")
                        .get("limit"))
                .put("amount", "9000.00");

        Delegation delegation = read(builder, defaults());

        ChainException e =
                assertThrows(ChainException.class, () -> delegation.claim(ClaimPath.parse("mandate.limit.amount")));
        assertEquals(
                "the Delegate Payload of KB-SD-JWT 2 has another value for mandate.limit.amount than the first link",
                e.getMessage());
    }

    @Test
    void claimRefusesALaterLinkThatAddsTheClaim() throws Exception {
        ChainBuilder builder = new ChainBuilder().links(2, "invoice:pay");
        builder.link(1).delegatePayload.withObjectProperty("mandate").remove("limit");

        Delegation delegation = read(builder, defaults());

        ChainException e =
                assertThrows(ChainException.class, () -> delegation.claim(ClaimPath.parse("mandate.limit.amount")));
        assertEquals(
                "the Delegate Payload of KB-SD-JWT 2 has another value for mandate.limit.amount than the first link",
                e.getMessage());
    }

    private static DelegationReader.Settings defaults() {
        return settings(null, CREDENTIAL_TYPES, Set.of());
    }

    private static DelegationReader.Settings settings(
            ClaimPath audiences, Set<String> credentialTypes, Set<String> delegateTypes) {
        return new DelegationReader.Settings(
                ClaimPath.parse("euid_reference"),
                ClaimPath.parse("authorisation.actions"),
                ClaimPath.parse("mandate.actions"),
                ClaimPath.parse("agent.id"),
                audiences,
                credentialTypes,
                delegateTypes,
                AUDIENCE);
    }

    private static Delegation read(ChainBuilder builder, DelegationReader.Settings settings) throws ChainException {
        ChainVerifier verifier = new ChainVerifier(
                (header, iss) -> List.of(JwkVerifiers.forKey(builder.issuerJwk(), header.getRawAlgorithm())),
                Clock.fixed(Instant.ofEpochSecond(builder.now), ZoneOffset.UTC));
        return new DelegationReader(settings).read(verifier.verify(builder.build(), AUDIENCE));
    }
}
