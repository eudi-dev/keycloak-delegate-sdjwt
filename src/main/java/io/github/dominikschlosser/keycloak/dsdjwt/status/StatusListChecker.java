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

package io.github.dominikschlosser.keycloak.dsdjwt.status;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.ChainException;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.IssuerKeyResolver;
import io.github.dominikschlosser.keycloak.dsdjwt.chain.NumericDates;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.OptionalLong;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.util.JsonSerialization;

/** Checks the Token Status List entry of a credential (draft-ietf-oauth-status-list-21). */
public final class StatusListChecker {

    private static final int MAX_LIST_SIZE = 16 * 1024 * 1024;

    private final StatusListFetcher fetcher;
    private final IssuerKeyResolver trust;
    private final Clock clock;
    private final Duration clockSkew;

    public StatusListChecker(StatusListFetcher fetcher, IssuerKeyResolver trust, Clock clock, Duration clockSkew) {
        this.fetcher = fetcher;
        this.trust = trust;
        this.clock = clock;
        this.clockSkew = clockSkew;
    }

    /**
     * Refuses a credential whose status is not VALID. A credential without a status claim passes,
     * because its trusted issuer signed it without one.
     */
    public void check(JsonNode credential) throws ChainException {
        JsonNode status = credential.get("status");
        if (status == null) {
            return;
        }
        // §6.2: a Referenced Token in JOSE has status.status_list with idx and uri.
        JsonNode reference = status.get("status_list");
        if (reference == null || !reference.isObject()) {
            throw new ChainException("the credential has a status claim without status_list");
        }
        JsonNode uri = reference.get("uri");
        JsonNode index = reference.get("idx");
        if (uri == null
                || !uri.isTextual()
                || index == null
                || !index.canConvertToInt()
                || !index.isIntegralNumber()
                || index.intValue() < 0) {
            throw new ChainException("the status_list of the credential needs a uri and a whole number idx");
        }
        String location = uri.textValue();
        if (!"https".equalsIgnoreCase(schemeOf(location))) {
            throw new ChainException("the status list URI " + location + " does not use https");
        }
        int value = statusValue(
                fetcher.fetch(location),
                location,
                index.intValue(),
                credential.get("iss").textValue());
        switch (value) {
            case 0 -> {}
            case 1 -> throw new ChainException("the credential is invalid (status 1)");
            case 2 -> throw new ChainException("the issuer has suspended the credential (status 2)");
            default -> throw new ChainException("the status list gives the credential the status " + value);
        }
    }

    private int statusValue(String token, String uri, int index, String credentialIssuer) throws ChainException {
        JWSInput jws;
        JsonNode claims;
        try {
            jws = new JWSInput(token);
            claims = JsonSerialization.mapper.readTree(jws.getContent());
        } catch (Exception e) {
            throw new ChainException("the status list token at " + uri + " is not a JWT", e);
        }
        // §5.1: the typ header is statuslist+jwt and sub equals the URI of the Referenced Token.
        if (!"statuslist+jwt".equals(jws.getHeader().getType())) {
            throw new ChainException(
                    "the status list token has typ " + jws.getHeader().getType() + ", expected statuslist+jwt");
        }
        // §5.1 does not require iss. Only the keys of the credential issuer may sign the list, one of the options of
        // §11.3.
        JsonNode tokenIssuer = claims.get("iss");
        if (tokenIssuer != null
                && !(tokenIssuer.isTextual() && tokenIssuer.textValue().equals(credentialIssuer))) {
            throw new ChainException("the status list token has iss " + tokenIssuer + ", but the credential has iss "
                    + credentialIssuer);
        }
        verifySignature(jws, credentialIssuer);
        if (!claims.path("sub").isTextual() || !uri.equals(claims.get("sub").textValue())) {
            throw new ChainException("the status list token is for " + claims.get("sub") + ", not " + uri);
        }
        // §5.1 requires iat, and §8.3 step 3.b checks that the required claims exist.
        long iat = NumericDates.require(claims, "iat", "the status list token");
        if (iat > clock.instant().getEpochSecond() + clockSkew.toSeconds()) {
            throw new ChainException("the status list token has an iat in the future");
        }
        OptionalLong exp = NumericDates.read(claims, "exp", "the status list token");
        if (exp.isPresent()
                && exp.getAsLong() + clockSkew.toSeconds() <= clock.instant().getEpochSecond()) {
            throw new ChainException("the status list token is expired");
        }
        JsonNode list = claims.get("status_list");
        int bits = list == null ? 0 : list.path("bits").asInt();
        if (bits != 1 && bits != 2 && bits != 4 && bits != 8) {
            throw new ChainException("the status list has an unsupported size of " + bits + " bits");
        }
        byte[] statuses = inflate(list.path("lst").asText());
        long position = (long) index * bits;
        if (position / 8 >= statuses.length) {
            throw new ChainException("the status list has no entry " + index);
        }
        return (statuses[(int) (position / 8)] & 0xff) >> (position % 8) & ((1 << bits) - 1);
    }

    private void verifySignature(JWSInput jws, String issuer) throws ChainException {
        List<SignatureVerifierContext> verifiers = trust.resolve(jws.getHeader(), issuer);
        byte[] input = jws.getEncodedSignatureInput().getBytes(StandardCharsets.US_ASCII);
        for (SignatureVerifierContext verifier : verifiers) {
            try {
                if (verifier.verify(input, jws.getSignature())) {
                    return;
                }
            } catch (Exception e) {
                // The next candidate key may match.
            }
        }
        throw new ChainException("the signature of the status list token does not verify with a trusted issuer key");
    }

    /** lst is a base64url encoded byte array with ZLIB compression. */
    private static byte[] inflate(String lst) throws ChainException {
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(Base64Url.decode(lst));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            while (!inflater.finished()) {
                int read = inflater.inflate(buffer);
                if (read == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    throw new ChainException("the status list is truncated");
                }
                out.write(buffer, 0, read);
                if (out.size() > MAX_LIST_SIZE) {
                    throw new ChainException("the status list is larger than " + MAX_LIST_SIZE + " bytes");
                }
            }
            return out.toByteArray();
        } catch (DataFormatException | IllegalArgumentException e) {
            throw new ChainException("the status list is not ZLIB data", e);
        } finally {
            inflater.end();
        }
    }

    private static String schemeOf(String uri) {
        try {
            return URI.create(uri).getScheme();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
