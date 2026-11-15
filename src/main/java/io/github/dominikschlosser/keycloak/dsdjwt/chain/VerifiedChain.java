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

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.Set;
import org.keycloak.sdjwt.IssuerSignedJWT;

/**
 * A dSD-JWT+KB that passed every check of §6.
 *
 * @param credentialJwt the Issuer-signed JWT of the credential
 * @param credential the disclosed payload of the credential
 * @param links the KB-SD-JWTs in chain order, first delegation first
 * @param firstWithheld the paths in the first Delegate Payload of each object or array that holds a
 *     digest without a presented Disclosure. A path names object members and array indexes.
 * @param nonce the nonce of the Key Binding JWT
 * @param expiresAt the earliest exp of the credential, the Delegate Payloads and the Key Binding JWT
 */
public record VerifiedChain(
        IssuerSignedJWT credentialJwt,
        ObjectNode credential,
        List<VerifiedLink> links,
        Set<List<String>> firstWithheld,
        String nonce,
        long expiresAt) {

    public VerifiedChain {
        links = List.copyOf(links);
        firstWithheld = Set.copyOf(firstWithheld);
    }
}
