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

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.util.JsonSerialization;

/** Reads the sample chains in src/test/resources/sample-chains. tools/samplechains writes them with the eudi-dev Go library. */
public final class SampleChains {

    private SampleChains() {}

    public static JsonNode read(String name) {
        try (InputStream in = SampleChains.class.getResourceAsStream("/sample-chains/" + name)) {
            if (in == null) {
                throw new IllegalArgumentException("no sample chain " + name);
            }
            return JsonSerialization.mapper.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static JWK jwk(JsonNode node) {
        return JsonSerialization.mapper.convertValue(node, JWK.class);
    }
}
