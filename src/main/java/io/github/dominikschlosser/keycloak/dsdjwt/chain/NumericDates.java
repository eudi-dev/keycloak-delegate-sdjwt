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

import com.fasterxml.jackson.databind.JsonNode;
import java.util.OptionalLong;

/** Reads the NumericDate claims of RFC 7519 §2. */
public final class NumericDates {

    /** 9999-12-31T23:59:59Z. */
    static final long MAX = 253402300799L;

    private NumericDates() {}

    public static OptionalLong read(JsonNode claims, String name, String owner) throws ChainException {
        JsonNode value = claims.get(name);
        if (value == null) {
            return OptionalLong.empty();
        }
        if (!value.isNumber()) {
            throw new ChainException(owner + " has a " + name + " claim that is not a number");
        }
        double seconds = value.asDouble();
        if (!(seconds >= 0 && seconds <= MAX)) {
            throw new ChainException(owner + " has a " + name + " claim that is not a NumericDate");
        }
        return OptionalLong.of((long) Math.floor(seconds));
    }

    public static long require(JsonNode claims, String name, String owner) throws ChainException {
        OptionalLong value = read(claims, name, owner);
        if (value.isEmpty()) {
            throw new ChainException(owner + " has no " + name + " claim");
        }
        return value.getAsLong();
    }
}
