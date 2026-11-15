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

package io.github.dominikschlosser.keycloak.dsdjwt.nonce;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.Config;

class NonceResourceProviderFactoryTest {

    private static final String PREFIX = "dsdjwt-nonce-test.";

    @AfterEach
    void clear() {
        System.clearProperty(PREFIX + NonceResourceProviderFactory.LIFESPAN);
    }

    @Test
    void offersALifespanOf120SecondsByDefault() {
        assertEquals(
                120L,
                new NonceResourceProviderFactory().getConfigMetadata().get(0).getDefaultValue());
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "-5"})
    void refusesALifespanThatIsNotPositive(String lifespan) {
        System.setProperty(PREFIX + NonceResourceProviderFactory.LIFESPAN, lifespan);

        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> new NonceResourceProviderFactory()
                        .init(new Config.SystemPropertiesScope(PREFIX)));

        assertEquals("nonceLifespan must be positive", e.getMessage());
    }
}
