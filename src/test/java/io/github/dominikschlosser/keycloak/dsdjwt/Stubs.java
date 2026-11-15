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

import java.lang.reflect.Proxy;

/** Builds a stub of an interface that answers each call by method name. */
public final class Stubs {

    private Stubs() {}

    public interface Handler {
        Object handle(String method, Object[] args) throws Exception;
    }

    @SuppressWarnings("unchecked")
    public static <T> T stub(Class<?> type, Handler handler) {
        return (T) Proxy.newProxyInstance(
                Stubs.class.getClassLoader(),
                new Class<?>[] {type},
                (proxy, method, args) -> handler.handle(method.getName(), args));
    }
}
