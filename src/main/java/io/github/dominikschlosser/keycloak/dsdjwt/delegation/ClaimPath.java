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

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Optional;

/** A path of object member names such as {@code mandate.limit.amount}. */
public final class ClaimPath {

    private final String path;
    private final List<String> members;

    private ClaimPath(String path, List<String> members) {
        this.path = path;
        this.members = members;
    }

    /** Parses a dot separated path. Member names that contain a dot cannot be addressed. */
    public static ClaimPath parse(String path) {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("a claim path must not be empty");
        }
        List<String> members = List.of(path.trim().split("\\.", -1));
        if (members.stream().anyMatch(String::isEmpty)) {
            throw new IllegalArgumentException("the claim path " + path + " has an empty member name");
        }
        return new ClaimPath(path.trim(), members);
    }

    /** Returns the value at this path. A JSON null counts as absent. */
    public Optional<JsonNode> find(JsonNode root) {
        JsonNode node = root;
        for (String member : members) {
            if (node == null || !node.isObject()) {
                return Optional.empty();
            }
            node = node.get(member);
        }
        return node == null || node.isNull() ? Optional.empty() : Optional.of(node);
    }

    /** Whether the value at this path holds the node at the other path, or is that node. */
    public boolean holds(List<String> other) {
        return other.size() >= members.size()
                && other.subList(0, members.size()).equals(members);
    }

    @Override
    public String toString() {
        return path;
    }
}
