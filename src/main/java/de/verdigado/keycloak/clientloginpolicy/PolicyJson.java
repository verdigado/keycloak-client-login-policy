package de.verdigado.keycloak.clientloginpolicy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.util.JsonSerialization;

/**
 * Reads a policy document:
 *
 * <pre>
 * {
 *   "default": [{ "deny": "group:/blocked" }],
 *   "clients": {
 *     "restricted-app": [{ "allow": "role:staff" }, { "allow": "group:/board" }]
 *   }
 * }
 * </pre>
 */
final class PolicyJson {

    private PolicyJson() {
    }

    static Policy parse(String document) {
        Map<String, Object> root = asMap(read(document), "document");

        List<Rule> fallback = rules(root.get("default"), "default");

        Map<String, List<Rule>> byClient = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : asMap(root.get("clients"), "clients").entrySet()) {
            byClient.put(entry.getKey(), rules(entry.getValue(), "client " + entry.getKey()));
        }

        return new Policy(fallback, Map.copyOf(byClient));
    }

    private static Object read(String document) {
        try {
            return JsonSerialization.readValue(document, Map.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("policy is not readable json: " + e.getMessage(), e);
        }
    }

    private static List<Rule> rules(Object value, String where) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> entries)) {
            throw new IllegalArgumentException(where + " must be a list of rules");
        }

        List<Rule> rules = new ArrayList<>();
        for (Object entry : entries) {
            rules.add(rule(entry, where));
        }
        return List.copyOf(rules);
    }

    private static Rule rule(Object entry, String where) {
        Map<String, Object> fields = asMap(entry, where + " rule");
        if (fields.size() != 1) {
            throw new IllegalArgumentException(where + ": a rule is one allow or one deny, got " + fields.keySet());
        }

        Map.Entry<String, Object> only = fields.entrySet().iterator().next();
        String condition = String.valueOf(only.getValue());

        return switch (only.getKey()) {
            case "allow" -> Rule.allow(condition);
            case "deny" -> Rule.deny(condition);
            default -> throw new IllegalArgumentException(
                    where + ": a rule is allow or deny, got '" + only.getKey() + "'");
        };
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value, String where) {
        if (value == null) {
            return Map.of();
        }
        if (!(value instanceof Map<?, ?>)) {
            throw new IllegalArgumentException(where + " must be a mapping");
        }
        return (Map<String, Object>) value;
    }
}
