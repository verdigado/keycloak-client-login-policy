package de.verdigado.keycloak.clientloginpolicy;

import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Who a rule applies to. Written as an object so that nothing has to be escaped:
 * {@code {"role": "staff"}}, {@code {"role": "access", "client": "reporting"}},
 * {@code {"group": "/board"}}, {@code {"attribute": "department", "value": "finance"}}
 * or {@code {"attribute": "department"}} for any value at all.
 *
 * <p>Adding {@code "match": "regex"} compares by regular expression instead of
 * literally, against the role name, the group path or the attribute value.
 */
sealed interface Condition {

    boolean matches(Subject subject);

    /** How this condition reads in a log line. */
    String describe();

    record Role(String client, Match name) implements Condition {

        @Override
        public boolean matches(Subject subject) {
            if (!name.isRegex()) {
                return client == null
                        ? subject.hasRealmRole(name.text())
                        : subject.hasClientRole(client, name.text());
            }

            Stream<String> held = client == null ? subject.realmRoleNames() : subject.clientRoleNames(client);
            return held.anyMatch(name::test);
        }

        @Override
        public String describe() {
            return client == null
                    ? "realm role " + name.describe()
                    : "client role " + name.describe() + " on " + client;
        }
    }

    record Group(Match path) implements Condition {

        @Override
        public boolean matches(Subject subject) {
            return subject.groupPaths().anyMatch(this::covers);
        }

        /** An exact path takes everything nested under it with it. */
        private boolean covers(String groupPath) {
            return path.isRegex()
                    ? path.test(groupPath)
                    : groupPath.equals(path.text()) || groupPath.startsWith(path.text() + "/");
        }

        @Override
        public String describe() {
            return "group " + path.describe();
        }
    }

    record Attribute(String name, Match value) implements Condition {

        @Override
        public boolean matches(Subject subject) {
            return subject.attributeValues(name)
                    .anyMatch(held -> value == null ? !held.isEmpty() : value.test(held));
        }

        @Override
        public String describe() {
            return value == null ? "attribute " + name + " set" : "attribute " + name + "=" + value.describe();
        }
    }

    static Condition realmRole(String name) {
        return new Role(null, Match.exact(name));
    }

    static Condition clientRole(String client, String name) {
        return new Role(client, Match.exact(name));
    }

    static Condition group(String path) {
        return new Group(Match.exact(path.startsWith("/") ? path : "/" + path));
    }

    static Condition attribute(String name, String value) {
        return new Attribute(name, value == null ? null : Match.exact(value));
    }

    static Condition of(Map<String, Object> fields) {
        String mode = text(fields, "match");

        if (fields.containsKey("role")) {
            return only(fields, "role", Set.of("role", "client", "match"),
                    new Role(text(fields, "client"), Match.of(required(fields, "role"), mode)));
        }
        if (fields.containsKey("group")) {
            return only(fields, "group", Set.of("group", "match"), group(required(fields, "group"), mode));
        }
        if (fields.containsKey("attribute")) {
            String value = text(fields, "value");
            return only(fields, "attribute", Set.of("attribute", "value", "match"),
                    new Attribute(required(fields, "attribute"), value == null ? null : Match.of(value, mode)));
        }
        throw new IllegalArgumentException("a condition names a role, a group or an attribute, got " + fields.keySet());
    }

    private static Condition group(String path, String mode) {
        Match match = Match.of(path, mode);
        return match.isRegex() ? new Group(match) : group(path);
    }

    /** So that a stray or contradictory key is reported rather than ignored. */
    private static Condition only(Map<String, Object> fields, String kind, Set<String> known, Condition condition) {
        for (String key : fields.keySet()) {
            if (!known.contains(key)) {
                throw new IllegalArgumentException("a " + kind + " condition has no use for '" + key + "'");
            }
        }
        return condition;
    }

    private static String required(Map<String, Object> fields, String key) {
        String value = text(fields, key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(key + " has no value");
        }
        return value;
    }

    private static String text(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String string)) {
            throw new IllegalArgumentException(key + " must be text, got " + value);
        }
        return string;
    }
}
