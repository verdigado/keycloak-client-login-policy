package de.verdigado.keycloak.clientloginpolicy;

import java.util.Map;

/**
 * Who a rule applies to. Written as an object so that nothing has to be escaped:
 * {@code {"role": "staff"}}, {@code {"role": "access", "client": "reporting"}},
 * {@code {"group": "/board"}}, {@code {"attribute": "department", "value": "finance"}}
 * or {@code {"attribute": "department"}} for any value at all.
 */
sealed interface Condition {

    boolean matches(Subject subject);

    /** How this condition reads in a log line. */
    String describe();

    record Role(String client, String name) implements Condition {

        @Override
        public boolean matches(Subject subject) {
            return client == null ? subject.hasRealmRole(name) : subject.hasClientRole(client, name);
        }

        @Override
        public String describe() {
            return client == null ? "realm role " + name : "client role " + name + " on " + client;
        }
    }

    record Group(String path) implements Condition {

        @Override
        public boolean matches(Subject subject) {
            return subject.inGroup(path);
        }

        @Override
        public String describe() {
            return "group " + path;
        }
    }

    record Attribute(String name, String value) implements Condition {

        @Override
        public boolean matches(Subject subject) {
            return subject.hasAttribute(name, value);
        }

        @Override
        public String describe() {
            return value == null ? "attribute " + name + " set" : "attribute " + name + "=" + value;
        }
    }

    static Condition realmRole(String name) {
        return new Role(null, name);
    }

    static Condition clientRole(String client, String name) {
        return new Role(client, name);
    }

    static Condition group(String path) {
        return new Group(path.startsWith("/") ? path : "/" + path);
    }

    static Condition attribute(String name, String value) {
        return new Attribute(name, value);
    }

    static Condition of(Map<String, Object> fields) {
        if (fields.containsKey("role")) {
            return new Role(text(fields, "client"), required(fields, "role"));
        }
        if (fields.containsKey("group")) {
            return group(required(fields, "group"));
        }
        if (fields.containsKey("attribute")) {
            return new Attribute(required(fields, "attribute"), text(fields, "value"));
        }
        throw new IllegalArgumentException("a condition names a role, a group or an attribute, got " + fields.keySet());
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
