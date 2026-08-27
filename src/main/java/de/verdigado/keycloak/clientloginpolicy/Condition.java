package de.verdigado.keycloak.clientloginpolicy;

/**
 * Who a rule applies to: {@code role:<name>}, {@code role:<clientId>/<name>},
 * {@code group:/path}, {@code attribute:<name>} or {@code attribute:<name>=<value>}.
 */
record Condition(Kind kind, String value, String expected) {

    enum Kind {
        ROLE,
        GROUP,
        ATTRIBUTE
    }

    String describe() {
        String prefix = kind().name().toLowerCase() + ":" + value();
        return expected() == null ? prefix : prefix + "=" + expected();
    }

    static Condition parse(String text) {
        int colon = text.indexOf(':');
        if (colon < 0) {
            throw new IllegalArgumentException("condition must read kind:value, got '" + text + "'");
        }

        String kind = text.substring(0, colon).trim();
        String value = text.substring(colon + 1).trim();
        if (value.isEmpty()) {
            throw new IllegalArgumentException("condition has no value: '" + text + "'");
        }

        return switch (kind) {
            case "role" -> new Condition(Kind.ROLE, value, null);
            case "group" -> new Condition(Kind.GROUP, value.startsWith("/") ? value : "/" + value, null);
            case "attribute" -> attribute(value);
            default -> throw new IllegalArgumentException("unknown condition kind '" + kind + "'");
        };
    }

    private static Condition attribute(String value) {
        int equals = value.indexOf('=');
        if (equals < 0) {
            return new Condition(Kind.ATTRIBUTE, value, null);
        }

        String name = value.substring(0, equals).trim();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("attribute condition has no name: '" + value + "'");
        }
        return new Condition(Kind.ATTRIBUTE, name, value.substring(equals + 1).trim());
    }
}
