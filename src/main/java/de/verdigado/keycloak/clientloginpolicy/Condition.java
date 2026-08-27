package de.verdigado.keycloak.clientloginpolicy;

record Condition(Kind kind, String value) {

    enum Kind {
        ROLE,
        GROUP
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
            case "role" -> new Condition(Kind.ROLE, value);
            case "group" -> new Condition(Kind.GROUP, value.startsWith("/") ? value : "/" + value);
            default -> throw new IllegalArgumentException("unknown condition kind '" + kind + "'");
        };
    }
}
