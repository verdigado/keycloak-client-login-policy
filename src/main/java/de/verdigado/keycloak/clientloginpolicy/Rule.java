package de.verdigado.keycloak.clientloginpolicy;

/**
 * One line of a client's policy: what to do, and who it applies to.
 * Conditions are written as {@code role:<name>}, {@code role:<clientId>/<name>}
 * or {@code group:/path}.
 */
record Rule(Effect effect, Condition condition) {

    enum Effect {
        ALLOW,
        DENY
    }

    static Rule allow(String condition) {
        return new Rule(Effect.ALLOW, Condition.parse(condition));
    }

    static Rule deny(String condition) {
        return new Rule(Effect.DENY, Condition.parse(condition));
    }

    /** How this rule reads in a log line. */
    String describe() {
        return effect().name().toLowerCase() + " " + condition().describe();
    }
}
