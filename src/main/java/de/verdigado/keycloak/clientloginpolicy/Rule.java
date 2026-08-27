package de.verdigado.keycloak.clientloginpolicy;

/** One line of a client's policy: what to do, and who it applies to. */
record Rule(Effect effect, Condition condition) {

    enum Effect {
        ALLOW,
        DENY
    }

    static Rule allow(Condition condition) {
        return new Rule(Effect.ALLOW, condition);
    }

    static Rule deny(Condition condition) {
        return new Rule(Effect.DENY, condition);
    }

    /** How this rule reads in a log line. */
    String describe() {
        return effect.name().toLowerCase() + " " + condition.describe();
    }
}
