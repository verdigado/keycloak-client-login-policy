package de.verdigado.keycloak.clientloginpolicy;

/** Whether the user may log in, and what settled it. */
record Decision(boolean allowed, String reason) {

    static Decision allow(String reason) {
        return new Decision(true, reason);
    }

    static Decision deny(String reason) {
        return new Decision(false, reason);
    }
}
