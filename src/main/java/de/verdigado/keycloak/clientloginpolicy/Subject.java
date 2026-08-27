package de.verdigado.keycloak.clientloginpolicy;

/**
 * The user a policy is being decided for, reduced to the questions a policy asks.
 */
interface Subject {

    /** {@code name} for a realm role, {@code clientId/name} for a client role. */
    boolean hasRole(String name);

    /** True for the group itself and for anything nested under it. */
    boolean inGroup(String path);
}
