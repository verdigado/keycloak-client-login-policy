package de.verdigado.keycloak.clientloginpolicy;

/**
 * The user a policy is being decided for, reduced to the questions a policy asks.
 */
interface Subject {

    boolean hasRealmRole(String name);

    boolean hasClientRole(String clientId, String name);

    /** True for the group itself and for anything nested under it. */
    boolean inGroup(String path);

    /** A null {@code value} asks whether the attribute is set at all. */
    boolean hasAttribute(String name, String value);
}
