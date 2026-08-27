package de.verdigado.keycloak.clientloginpolicy;

import java.util.stream.Stream;

/**
 * The user a policy is being decided for, reduced to what a policy asks about.
 * The two role questions exist because Keycloak answers them far more cheaply
 * than it hands over every role the user holds.
 */
interface Subject {

    boolean hasRealmRole(String name);

    boolean hasClientRole(String clientId, String name);

    Stream<String> realmRoleNames();

    Stream<String> clientRoleNames(String clientId);

    Stream<String> groupPaths();

    Stream<String> attributeValues(String name);
}
