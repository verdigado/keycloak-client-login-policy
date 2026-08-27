package de.verdigado.keycloak.clientloginpolicy;

import java.util.Map;

/**
 * Which realm role a client demands of anyone logging in to it.
 * Hardcoded for now; this is where per-client configuration will hook in.
 */
final class ClientLoginRules {

    private static final Map<String, String> REQUIRED_REALM_ROLE = Map.of(
            "restricted-app", "staff");

    private ClientLoginRules() {
    }

    /** The role the client demands, or null if it lets everyone in. */
    static String requiredRealmRole(String clientId) {
        return REQUIRED_REALM_ROLE.get(clientId);
    }
}
