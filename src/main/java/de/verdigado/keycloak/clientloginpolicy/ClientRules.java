package de.verdigado.keycloak.clientloginpolicy;

import java.util.List;
import java.util.Map;

/**
 * The policy each client is held to. Hardcoded for now; this is where
 * per-client configuration will hook in.
 */
final class ClientRules {

    private static final List<Rule> DEFAULT = List.of();

    private static final Map<String, List<Rule>> BY_CLIENT = Map.of(
            "restricted-app", List.of(
                    Rule.allow("role:staff"),
                    Rule.allow("group:/board")));

    private ClientRules() {
    }

    static List<Rule> forClient(String clientId) {
        return BY_CLIENT.getOrDefault(clientId, DEFAULT);
    }
}
