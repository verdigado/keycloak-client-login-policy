package de.verdigado.keycloak.clientloginpolicy;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The rules every client in a realm is held to: the clients the policy keeps
 * its hands off, the fallback for clients without an entry, and the entries.
 */
record Policy(Set<String> exempt, List<Rule> fallback, Map<String, List<Rule>> byClient) {

    List<Rule> forClient(String clientId) {
        if (exempt.contains(clientId)) {
            return List.of();
        }
        return byClient.getOrDefault(clientId, fallback);
    }
}
