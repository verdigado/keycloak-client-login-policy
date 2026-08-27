package de.verdigado.keycloak.clientloginpolicy;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The rules every client in a realm is held to: the clients the policy keeps
 * its hands off, the fallback for clients without an entry, and the entries.
 */
record Policy(Set<String> exempt, List<Rule> fallback, Map<String, List<Rule>> byClient) {

    /** No document configured: the provider has nothing to say about anyone. */
    static final Policy OPEN = new Policy(PolicyJson.DEFAULT_EXEMPT, List.of(), Map.of());

    /**
     * A document that could not be read. Nobody gets in on rules we cannot see,
     * except through the clients the policy never touches — which is what keeps
     * a typo from shutting the console along with everything else.
     */
    static final Policy CLOSED = new Policy(PolicyJson.DEFAULT_EXEMPT,
            List.of(Rule.deny(Condition.everyone())), Map.of());

    List<Rule> forClient(String clientId) {
        if (exempt.contains(clientId)) {
            return List.of();
        }
        return byClient.getOrDefault(clientId, fallback);
    }
}
