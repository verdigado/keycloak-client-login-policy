package de.verdigado.keycloak.clientloginpolicy;

import java.util.List;
import java.util.Map;

/**
 * The rules every client in a realm is held to, plus the fallback for clients
 * without an entry of their own.
 */
record Policy(List<Rule> fallback, Map<String, List<Rule>> byClient) {

    List<Rule> forClient(String clientId) {
        return byClient.getOrDefault(clientId, fallback);
    }
}
