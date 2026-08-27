package de.verdigado.keycloak.clientloginpolicy;

import java.util.List;

/**
 * The policy in force. Hardcoded for now; this is where a configured document
 * will be read instead.
 */
final class ClientRules {

    private static final String DOCUMENT = """
            {
              "default": [],
              "clients": {
                "restricted-app": [
                  { "allow": "role:staff" },
                  { "allow": "group:/board" }
                ]
              }
            }
            """;

    private static final Policy POLICY = PolicyJson.parse(DOCUMENT);

    private ClientRules() {
    }

    static List<Rule> forClient(String clientId) {
        return POLICY.forClient(clientId);
    }
}
