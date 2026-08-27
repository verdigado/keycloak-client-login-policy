package de.verdigado.keycloak.clientloginpolicy;

/**
 * The policy in force. Hardcoded for now; this is where a configured document
 * will be read instead.
 */
final class ClientRules {

    private static final String DOCUMENT = """
            {
              "default": [{ "deny": "attribute:guest=TRUE" }],
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

    static Policy policy() {
        return POLICY;
    }
}
