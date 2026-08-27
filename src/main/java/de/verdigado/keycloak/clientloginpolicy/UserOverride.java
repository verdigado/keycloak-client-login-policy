package de.verdigado.keycloak.clientloginpolicy;

/**
 * A per-user exception to the policy, kept on the user rather than in the
 * document: both attributes hold client ids, one value per client.
 */
enum UserOverride {

    ALLOW,
    DENY,
    NONE;

    static final String ALLOW_ATTRIBUTE = "client-login-policy.allow";
    static final String DENY_ATTRIBUTE = "client-login-policy.deny";

    static UserOverride of(Subject subject, String clientId) {
        if (lists(subject, DENY_ATTRIBUTE, clientId)) {
            return DENY;
        }
        if (lists(subject, ALLOW_ATTRIBUTE, clientId)) {
            return ALLOW;
        }
        return NONE;
    }

    private static boolean lists(Subject subject, String attribute, String clientId) {
        return subject.attributeValues(attribute).anyMatch(clientId::equals);
    }
}
