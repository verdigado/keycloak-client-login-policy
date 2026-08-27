package de.verdigado.keycloak.clientloginpolicy;

import java.util.List;

final class LoginPolicy {

    private LoginPolicy() {
    }

    /**
     * An exempt client admits everyone. Otherwise a user's own override settles
     * it, and only then does the client's policy decide.
     */
    static boolean allows(Policy policy, Subject subject, String clientId) {
        if (policy.exempt().contains(clientId)) {
            return true;
        }

        return switch (UserOverride.of(subject, clientId)) {
            case DENY -> false;
            case ALLOW -> true;
            case NONE -> allows(policy.forClient(clientId), subject);
        };
    }

    /**
     * A matching deny turns the user away. Otherwise, a client that lists allow
     * rules admits only users matching one of them; a client that lists none
     * admits everyone.
     */
    static boolean allows(List<Rule> rules, Subject subject) {
        boolean restricted = false;

        for (Rule rule : rules) {
            boolean matches = matches(rule.condition(), subject);

            if (rule.effect() == Rule.Effect.DENY && matches) {
                return false;
            }
            if (rule.effect() == Rule.Effect.ALLOW) {
                restricted = true;
            }
        }

        if (!restricted) {
            return true;
        }

        return rules.stream()
                .filter(rule -> rule.effect() == Rule.Effect.ALLOW)
                .anyMatch(rule -> matches(rule.condition(), subject));
    }

    private static boolean matches(Condition condition, Subject subject) {
        return switch (condition.kind()) {
            case ROLE -> subject.hasRole(condition.value());
            case GROUP -> subject.inGroup(condition.value());
            case ATTRIBUTE -> subject.hasAttribute(condition.value(), condition.expected());
        };
    }
}
