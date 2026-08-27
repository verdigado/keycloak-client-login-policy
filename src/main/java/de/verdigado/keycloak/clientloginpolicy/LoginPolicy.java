package de.verdigado.keycloak.clientloginpolicy;

import java.util.List;

final class LoginPolicy {

    private LoginPolicy() {
    }

    /**
     * An exempt client admits everyone. Otherwise a user's own override settles
     * it, and only then does the client's policy decide.
     */
    static Decision decide(Policy policy, Subject subject, String clientId) {
        if (policy.exempt().contains(clientId)) {
            return Decision.allow("client is exempt from the policy");
        }

        return switch (UserOverride.of(subject, clientId)) {
            case DENY -> Decision.deny("the user's " + UserOverride.DENY_ATTRIBUTE + " lists this client");
            case ALLOW -> Decision.allow("the user's " + UserOverride.ALLOW_ATTRIBUTE + " lists this client");
            case NONE -> decide(policy.forClient(clientId), subject);
        };
    }

    /**
     * A matching deny turns the user away. Otherwise, a client that lists allow
     * rules admits only users matching one of them; a client that lists none
     * admits everyone.
     */
    static Decision decide(List<Rule> rules, Subject subject) {
        List<Rule> allowRules = rules.stream().filter(rule -> rule.effect() == Rule.Effect.ALLOW).toList();

        for (Rule rule : rules) {
            if (rule.effect() == Rule.Effect.DENY && matches(rule.condition(), subject)) {
                return Decision.deny(rule.describe());
            }
        }

        if (allowRules.isEmpty()) {
            return Decision.allow("no rule keeps the user out");
        }

        return allowRules.stream()
                .filter(rule -> matches(rule.condition(), subject))
                .findFirst()
                .map(rule -> Decision.allow(rule.describe()))
                .orElseGet(() -> Decision.deny("no allow rule matches the user"));
    }

    private static boolean matches(Condition condition, Subject subject) {
        return switch (condition.kind()) {
            case ROLE -> subject.hasRole(condition.value());
            case GROUP -> subject.inGroup(condition.value());
            case ATTRIBUTE -> subject.hasAttribute(condition.value(), condition.expected());
        };
    }
}
