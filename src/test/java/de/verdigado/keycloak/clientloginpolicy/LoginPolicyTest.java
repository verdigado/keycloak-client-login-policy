package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

class LoginPolicyTest {

    private record FakeSubject(Set<String> roles, Set<String> groups) implements Subject {

        @Override
        public boolean hasRole(String name) {
            return roles.contains(name);
        }

        @Override
        public boolean inGroup(String path) {
            return groups.stream().anyMatch(g -> g.equals(path) || g.startsWith(path + "/"));
        }
    }

    private static final Subject STAFF = new FakeSubject(Set.of("staff"), Set.of());
    private static final Subject NOBODY = new FakeSubject(Set.of(), Set.of());
    private static final Subject CHAIR = new FakeSubject(Set.of(), Set.of("/board/chairs"));

    @Test
    void letsEveryoneInWhenThereAreNoRules() {
        assertTrue(LoginPolicy.allows(List.of(), NOBODY));
    }

    @Test
    void admitsOnlyUsersMatchingAnAllowRule() {
        List<Rule> rules = List.of(Rule.allow("role:staff"));

        assertTrue(LoginPolicy.allows(rules, STAFF));
        assertFalse(LoginPolicy.allows(rules, NOBODY));
    }

    @Test
    void takesAnyOneOfSeveralAllowRules() {
        List<Rule> rules = List.of(Rule.allow("role:staff"), Rule.allow("group:/board"));

        assertTrue(LoginPolicy.allows(rules, STAFF));
        assertTrue(LoginPolicy.allows(rules, CHAIR));
        assertFalse(LoginPolicy.allows(rules, NOBODY));
    }

    @Test
    void letsADenyRuleOverruleAnAllow() {
        List<Rule> rules = List.of(Rule.allow("role:staff"), Rule.deny("group:/board"));
        Subject staffOnTheBoard = new FakeSubject(Set.of("staff"), Set.of("/board"));

        assertFalse(LoginPolicy.allows(rules, staffOnTheBoard));
        assertTrue(LoginPolicy.allows(rules, STAFF));
    }

    @Test
    void denyRulesAloneKeepTheClientOpenToEveryoneElse() {
        List<Rule> rules = List.of(Rule.deny("role:staff"));

        assertFalse(LoginPolicy.allows(rules, STAFF));
        assertTrue(LoginPolicy.allows(rules, NOBODY));
    }
}
