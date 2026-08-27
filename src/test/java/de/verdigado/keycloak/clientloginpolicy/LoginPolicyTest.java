package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

class LoginPolicyTest {

    private record FakeSubject(Set<String> roles, Set<String> groups, Map<String, String> attributes)
            implements Subject {

        FakeSubject(Set<String> roles, Set<String> groups) {
            this(roles, groups, Map.of());
        }

        @Override
        public boolean hasRole(String name) {
            return roles.contains(name);
        }

        @Override
        public boolean inGroup(String path) {
            return groups.stream().anyMatch(g -> g.equals(path) || g.startsWith(path + "/"));
        }

        @Override
        public boolean hasAttribute(String name, String value) {
            String held = attributes.get(name);
            return held != null && (value == null || held.equals(value));
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
    void matchesOnAnAttributeValue() {
        List<Rule> rules = List.of(Rule.allow("attribute:department=finance"));
        Subject finance = new FakeSubject(Set.of(), Set.of(), Map.of("department", "finance"));
        Subject sales = new FakeSubject(Set.of(), Set.of(), Map.of("department", "sales"));

        assertTrue(LoginPolicy.allows(rules, finance));
        assertFalse(LoginPolicy.allows(rules, sales));
        assertFalse(LoginPolicy.allows(rules, NOBODY));
    }

    @Test
    void takesAnAttributeSetToAnything() {
        List<Rule> rules = List.of(Rule.allow("attribute:department"));

        assertTrue(LoginPolicy.allows(rules, new FakeSubject(Set.of(), Set.of(), Map.of("department", "sales"))));
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
