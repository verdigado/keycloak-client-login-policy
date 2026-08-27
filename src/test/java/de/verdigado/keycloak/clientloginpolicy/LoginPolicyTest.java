package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

class LoginPolicyTest {

    private record FakeSubject(Set<String> roles, Set<String> groups, Map<String, String> attributes)
            implements Subject {

        FakeSubject(Set<String> roles, Set<String> groups) {
            this(roles, groups, Map.of());
        }

        @Override
        public boolean hasRealmRole(String name) {
            return roles.contains(name);
        }

        @Override
        public boolean hasClientRole(String clientId, String name) {
            return roles.contains(clientId + "/" + name);
        }

        @Override
        public Stream<String> realmRoleNames() {
            return roles.stream().filter(role -> !role.contains("/"));
        }

        @Override
        public Stream<String> clientRoleNames(String clientId) {
            return roles.stream()
                    .filter(role -> role.startsWith(clientId + "/"))
                    .map(role -> role.substring(clientId.length() + 1));
        }

        @Override
        public Stream<String> groupPaths() {
            return groups.stream();
        }

        @Override
        public Stream<String> attributeValues(String name) {
            String held = attributes.get(name);
            return held == null ? Stream.empty() : Stream.of(held);
        }
    }

    private static final Subject STAFF = new FakeSubject(Set.of("staff"), Set.of());
    private static final Subject NOBODY = new FakeSubject(Set.of(), Set.of());
    private static final Subject CHAIR = new FakeSubject(Set.of(), Set.of("/board/chairs"));

    private static Policy policyDenying(String clientId, Condition condition) {
        return new Policy(Set.of("account-console"), List.of(),
                Map.of(clientId, List.of(Rule.deny(condition))));
    }

    @Test
    void letsAUserOverrideOverruleTheClientsRules() {
        Policy policy = policyDenying("demo-app", Condition.attribute("guest", "TRUE"));
        Subject guest = new FakeSubject(Set.of(), Set.of(), Map.of("guest", "TRUE"));
        Subject invited = new FakeSubject(Set.of(), Set.of(),
                Map.of("guest", "TRUE", UserOverride.ALLOW_ATTRIBUTE, "demo-app"));

        assertFalse(LoginPolicy.decide(policy, guest, "demo-app").allowed());
        assertTrue(LoginPolicy.decide(policy, invited, "demo-app").allowed());
    }

    @Test
    void keepsAUserOutOfAClientTheirOwnOverrideDenies() {
        Policy open = new Policy(Set.of(), List.of(), Map.of());
        Subject barred = new FakeSubject(Set.of(), Set.of(), Map.of(UserOverride.DENY_ATTRIBUTE, "demo-app"));

        assertFalse(LoginPolicy.decide(open, barred, "demo-app").allowed());
        assertTrue(LoginPolicy.decide(open, barred, "other-app").allowed());
    }

    @Test
    void letsADenyOverrideBeatAnAllowOverride() {
        Policy open = new Policy(Set.of(), List.of(), Map.of());
        Subject both = new FakeSubject(Set.of(), Set.of(),
                Map.of(UserOverride.ALLOW_ATTRIBUTE, "demo-app", UserOverride.DENY_ATTRIBUTE, "demo-app"));

        assertFalse(LoginPolicy.decide(open, both, "demo-app").allowed());
    }

    @Test
    void leavesAnExemptClientAloneEvenWithAUserDeny() {
        Policy policy = policyDenying("demo-app", Condition.attribute("guest", "TRUE"));
        Subject barred = new FakeSubject(Set.of(), Set.of(), Map.of(UserOverride.DENY_ATTRIBUTE, "account-console"));

        assertTrue(LoginPolicy.decide(policy, barred, "account-console").allowed());
    }

    @Test
    void saysWhichRuleTurnedTheUserAway() {
        List<Rule> rules = List.of(Rule.allow(Condition.realmRole("staff")), Rule.deny(Condition.group("/board")));
        Subject staffOnTheBoard = new FakeSubject(Set.of("staff"), Set.of("/board"));

        assertEquals("deny group /board", LoginPolicy.decide(rules, staffOnTheBoard, "some-app").reason());
        assertEquals("allow realm role staff", LoginPolicy.decide(rules, STAFF, "some-app").reason());
        assertEquals("no allow rule matches the user", LoginPolicy.decide(rules, NOBODY, "some-app").reason());
    }

    @Test
    void saysWhichOverrideSettledIt() {
        Policy open = new Policy(Set.of(), List.of(), Map.of());
        Subject barred = new FakeSubject(Set.of(), Set.of(), Map.of(UserOverride.DENY_ATTRIBUTE, "demo-app"));

        assertEquals("the user's client-login-policy.deny lists this client",
                LoginPolicy.decide(open, barred, "demo-app").reason());
    }

    @Test
    void letsEveryoneInWhenThereAreNoRules() {
        assertTrue(LoginPolicy.decide(List.of(), NOBODY, "some-app").allowed());
    }

    @Test
    void admitsOnlyUsersMatchingAnAllowRule() {
        List<Rule> rules = List.of(Rule.allow(Condition.realmRole("staff")));

        assertTrue(LoginPolicy.decide(rules, STAFF, "some-app").allowed());
        assertFalse(LoginPolicy.decide(rules, NOBODY, "some-app").allowed());
    }

    @Test
    void takesAnyOneOfSeveralAllowRules() {
        List<Rule> rules = List.of(Rule.allow(Condition.realmRole("staff")), Rule.allow(Condition.group("/board")));

        assertTrue(LoginPolicy.decide(rules, STAFF, "some-app").allowed());
        assertTrue(LoginPolicy.decide(rules, CHAIR, "some-app").allowed());
        assertFalse(LoginPolicy.decide(rules, NOBODY, "some-app").allowed());
    }

    @Test
    void matchesOnAnAttributeValue() {
        List<Rule> rules = List.of(Rule.allow(Condition.attribute("department", "finance")));
        Subject finance = new FakeSubject(Set.of(), Set.of(), Map.of("department", "finance"));
        Subject sales = new FakeSubject(Set.of(), Set.of(), Map.of("department", "sales"));

        assertTrue(LoginPolicy.decide(rules, finance, "some-app").allowed());
        assertFalse(LoginPolicy.decide(rules, sales, "some-app").allowed());
        assertFalse(LoginPolicy.decide(rules, NOBODY, "some-app").allowed());
    }

    @Test
    void takesAnAttributeSetToAnything() {
        List<Rule> rules = List.of(Rule.allow(Condition.attribute("department", null)));

        assertTrue(LoginPolicy.decide(rules, new FakeSubject(Set.of(), Set.of(), Map.of("department", "sales")), "some-app").allowed());
        assertFalse(LoginPolicy.decide(rules, NOBODY, "some-app").allowed());
    }

    @Test
    void letsADenyRuleOverruleAnAllow() {
        List<Rule> rules = List.of(Rule.allow(Condition.realmRole("staff")), Rule.deny(Condition.group("/board")));
        Subject staffOnTheBoard = new FakeSubject(Set.of("staff"), Set.of("/board"));

        assertFalse(LoginPolicy.decide(rules, staffOnTheBoard, "some-app").allowed());
        assertTrue(LoginPolicy.decide(rules, STAFF, "some-app").allowed());
    }

    @Test
    void denyRulesAloneKeepTheClientOpenToEveryoneElse() {
        List<Rule> rules = List.of(Rule.deny(Condition.realmRole("staff")));

        assertFalse(LoginPolicy.decide(rules, STAFF, "some-app").allowed());
        assertTrue(LoginPolicy.decide(rules, NOBODY, "some-app").allowed());
    }
}
