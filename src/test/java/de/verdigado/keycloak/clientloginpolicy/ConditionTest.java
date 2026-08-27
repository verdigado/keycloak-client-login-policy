package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

class ConditionTest {

    private static Subject subjectWithClientRole(String clientId, String role) {
        return new Subject() {

            @Override
            public boolean hasRealmRole(String name) {
                return false;
            }

            @Override
            public boolean hasClientRole(String on, String name) {
                return on.equals(clientId) && name.equals(role);
            }

            @Override
            public Stream<String> realmRoleNames() {
                return Stream.empty();
            }

            @Override
            public Stream<String> clientRoleNames(String on) {
                return on.equals(clientId) ? Stream.of(role) : Stream.empty();
            }

            @Override
            public Stream<String> groupPaths() {
                return Stream.empty();
            }

            @Override
            public Stream<String> attributeValues(String name) {
                return Stream.empty();
            }
        };
    }

    private static Subject subjectWith(Set<String> realmRoles, Set<String> groups) {
        return new Subject() {

            @Override
            public boolean hasRealmRole(String name) {
                return realmRoles.contains(name);
            }

            @Override
            public boolean hasClientRole(String clientId, String name) {
                return false;
            }

            @Override
            public Stream<String> realmRoleNames() {
                return realmRoles.stream();
            }

            @Override
            public Stream<String> clientRoleNames(String clientId) {
                return Stream.empty();
            }

            @Override
            public Stream<String> groupPaths() {
                return groups.stream();
            }

            @Override
            public Stream<String> attributeValues(String name) {
                return Stream.empty();
            }
        };
    }

    @Test
    void readsARealmRole() {
        assertEquals(Condition.realmRole("staff"), Condition.of(Map.of("realmRole", "staff")));
    }

    @Test
    void readsAClientRole() {
        assertEquals(Condition.clientRole("reporting", "access"),
                Condition.of(Map.of("clientRole", "access", "client", "reporting")));
    }

    @Test
    void anchorsGroupPaths() {
        assertEquals(Condition.group("/board"), Condition.of(Map.of("group", "board")));
    }

    @Test
    void takesAnAttributeWithAndWithoutAValue() {
        assertEquals(Condition.attribute("department", "finance"),
                Condition.of(Map.of("attribute", "department", "value", "finance")));
        assertEquals(Condition.attribute("department", null), Condition.of(Map.of("attribute", "department")));
    }

    @Test
    void keepsCharactersThatUsedToNeedEscaping() {
        Condition.Attribute condition =
                (Condition.Attribute) Condition.of(Map.of("attribute", "cost=centre", "value", "a=b:c"));

        assertEquals("cost=centre", condition.name());
        assertEquals("a=b:c", condition.value().text());
    }

    @Test
    void describesItselfForALogLine() {
        assertEquals("realm role staff", Condition.realmRole("staff").describe());
        assertEquals("client role access on reporting", Condition.clientRole("reporting", "access").describe());
        assertEquals("group /board", Condition.group("/board").describe());
        assertEquals("attribute department=finance", Condition.attribute("department", "finance").describe());
        assertEquals("attribute department set", Condition.attribute("department", null).describe());
    }

    @Test
    void takesAClientRoleOnTheClientBeingEntered() {
        Condition condition = Condition.of(Map.of("clientRole", "access"));
        Subject holder = subjectWithClientRole("restricted-app", "access");

        assertTrue(condition.matches(holder, "restricted-app"));
        assertFalse(condition.matches(holder, "demo-app"));
        assertEquals("client role access on the client entered", condition.describe());
    }

    @Test
    void takesAClientRoleOnANamedClient() {
        Condition condition = Condition.of(Map.of("clientRole", "access", "client", "intranet"));
        Subject holder = subjectWithClientRole("intranet", "access");

        assertTrue(condition.matches(holder, "restricted-app"));
        assertEquals("client role access on intranet", condition.describe());
    }

    @Test
    void comparesByRegexWhenAsked() {
        Condition role = Condition.of(Map.of("realmRole", "^tenant-[0-9]+-staff$", "match", "regex"));
        Subject holder = subjectWith(Set.of("tenant-7-staff"), Set.of());
        Subject other = subjectWith(Set.of("tenant-seven-staff"), Set.of());

        assertTrue(role.matches(holder, "some-app"));
        assertFalse(role.matches(other, "some-app"));
        assertEquals("realm role matching ^tenant-[0-9]+-staff$", role.describe());
    }

    @Test
    void comparesGroupPathsByRegexWhenAsked() {
        Condition group = Condition.of(Map.of("group", "^/tenants/[^/]+/staff$", "match", "regex"));

        assertTrue(group.matches(subjectWith(Set.of(), Set.of("/tenants/acme/staff")), "some-app"));
        assertFalse(group.matches(subjectWith(Set.of(), Set.of("/tenants/acme/staff/leads")), "some-app"));
    }

    @Test
    void refusesAPatternItCannotCompile() {
        assertThrows(IllegalArgumentException.class, () -> Condition.of(Map.of("realmRole", "[", "match", "regex")));
        assertThrows(IllegalArgumentException.class,
                () -> Condition.of(Map.of("realmRole", "staff", "match", "glob")));
    }

    @Test
    void rejectsWhatItCannotRead() {
        assertThrows(IllegalArgumentException.class, () -> Condition.of(Map.of("team", "staff")));
        assertThrows(IllegalArgumentException.class, () -> Condition.of(Map.of("realmRole", "")));
        assertThrows(IllegalArgumentException.class, () -> Condition.of(Map.of("realmRole", 3)));
        assertThrows(IllegalArgumentException.class, () -> Condition.of(Map.of("group", 5)));
        assertThrows(IllegalArgumentException.class,
                () -> Condition.of(Map.of("attribute", "department", "value", 3)));
    }

    @Test
    void refusesAKeyItWouldOtherwiseIgnore() {
        assertThrows(IllegalArgumentException.class, () -> Condition.of(Map.of("realmRole", "staff", "group", "/board")));
        assertThrows(IllegalArgumentException.class, () -> Condition.of(Map.of("group", "/board", "client", "app")));
        assertThrows(IllegalArgumentException.class,
                () -> Condition.of(Map.of("attribute", "department", "vaule", "finance")));
    }
}
