package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;

import org.junit.jupiter.api.Test;

class ConditionTest {

    @Test
    void readsARealmRole() {
        assertEquals(Condition.realmRole("staff"), Condition.of(Map.of("role", "staff")));
    }

    @Test
    void readsAClientRole() {
        assertEquals(Condition.clientRole("reporting", "access"),
                Condition.of(Map.of("role", "access", "client", "reporting")));
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
        assertEquals("a=b:c", condition.value());
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
    void rejectsWhatItCannotRead() {
        assertThrows(IllegalArgumentException.class, () -> Condition.of(Map.of("team", "staff")));
        assertThrows(IllegalArgumentException.class, () -> Condition.of(Map.of("role", "")));
        assertThrows(IllegalArgumentException.class, () -> Condition.of(Map.of("role", 3)));
    }
}
