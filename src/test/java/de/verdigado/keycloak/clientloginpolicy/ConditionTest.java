package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ConditionTest {

    @Test
    void readsARealmRole() {
        assertEquals(new Condition(Condition.Kind.ROLE, "staff", null), Condition.parse("role:staff"));
    }

    @Test
    void keepsTheClientOnAClientRole() {
        assertEquals(new Condition(Condition.Kind.ROLE, "restricted-app/access", null),
                Condition.parse("role:restricted-app/access"));
    }

    @Test
    void anchorsGroupPaths() {
        assertEquals(Condition.parse("group:/board"), Condition.parse("group:board"));
    }

    @Test
    void splitsAnAttributeFromItsValue() {
        assertEquals(new Condition(Condition.Kind.ATTRIBUTE, "department", "finance"),
                Condition.parse("attribute:department=finance"));
    }

    @Test
    void leavesTheValueOpenWhenNoneIsGiven() {
        assertEquals(new Condition(Condition.Kind.ATTRIBUTE, "department", null),
                Condition.parse("attribute:department"));
    }

    @Test
    void rejectsWhatItCannotRead() {
        assertThrows(IllegalArgumentException.class, () -> Condition.parse("staff"));
        assertThrows(IllegalArgumentException.class, () -> Condition.parse("role:"));
        assertThrows(IllegalArgumentException.class, () -> Condition.parse("team:staff"));
        assertThrows(IllegalArgumentException.class, () -> Condition.parse("attribute:=finance"));
    }
}
