package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class PolicyJsonTest {

    private static final String DOCUMENT = """
            {
              "version": 1,
              "default": [{ "deny": { "group": "/blocked" } }],
              "clients": {
                "restricted-app": [{ "allow": { "realmRole": "staff" } }, { "allow": { "group": "/board" } }],
                "open-app": []
              }
            }
            """;

    @Test
    void readsAClientsRules() {
        Policy policy = PolicyJson.parse(DOCUMENT);

        assertEquals(List.of(Rule.allow(Condition.realmRole("staff")), Rule.allow(Condition.group("/board"))),
                policy.forClient("restricted-app"));
    }

    @Test
    void tellsAnEmptyRuleListApartFromNoEntry() {
        Policy policy = PolicyJson.parse(DOCUMENT);

        assertTrue(policy.forClient("open-app").isEmpty());
        assertEquals(List.of(Rule.deny(Condition.group("/blocked"))), policy.forClient("some-other-app"));
    }

    @Test
    void keepsItsHandsOffKeycloaksOwnClientsUnlessTold() {
        Policy policy = PolicyJson.parse(DOCUMENT);

        assertTrue(policy.forClient("account-console").isEmpty());
        assertEquals(List.of(Rule.deny(Condition.group("/blocked"))), policy.forClient("some-other-app"));
    }

    @Test
    void takesTheExemptListADocumentGives() {
        Policy policy = PolicyJson.parse("""
                { "exempt": ["reporting"], "default": [{ "deny": { "group": "/blocked" } }] }
                """);

        assertTrue(policy.forClient("reporting").isEmpty());
        assertEquals(List.of(Rule.deny(Condition.group("/blocked"))), policy.forClient("account-console"));
    }

    @Test
    void takesAnEmptyExemptListAsExemptingNothing() {
        Policy policy = PolicyJson.parse("""
                { "exempt": [], "default": [{ "deny": { "group": "/blocked" } }] }
                """);

        assertEquals(List.of(Rule.deny(Condition.group("/blocked"))), policy.forClient("account-console"));
    }

    @Test
    void exemptionWinsOverAClientsOwnRules() {
        Policy policy = PolicyJson.parse("""
                { "exempt": ["reporting"], "clients": { "reporting": [{ "allow": { "realmRole": "staff" } }] } }
                """);

        assertTrue(policy.forClient("reporting").isEmpty());
    }

    @Test
    void takesADocumentWithoutClients() {
        assertTrue(PolicyJson.parse("{ \"default\": [] }").forClient("anything").isEmpty());
    }

    @Test
    void refusesAVersionItDoesNotRead() {
        assertThrows(IllegalArgumentException.class, () -> PolicyJson.parse("{ \"version\": 2 }"));
        assertThrows(IllegalArgumentException.class, () -> PolicyJson.parse("{ \"version\": \"1\" }"));
    }

    @Test
    void takesADocumentWithoutAVersion() {
        assertTrue(PolicyJson.parse("{ \"clients\": {} }").forClient("anything").isEmpty());
    }

    @Test
    void refusesAnExemptEntryThatIsNotAClientId() {
        assertThrows(IllegalArgumentException.class, () -> PolicyJson.parse("{ \"exempt\": [42] }"));
    }

    @Test
    void namesWhatItCannotRead() {
        assertThrows(IllegalArgumentException.class, () -> PolicyJson.parse("not json at all"));
        assertThrows(IllegalArgumentException.class, () -> PolicyJson.parse("{ \"clients\": [1, 2] }"));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyJson.parse("{ \"clients\": { \"app\": [{ \"maybe\": { \"realmRole\": \"staff\" } }] } }"));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyJson.parse("{ \"clients\": { \"app\": [{ \"allow\": { \"realmRole\": \"a\" }, \"deny\": { \"realmRole\": \"b\" } }] } }"));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyJson.parse("{ \"clients\": { \"app\": [{ \"allow\": \"staff\" }] } }"));
        assertThrows(IllegalArgumentException.class,
                () -> PolicyJson.parse("{ \"clients\": { \"app\": [{ \"allow\": { \"team\": \"x\" } }] } }"));
    }
}
