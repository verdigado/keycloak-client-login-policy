package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class ClientRulesTest {

    @Test
    void holdsARestrictedClientToItsRules() {
        assertEquals(2, ClientRules.policy().forClient("restricted-app").size());
    }

    @Test
    void fallsBackToTheDefaultForEveryoneElse() {
        assertEquals(List.of(Rule.deny(Condition.attribute("guest", "TRUE"))), ClientRules.policy().forClient("demo-app"));
    }

    @Test
    void leavesKeycloaksOwnClientsAlone() {
        assertTrue(ClientRules.policy().forClient("account-console").isEmpty());
    }
}
