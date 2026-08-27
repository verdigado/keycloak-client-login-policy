package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class ClientLoginRulesTest {

    @Test
    void namesTheRoleARestrictedClientDemands() {
        assertEquals("staff", ClientLoginRules.requiredRealmRole("restricted-app"));
    }

    @Test
    void leavesOtherClientsOpen() {
        assertNull(ClientLoginRules.requiredRealmRole("demo-app"));
    }
}
