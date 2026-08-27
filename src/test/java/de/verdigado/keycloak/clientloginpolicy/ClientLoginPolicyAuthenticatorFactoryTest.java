package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;

class ClientLoginPolicyAuthenticatorFactoryTest {

    private final ClientLoginPolicyAuthenticatorFactory factory = new ClientLoginPolicyAuthenticatorFactory();

    @Test
    void keepsItsProviderId() {
        assertEquals("client-login-policy", factory.getId());
    }

    @Test
    void offersRequiredAndDisabled() {
        assertArrayEquals(new Requirement[] { Requirement.REQUIRED, Requirement.DISABLED },
                factory.getRequirementChoices());
    }

    @Test
    void createsAnAuthenticator() {
        assertNotNull(factory.create(null));
    }
}
