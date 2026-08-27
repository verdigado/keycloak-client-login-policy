package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;

class ConfiguredPolicyTest {

    private static AuthenticatorConfigModel configuredWith(String document) {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(document == null ? Map.of() : Map.of(ConfiguredPolicy.DOCUMENT, document));
        return config;
    }

    @Test
    void saysNothingAboutAnyoneWithoutADocument() {
        assertSame(Policy.OPEN, ConfiguredPolicy.of(null));
        assertSame(Policy.OPEN, ConfiguredPolicy.of(configuredWith(null)));
        assertSame(Policy.OPEN, ConfiguredPolicy.of(configuredWith("   ")));
    }

    @Test
    void readsTheConfiguredDocument() {
        Policy policy = ConfiguredPolicy.of(configuredWith("""
                { "clients": { "restricted-app": [{ "allow": { "realmRole": "staff" } }] } }
                """));

        assertEquals(List.of(Rule.allow(Condition.realmRole("staff"))), policy.forClient("restricted-app"));
    }

    @Test
    void keepsWhatItAlreadyRead() {
        String document = "{ \"clients\": { \"a\": [{ \"deny\": { \"group\": \"/blocked\" } }] } }";

        assertSame(ConfiguredPolicy.of(configuredWith(document)), ConfiguredPolicy.of(configuredWith(document)));
    }

    @Test
    void refusesADocumentItCannotRead() {
        assertThrows(IllegalArgumentException.class, () -> ConfiguredPolicy.of(configuredWith("{ oops")));
    }

    @Test
    void turnsEveryoneAwayWhenTheDocumentIsBroken() {
        Subject nobody = new Subject() {

            @Override
            public boolean hasRealmRole(String name) {
                return false;
            }

            @Override
            public boolean hasClientRole(String clientId, String name) {
                return false;
            }

            @Override
            public java.util.stream.Stream<String> realmRoleNames() {
                return java.util.stream.Stream.empty();
            }

            @Override
            public java.util.stream.Stream<String> clientRoleNames(String clientId) {
                return java.util.stream.Stream.empty();
            }

            @Override
            public java.util.stream.Stream<String> groupPaths() {
                return java.util.stream.Stream.empty();
            }

            @Override
            public java.util.stream.Stream<String> attributeValues(String name) {
                return java.util.stream.Stream.empty();
            }
        };

        assertEquals(false, LoginPolicy.decide(Policy.CLOSED, nobody, "demo-app").allowed());
        assertEquals(true, LoginPolicy.decide(Policy.CLOSED, nobody, "account-console").allowed());
    }
}
