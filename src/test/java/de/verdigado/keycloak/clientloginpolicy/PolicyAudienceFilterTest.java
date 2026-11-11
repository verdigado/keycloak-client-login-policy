package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.AccessToken;

class PolicyAudienceFilterTest {

    private static final Subject GUEST = withAttributes(Map.of("guest", "TRUE"));
    private static final Subject MEMBER = withAttributes(Map.of());

    private static final Policy NO_GUESTS = new Policy(Set.of("account"),
            List.of(Rule.deny(Condition.attribute("guest", "TRUE"))), Map.of());

    private static final Function<String, Optional<Policy>> EVERY_CLIENT_NO_GUESTS = clientId -> Optional.of(NO_GUESTS);

    private static Subject withAttributes(Map<String, String> attributes) {
        return new Subject() {

            @Override
            public boolean hasRealmRole(String role) {
                return false;
            }

            @Override
            public boolean hasClientRole(String clientId, String role) {
                return false;
            }

            @Override
            public Stream<String> realmRoleNames() {
                return Stream.empty();
            }

            @Override
            public Stream<String> clientRoleNames(String clientId) {
                return Stream.empty();
            }

            @Override
            public Stream<String> groupPaths() {
                return Stream.empty();
            }

            @Override
            public Stream<String> attributeValues(String attribute) {
                return Stream.ofNullable(attributes.get(attribute));
            }
        };
    }

    private static List<String> kept(Subject subject, Function<String, Optional<Policy>> policyFor,
            String... audience) {
        return Stream.of(audience).filter(PolicyAudienceFilter.mayKeep(subject, policyFor, "someone")).toList();
    }

    private static AccessToken filtered(Subject subject, AccessToken token) {
        PolicyAudienceFilter.filter(token, PolicyAudienceFilter.mayKeep(subject, EVERY_CLIENT_NO_GUESTS, "someone"));
        return token;
    }

    @Test
    void keepsItsProviderId() {
        assertEquals("client-login-policy-audience-filter", new PolicyAudienceFilter().getId());
    }

    @Test
    void runsAfterEveryOtherMapper() {
        assertEquals(Integer.MAX_VALUE, new PolicyAudienceFilter().getPriority());
    }

    @Test
    void offersNoSwitchToTurnTheFilterOff() {
        assertEquals(List.of(), new PolicyAudienceFilter().getConfigProperties());
    }

    @Test
    void removesAClientThePolicyKeepsTheUserOutOf() {
        assertEquals(List.of("wolke"), kept(MEMBER, EVERY_CLIENT_NO_GUESTS, "wolke"));
        assertEquals(List.of(), kept(GUEST, EVERY_CLIENT_NO_GUESTS, "wolke"));
    }

    @Test
    void decidesEachEntryByItsOwnRules() {
        Policy wolkeForGuests = new Policy(Set.of(), List.of(Rule.deny(Condition.attribute("guest", "TRUE"))),
                Map.of("wolke", List.of()));

        assertEquals(List.of("wolke"), kept(GUEST, clientId -> Optional.of(wolkeForGuests), "drupal", "wolke"));
    }

    @Test
    void honoursUserOverrides() {
        Subject invitedGuest = withAttributes(Map.of("guest", "TRUE", UserOverride.ALLOW_ATTRIBUTE, "wolke"));

        assertEquals(List.of("wolke"), kept(invitedGuest, EVERY_CLIENT_NO_GUESTS, "wolke"));
    }

    @Test
    void keepsAnExemptClient() {
        assertEquals(List.of("account"), kept(GUEST, EVERY_CLIENT_NO_GUESTS, "account", "wolke"));
    }

    @Test
    void keepsAnEntryWithoutAPolicyToAsk() {
        Function<String, Optional<Policy>> onlyWolke = clientId -> clientId.equals("wolke")
                ? Optional.of(NO_GUESTS)
                : Optional.empty();

        assertEquals(List.of("https://api.example.org"), kept(GUEST, onlyWolke, "https://api.example.org", "wolke"));
    }

    @Test
    void removesEveryClientButTheExemptOnesWhenTheDocumentIsBroken() {
        assertEquals(List.of("account"), kept(MEMBER, clientId -> Optional.of(Policy.CLOSED), "wolke", "account"));
    }

    @Test
    void keepsTheOrderOfWhatStays() {
        assertEquals(List.of("a", "b", "c"), kept(MEMBER, EVERY_CLIENT_NO_GUESTS, "a", "b", "c"));
    }

    @Test
    void removesTheClientRolesOfAClientThePolicyKeepsTheUserOutOf() {
        AccessToken token = new AccessToken();
        token.addAccess("wolke").addRole("user");
        token.addAccess("account").addRole("manage-account");

        assertEquals(Set.of("account"), filtered(GUEST, token).getResourceAccess().keySet());
    }

    @Test
    void decidesClientRolesEvenWithoutAnAudience() {
        AccessToken token = new AccessToken();
        token.addAccess("wolke").addRole("user");

        AccessToken result = filtered(GUEST, token);

        assertNull(result.getAudience());
        assertEquals(Set.of(), result.getResourceAccess().keySet());
    }

    @Test
    void dropsTheAudienceWhenNothingIsLeft() {
        AccessToken token = new AccessToken();
        token.audience("wolke", "drupal");

        assertNull(filtered(GUEST, token).getAudience());
    }

    @Test
    void leavesWhatTheUserMayKeepAlone() {
        AccessToken token = new AccessToken();
        token.audience("wolke");
        token.addAccess("wolke").addRole("user");

        AccessToken result = filtered(MEMBER, token);

        assertEquals(List.of("wolke"), List.of(result.getAudience()));
        assertEquals(Set.of("user"), result.getResourceAccess("wolke").getRoles());
    }

    @Test
    void decidesAClientInBothTheAudienceAndTheRolesOnce() {
        List<String> asked = new ArrayList<>();
        AccessToken token = new AccessToken();
        token.audience("wolke");
        token.addAccess("wolke").addRole("user");

        PolicyAudienceFilter.filter(token, PolicyAudienceFilter.mayKeep(GUEST, clientId -> {
            asked.add(clientId);
            return Optional.of(NO_GUESTS);
        }, "someone"));

        assertEquals(List.of("wolke"), asked);
    }
}
