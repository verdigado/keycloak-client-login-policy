package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;

class PolicyAudienceMapperTest {

    private static final Subject GUEST = withAttributes(Map.of("guest", "TRUE"));
    private static final Subject MEMBER = withAttributes(Map.of());

    private static final Policy NO_GUESTS = new Policy(Set.of("account"),
            List.of(Rule.deny(Condition.attribute("guest", "TRUE"))), Map.of());

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

    private static List<String> admitted(Subject subject, Function<String, Optional<Policy>> policyFor,
            String... targets) {
        return PolicyAudienceMapper.admitted(List.of(targets), subject, policyFor, "someone").toList();
    }

    private static ProtocolMapperModel mapperWithTargets(String targets) {
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(targets == null ? Map.of() : Map.of(PolicyAudienceMapper.TARGETS, targets));
        return model;
    }

    @Test
    void keepsItsProviderId() {
        assertEquals("client-login-policy-audience", new PolicyAudienceMapper().getId());
    }

    @Test
    void readsTheTargetsAsTheAdminConsoleStoresThem() {
        assertEquals(List.of("wolke", "drupal"), PolicyAudienceMapper.targets(mapperWithTargets("wolke##drupal")));
        assertEquals(List.of("wolke"), PolicyAudienceMapper.targets(mapperWithTargets("wolke")));
        assertEquals(List.of(), PolicyAudienceMapper.targets(mapperWithTargets("")));
        assertEquals(List.of(), PolicyAudienceMapper.targets(mapperWithTargets(null)));
    }

    @Test
    void addsATargetOnlyForUsersThePolicyLetsIn() {
        assertEquals(List.of("wolke"), admitted(MEMBER, clientId -> Optional.of(NO_GUESTS), "wolke"));
        assertEquals(List.of(), admitted(GUEST, clientId -> Optional.of(NO_GUESTS), "wolke"));
    }

    @Test
    void decidesEachTargetByItsOwnRules() {
        Policy wolkeForGuests = new Policy(Set.of(), List.of(Rule.deny(Condition.attribute("guest", "TRUE"))),
                Map.of("wolke", List.of()));

        assertEquals(List.of("wolke"), admitted(GUEST, clientId -> Optional.of(wolkeForGuests), "drupal", "wolke"));
    }

    @Test
    void honoursUserOverrides() {
        Subject invitedGuest = withAttributes(Map.of("guest", "TRUE", UserOverride.ALLOW_ATTRIBUTE, "wolke"));

        assertEquals(List.of("wolke"), admitted(invitedGuest, clientId -> Optional.of(NO_GUESTS), "wolke"));
    }

    @Test
    void addsAnExemptTargetForEveryone() {
        assertEquals(List.of("account"), admitted(GUEST, clientId -> Optional.of(NO_GUESTS), "account"));
    }

    @Test
    void leavesOutATargetWithoutAPolicyToAsk() {
        assertTrue(admitted(MEMBER, clientId -> Optional.empty(), "wolke").isEmpty());
    }

    @Test
    void leavesOutEveryTargetWhenTheDocumentIsBroken() {
        assertTrue(admitted(MEMBER, clientId -> Optional.of(Policy.CLOSED), "wolke").isEmpty());
    }
}
