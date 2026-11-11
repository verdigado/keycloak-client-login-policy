package de.verdigado.keycloak.clientloginpolicy;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;

/**
 * Removes every client from the token's audience and client roles that the
 * policy would not let the user log in to, so a service that only receives
 * tokens can rely on {@code aud} and {@code resource_access}. Other mappers
 * decide what goes into the token; this one runs after all of them and only
 * takes away. Mappers run whenever a token is issued, so the answer is as
 * fresh as the token.
 */
public class PolicyAudienceFilter extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, TokenIntrospectionTokenMapper {

    private static final Logger log = Logger.getLogger(PolicyAudienceFilter.class);

    public static final String PROVIDER_ID = "client-login-policy-audience-filter";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Client Login Policy Audience Filter";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Removes each client from the audience (aud) and the client roles (resource_access) that the "
                + "client login policy would not let the user log in to. Runs after every other mapper.";
    }

    /**
     * No settings, not even Keycloak's usual switches for which tokens a mapper
     * applies to: turning one off would quietly switch the filter off.
     */
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    /** Last, so the audience is complete before it is filtered. */
    @Override
    public int getPriority() {
        return Integer.MAX_VALUE;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel,
            KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        filter(token, userSession);
        return token;
    }

    @Override
    public AccessToken transformIntrospectionToken(AccessToken token, ProtocolMapperModel mappingModel,
            KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        filter(token, userSession);
        return token;
    }

    private static void filter(AccessToken token, UserSessionModel userSession) {
        RealmModel realm = userSession.getRealm();
        UserModel user = userSession.getUser();
        filter(token, mayKeep(new KeycloakSubject(realm, user), FlowPolicy.byClientId(realm), user.getUsername()));
    }

    /**
     * Takes each client the user may not keep out of both the audience and the
     * client roles, since a service may go by either.
     */
    static void filter(AccessToken token, Predicate<String> mayKeep) {
        String[] audience = token.getAudience();
        if (audience != null) {
            List<String> kept = Arrays.stream(audience).filter(mayKeep).toList();
            token.audience(kept.isEmpty() ? null : kept.toArray(String[]::new));
        }
        token.getResourceAccess().keySet().removeIf(mayKeep.negate());
    }

    /**
     * Whether the user may keep a client in the token. An entry the policy has
     * no rules for — not a client, or a client whose login never runs the
     * policy — stays. Each entry is decided once, since the audience and the
     * client roles mostly name the same clients.
     */
    static Predicate<String> mayKeep(Subject subject, Function<String, Optional<Policy>> policyFor,
            String username) {
        Map<String, Boolean> decided = new HashMap<>();
        return entry -> decided.computeIfAbsent(entry, e -> mayKeep(subject, policyFor.apply(e), e, username));
    }

    private static boolean mayKeep(Subject subject, Optional<Policy> policy, String entry, String username) {
        if (policy.isEmpty()) {
            return true;
        }
        Decision decision = LoginPolicy.decide(policy.get(), subject, entry);
        if (!decision.allowed()) {
            log.debugf("removing %s from the token of %s: %s", entry, username, decision.reason());
        }
        return decision.allowed();
    }
}
