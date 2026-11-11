package de.verdigado.keycloak.clientloginpolicy;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;

/**
 * Removes every client from the token's audience that the policy would not let
 * the user log in to, so a service that only receives tokens can rely on
 * {@code aud}. Other mappers decide what goes into the audience; this one runs
 * after all of them and only takes away. Mappers run whenever a token is
 * issued, so the answer is as fresh as the token.
 */
public class PolicyAudienceMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, TokenIntrospectionTokenMapper {

    private static final Logger log = Logger.getLogger(PolicyAudienceMapper.class);

    public static final String PROVIDER_ID = "client-login-policy-audience";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Client Login Policy Audience";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Removes each client from the audience (aud) that the client login policy would not let the user "
                + "log in to. Runs after every other mapper.";
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
        String[] audience = token.getAudience();
        if (audience == null || audience.length == 0) {
            return;
        }

        RealmModel realm = userSession.getRealm();
        Subject subject = new KeycloakSubject(realm, userSession.getUser());
        List<String> kept = kept(Arrays.asList(audience), subject, clientId -> policyFor(realm, clientId),
                userSession.getUser().getUsername());

        token.audience(kept.isEmpty() ? null : kept.toArray(String[]::new));
    }

    /**
     * The audience the user may keep. An entry the policy has no rules for —
     * not a client, or a client whose login never runs the policy — stays.
     */
    static List<String> kept(List<String> audience, Subject subject,
            Function<String, Optional<Policy>> policyFor, String username) {
        return audience.stream().filter(entry -> policyFor.apply(entry)
                .map(policy -> {
                    Decision decision = LoginPolicy.decide(policy, subject, entry);
                    if (!decision.allowed()) {
                        log.debugf("removing %s from the audience of %s: %s", entry, username, decision.reason());
                    }
                    return decision.allowed();
                })
                .orElse(true))
                .toList();
    }

    private static Optional<Policy> policyFor(RealmModel realm, String clientId) {
        ClientModel client = realm.getClientByClientId(clientId);
        return client == null ? Optional.empty() : FlowPolicy.of(realm, client);
    }
}
