package de.verdigado.keycloak.clientloginpolicy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

/**
 * Adds each target client to the token's audience if the policy would let the
 * user log in there, so a service that only receives tokens can tell from
 * {@code aud} alone. Mappers run whenever a token is issued, so the answer is
 * as fresh as the token.
 */
public class PolicyAudienceMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, TokenIntrospectionTokenMapper {

    private static final Logger log = Logger.getLogger(PolicyAudienceMapper.class);

    public static final String PROVIDER_ID = "client-login-policy-audience";

    static final String TARGETS = "targets";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty targets = new ProviderConfigProperty();
        targets.setName(TARGETS);
        targets.setLabel("Target clients");
        targets.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        targets.setHelpText("Client ids to add to the audience, each only if the client login policy "
                + "would let the user log in to that client.");
        CONFIG_PROPERTIES.add(targets);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, PolicyAudienceMapper.class);
    }

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
        return "Adds each target client to the audience (aud) if the client login policy lets the user in there.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
            KeycloakSession session, ClientSessionContext clientSessionCtx) {
        RealmModel realm = userSession.getRealm();
        String username = userSession.getUser().getUsername();
        Subject subject = new KeycloakSubject(realm, userSession.getUser());

        admitted(targets(mappingModel), subject, clientId -> policyFor(realm, clientId), username)
                .forEach(token::addAudience);
    }

    static List<String> targets(ProtocolMapperModel mappingModel) {
        String value = mappingModel.getConfig() == null ? null : mappingModel.getConfig().get(TARGETS);
        if (value == null) {
            return List.of();
        }
        return Arrays.stream(Constants.CFG_DELIMITER_PATTERN.split(value.strip()))
                .filter(target -> !target.isBlank())
                .toList();
    }

    /**
     * The targets the user may log in to. A target without a policy to ask is
     * left out, so a mistake in the setup cannot hand out access.
     */
    static Stream<String> admitted(List<String> targets, Subject subject,
            Function<String, Optional<Policy>> policyFor, String username) {
        return targets.stream().filter(clientId -> policyFor.apply(clientId)
                .map(policy -> {
                    Decision decision = LoginPolicy.decide(policy, subject, clientId);
                    log.debugf("%s %s audience %s: %s", username,
                            decision.allowed() ? "gets" : "does not get", clientId, decision.reason());
                    return decision.allowed();
                })
                .orElse(false));
    }

    private static Optional<Policy> policyFor(RealmModel realm, String clientId) {
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            log.warnf("realm %s has no client %s, leaving it out of the audience", realm.getName(), clientId);
            return Optional.empty();
        }
        if (!client.isEnabled()) {
            log.debugf("client %s is disabled, leaving it out of the audience", clientId);
            return Optional.empty();
        }

        Optional<Policy> policy = FlowPolicy.of(realm, client);
        if (policy.isEmpty()) {
            log.warnf("the browser flow of client %s has no enabled Client Login Policy step, "
                    + "leaving it out of the audience", clientId);
        }
        return policy;
    }
}
