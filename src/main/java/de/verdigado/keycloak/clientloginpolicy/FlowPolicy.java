package de.verdigado.keycloak.clientloginpolicy;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowBindings;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.AuthenticationFlowResolver;

/**
 * The policy a browser login to a client would be held to, read from the
 * `Client Login Policy` step of the flow that login would run. Empty for a
 * value that is not a client, and when that flow has no enabled step, so the
 * policy would not run there at all.
 */
final class FlowPolicy {

    private FlowPolicy() {
    }

    /**
     * Reads each flow once, however many of the clients asked about share it,
     * so it should live no longer than one token.
     */
    static Function<String, Optional<Policy>> byClientId(RealmModel realm) {
        Map<String, Optional<Policy>> byFlow = new HashMap<>();
        return clientId -> {
            ClientModel client = realm.getClientByClientId(clientId);
            AuthenticationFlowModel flow = client == null ? null : browserFlow(realm, client);
            return flow == null
                    ? Optional.empty()
                    : byFlow.computeIfAbsent(flow.getId(), id -> inFlow(realm, id));
        };
    }

    private static AuthenticationFlowModel browserFlow(RealmModel realm, ClientModel client) {
        AuthenticationFlowModel flow = AuthenticationFlowResolver.resolveBindingOverrideFlowForClient(
                client, AuthenticationFlowBindings.BROWSER_BINDING);
        return flow != null ? flow : realm.getBrowserFlow();
    }

    private static Optional<Policy> inFlow(RealmModel realm, String flowId) {
        return step(realm, flowId).map(step -> ConfiguredPolicy.orClosed(configOf(realm, step)));
    }

    private static AuthenticatorConfigModel configOf(RealmModel realm, AuthenticationExecutionModel step) {
        String id = step.getAuthenticatorConfig();
        return id == null ? null : realm.getAuthenticatorConfigById(id);
    }

    /** The first enabled policy step, searched through the enabled sub-flows in order. */
    private static Optional<AuthenticationExecutionModel> step(RealmModel realm, String flowId) {
        return realm.getAuthenticationExecutionsStream(flowId)
                .filter(AuthenticationExecutionModel::isEnabled)
                .flatMap(execution -> execution.isAuthenticatorFlow()
                        ? step(realm, execution.getFlowId()).stream()
                        : Stream.of(execution).filter(FlowPolicy::isPolicyStep))
                .findFirst();
    }

    private static boolean isPolicyStep(AuthenticationExecutionModel execution) {
        return ClientLoginPolicyAuthenticatorFactory.PROVIDER_ID.equals(execution.getAuthenticator());
    }
}
