package de.verdigado.keycloak.clientloginpolicy;

import java.util.Optional;
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
 * `Client Login Policy` step of the flow that login would run. Empty when that
 * flow has no enabled step, so the policy would not run there at all.
 */
final class FlowPolicy {

    private FlowPolicy() {
    }

    static Optional<Policy> of(RealmModel realm, ClientModel client) {
        AuthenticationFlowModel flow = AuthenticationFlowResolver.resolveBindingOverrideFlowForClient(
                client, AuthenticationFlowBindings.BROWSER_BINDING);
        if (flow == null) {
            flow = realm.getBrowserFlow();
        }
        if (flow == null) {
            return Optional.empty();
        }

        return step(realm, flow.getId()).map(step -> ConfiguredPolicy.orClosed(configOf(realm, step)));
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
