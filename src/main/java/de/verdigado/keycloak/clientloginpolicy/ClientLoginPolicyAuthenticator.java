package de.verdigado.keycloak.clientloginpolicy;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

public class ClientLoginPolicyAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(ClientLoginPolicyAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        Decision decision = LoginPolicy.decide(ClientRules.policy(), new KeycloakSubject(realm, user), clientId);

        if (decision.allowed()) {
            log.debugf("%s may log in to %s: %s", user.getUsername(), clientId, decision.reason());
            context.success();
            return;
        }

        log.infof("%s may not log in to %s: %s", user.getUsername(), clientId, decision.reason());
        context.getEvent().user(user).error(Errors.NOT_ALLOWED);
        Response challenge = context.form()
                .setError(Messages.ACCESS_DENIED)
                .createErrorPage(Response.Status.FORBIDDEN);
        context.failure(AuthenticationFlowError.ACCESS_DENIED, challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
