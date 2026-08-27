package de.verdigado.keycloak.clientloginpolicy;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

public class ClientLoginPolicyAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(ClientLoginPolicyAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        String requiredRole = ClientLoginRules.requiredRealmRole(clientId);

        if (requiredRole == null) {
            context.success();
            return;
        }

        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        RoleModel role = realm.getRole(requiredRole);

        if (role == null) {
            // Denying is the safe reading of a rule we cannot evaluate.
            log.warnf("%s requires realm role '%s', which does not exist in realm %s",
                    clientId, requiredRole, realm.getName());
            deny(context);
            return;
        }

        if (user.hasRole(role)) {
            context.success();
            return;
        }

        log.infof("%s may not log in to %s: realm role '%s' missing",
                user.getUsername(), clientId, requiredRole);
        deny(context);
    }

    private void deny(AuthenticationFlowContext context) {
        context.getEvent().user(context.getUser()).error(Errors.NOT_ALLOWED);
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
