package de.verdigado.keycloak.clientloginpolicy;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class ClientLoginPolicyAuthenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(ClientLoginPolicyAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String clientId = context.getAuthenticationSession().getClient().getClientId();

        log.infof("client-login-policy: hello, %s is logging in to %s",
                user == null ? "an unknown user" : user.getUsername(), clientId);

        context.success();
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
