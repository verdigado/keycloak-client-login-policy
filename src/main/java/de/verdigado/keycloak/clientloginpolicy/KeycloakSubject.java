package de.verdigado.keycloak.clientloginpolicy;

import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;

class KeycloakSubject implements Subject {

    private static final Logger log = Logger.getLogger(KeycloakSubject.class);

    private final RealmModel realm;
    private final UserModel user;

    KeycloakSubject(RealmModel realm, UserModel user) {
        this.realm = realm;
        this.user = user;
    }

    @Override
    public boolean hasRealmRole(String name) {
        return holds(realm.getRole(name), "realm role " + name);
    }

    @Override
    public boolean hasClientRole(String clientId, String name) {
        ClientModel client = realm.getClientByClientId(clientId);
        return holds(client == null ? null : client.getRole(name), "role " + name + " on client " + clientId);
    }

    @Override
    public Stream<String> realmRoleNames() {
        return heldRoles()
                .filter(RoleUtils::isRealmRole)
                .map(RoleModel::getName);
    }

    @Override
    public Stream<String> clientRoleNames(String clientId) {
        return heldRoles()
                .filter(role -> role.getContainer() instanceof ClientModel client
                        && client.getClientId().equals(clientId))
                .map(RoleModel::getName);
    }

    @Override
    public Stream<String> groupPaths() {
        return user.getGroupsStream().map(KeycloakModelUtils::buildGroupPath);
    }

    @Override
    public Stream<String> attributeValues(String name) {
        return user.getAttributeStream(name);
    }

    /** Everything the user holds, through groups and composites alike. */
    private Stream<RoleModel> heldRoles() {
        return RoleUtils.getDeepUserRoleMappings(user).stream();
    }

    private boolean holds(RoleModel role, String what) {
        if (role == null) {
            // A rule naming a role nobody can hold is one we cannot honour.
            log.warnf("realm %s has no %s", realm.getName(), what);
            return false;
        }
        // Covers roles held through a group and through a composite.
        return user.hasRole(role);
    }
}
