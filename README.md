# keycloak-client-login-policy

A Keycloak provider that decides which users may log in to which client, based on user data such as roles and groups.

The Keycloak this is built against lives in `<keycloak.version>` in [pom.xml](pom.xml) and nowhere else in prose.

## Requirements

- a JDK, 17 or newer — `sudo apt install openjdk-21-jdk-headless`. A JRE is not enough.
- Docker with the compose plugin.

Maven itself comes from the checked-in wrapper, so it does not need installing.

## Dev loop

```sh
make up      # keycloak on :8080 (admin/password)
make build   # package, load the jar, restart keycloak
make test
make logs
```

A fresh `make up` starts Keycloak without the provider: it is picked up from `dev/providers/`, which stays empty until `make build` fills it. Java changes need `make build` too — Keycloak cannot hot-reload providers. A remote debugger can attach on port 8787.

The `dev` realm in `dev/import/` is imported on first start; `make reset` wipes the database so a changed import is picked up again. It has two clients (`demo-app`, `restricted-app`), a `staff` realm role, two groups, and the users `alice` and `bob`, both with the password `password`.

The provider is not in any flow by default. To reach it: in the `dev` realm, duplicate the browser flow, add the "Client Login Policy" step after the forms sub-flow, set it to Required, and bind the copy as the browser flow. Logging in as alice then leaves a line in `make logs`.

## Releases

A version is `<keycloak.version>-<n>`: the Keycloak it was built against, plus a counter that starts at 1 for each new Keycloak and goes up with every release against it. A jar's filename therefore says which Keycloak it belongs on.

To release:

1. bump `<revision>` in [pom.xml](pom.xml), commit
2. `git tag v<revision> && git push origin v<revision>`

Pushing the tag builds, checks the tag against `<revision>`, and publishes the release with the jar attached. A Keycloak upgrade means bumping `<keycloak.version>` as well and restarting the counter at `-1`; the build refuses versions where the two disagree.

## Deploy

Take the jar from the release, copy it into the `providers/` directory of the target instance and restart it.
