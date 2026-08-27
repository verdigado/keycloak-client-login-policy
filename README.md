# Keycloak Client Login Policy

A Keycloak provider that decides which users may log in to which client, based on user data such as roles and groups.

## Setup

Take the jar from the [latest release](https://github.com/verdigado/keycloak-client-login-policy/releases/latest), copy it into the `providers/` directory of your Keycloak and restart it. A jar's filename says which Keycloak version it belongs on.

The policy is a step in an authentication flow, and Keycloak runs it only where you put it. Per realm:

1. Duplicate the browser flow.
2. Add a sub-flow at the top level, set it to Required, and move the existing top-level entries — Cookie, Kerberos, Identity Provider Redirector, Organization, forms — into it. They keep their own requirements.
3. Add the `Client Login Policy` execution at the top level, below that sub-flow, set to Required.
4. Bind the copy as the realm's browser flow.

The result:

```
browser with login policy
├── authenticate                     Required
│   ├── Cookie                       Alternative
│   ├── Identity Provider Redirector Alternative
│   └── forms                        Alternative
│       └── Username Password Form   Required
└── Client Login Policy              Required
```

The sub-flow is not decoration. Keycloak ignores every Alternative at a level that also holds a Required step, so putting the policy next to Cookie and forms means no username form is ever shown and no user is ever set — the login fails before the policy can decide anything.

At the top level and last, the policy runs whichever way the user got in: a fresh password login, an identity provider, or an existing SSO session being reused for another client.

Flows are bound per protocol. The browser flow covers the standard flow and the device authorization grant. Clients with direct access grants enabled bypass it — to cover those, build the direct grant flow the same way and bind it too. Token refresh and token exchange issue tokens without running any flow, so a user who logged in before a policy change keeps their access until the session or refresh token expires.

## Development

Needed: a JDK, 17 or newer — `sudo apt install openjdk-21-jdk-headless`, a JRE is not enough — and Docker with the compose plugin. Maven comes from the checked-in wrapper.

```sh
make up      # keycloak on :8080 (admin/password)
make build   # package, load the jar, restart keycloak
make test
make logs
```

A fresh `make up` starts Keycloak without the provider: it is picked up from `dev/providers/`, which stays empty until `make build` fills it. Java changes need `make build` too — Keycloak cannot hot-reload providers. A remote debugger can attach on port 8787.

The `dev` realm in `dev/import/` is imported on first start; `make reset` wipes the database so a changed import is picked up again. It has two clients (`demo-app`, `restricted-app`), a `staff` realm role, two groups, and the users `alice` and `bob`, both with the password `password`. It ships the flow above already bound, so logging in as alice leaves a line in `make logs`.

## Releases

The Keycloak this is built against lives in `<keycloak.version>` in [pom.xml](pom.xml) and nowhere else in prose. A version is `<keycloak.version>-<n>`: that Keycloak, plus a counter that starts at 1 for each new Keycloak and goes up with every release against it.

To release:

1. bump `<revision>` in [pom.xml](pom.xml), commit
2. `git tag v<revision> && git push origin v<revision>`

Pushing the tag builds, checks the tag against `<revision>`, and publishes the release with the jar attached. A Keycloak upgrade means bumping `<keycloak.version>` as well and restarting the counter at `-1`; the build refuses versions where the two disagree.
