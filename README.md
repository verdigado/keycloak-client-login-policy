# Keycloak Client Login Policy

A Keycloak provider that decides which users may log in to which client, based on user data such as roles and groups.

Each client is held to a list of rules:

- A user matching any `deny` rule is turned away, whatever else matches.
- Otherwise, a client with `allow` rules admits only users matching one of them.
- A client with no rules admits everyone, and so does a client with no policy of its own — those fall back to the default policy.

A condition names one of three things:

- `{"role": "staff"}` for a realm role, `{"role": "access", "client": "intranet"}` for a client role, held on that client whichever client is being logged into — roles inherited through a group or a composite count
- `{"group": "/board"}`, which also covers everything nested under it
- `{"attribute": "department", "value": "finance"}`, or `{"attribute": "department"}` for any value at all — values are compared exactly, and one matching value is enough for a multi-valued attribute

Names and values are separate fields, so a group path or an attribute value may contain whatever characters it likes.

Adding `"match": "regex"` compares by regular expression instead of literally — against the role name, the group path or the attribute value, and the whole of it has to match:

```json
{ "allow": { "role": "^tenant-[0-9]+-staff$", "match": "regex" } }
{ "allow": { "group": "^/tenants/[^/]+/staff$", "match": "regex" } }
```

A pattern that does not compile is refused when the policy is read, not when someone logs in. Two things to keep in mind: a regex on a group path matches that path only, where a literal path also covers everything nested under it; and a regex on roles has to expand every role the user holds, where a literal name is a single cheap lookup.

Attributes only work if the realm lets the provider read them: declare the attribute in the realm's user profile, or set unmanaged attributes to enabled. Keycloak silently drops undeclared attributes otherwise, and a rule naming one will never match.


### Per-user exceptions

Two user attributes overrule the policy for one person, without touching the document. Both hold client ids, one value per client:

- `client-login-policy.allow` — this user gets in, whatever the client's rules say
- `client-login-policy.deny` — this user is turned away, whatever the client's rules say

A deny beats an allow, and both beat the client's rules. Exempt clients are left alone even here, so an override cannot lock someone out of the account console.

Users turned away get an access denied page and the login is recorded as a `not_allowed` event.

The policy is written as a JSON document:

```json
{
  "version": 1,
  "exempt": ["reporting"],
  "default": [{ "deny": { "group": "/blocked" } }],
  "clients": {
    "restricted-app": [
      { "allow": { "role": "staff" } },
      { "allow": { "role": "access", "client": "intranet" } },
      { "allow": { "group": "/board" } },
      { "allow": { "attribute": "department", "value": "finance" } }
    ],
    "open-app": []
  }
}
```

`version` says which reading of the document to apply. It may be left out while there is only one, and a document naming a version this provider does not read is refused rather than half-understood.

`exempt` lists clients the policy skips, `default` holds the rules for clients without an entry of their own, and a client listed with an empty list admits everyone.

Leave `exempt` out and it holds Keycloak's own clients — `account`, `account-console`, `security-admin-console`, `admin-cli` and `broker`. A `default` that denies would otherwise shut people out of their own account page and admins out of the console. Write the key to replace that list, including with `[]` to exempt nothing. An exempt client is left alone even if it has an entry under `clients`.

The document is still hardcoded in the provider — reading it from configuration comes next.

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

Optional: `make keycloak-src` clones the Keycloak this builds against into `.keycloak-src/`, so the SPI sources and Keycloak's own providers can be read and searched locally. Nothing in the build or the dev loop needs it.

## Releases

The Keycloak this is built against lives in `<keycloak.version>` in [pom.xml](pom.xml) and nowhere else in prose. A version is `<keycloak.version>-<n>`: that Keycloak, plus a counter that starts at 1 for each new Keycloak and goes up with every release against it.

To release:

1. bump `<revision>` in [pom.xml](pom.xml), commit
2. `git tag v<revision> && git push origin v<revision>`

Pushing the tag builds, checks the tag against `<revision>`, and publishes the release with the jar attached. A Keycloak upgrade means bumping `<keycloak.version>` as well and restarting the counter at `-1`; the build refuses versions where the two disagree.
