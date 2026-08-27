# Keycloak Client Login Policy

A Keycloak provider that decides which users may log in to which client, based on the user's roles, groups and attributes.

## What it covers

The policy runs as a step in an authentication flow, and flows are bound per protocol. In the browser flow it covers interactive logins for OIDC and SAML, including the device authorization grant, and it also runs when a user with an existing SSO session opens a second client without seeing a login form.

- Clients with direct access grants enabled skip the browser flow. To cover them, build the direct grant flow the same way and bind it too.
- Token refresh and token exchange issue tokens without running a flow, so a user who logged in before you changed the policy keeps access until the session or the refresh token expires.

## Policy

The rules are one JSON document per realm, entered in the settings of the `Client Login Policy` step — see [Setup](#setup). An empty document lets everyone in, and an edit applies to the next login.

```json
{
  "version": 1,
  "exempt": ["reporting"],
  "default": [{ "deny": { "group": "/blocked" } }],
  "clients": {
    "restricted-app": [
      { "allow": { "realmRole": "staff" } },
      { "allow": { "clientRole": "access" } },
      { "allow": { "group": "/board" } },
      { "allow": { "attribute": "department", "value": "finance" } }
    ],
    "open-app": []
  }
}
```

- `clients` holds the rules per client.
- `default` holds the rules for every client without an entry of its own.
- `exempt` lists clients the policy skips completely, even when they have an entry under `clients`.
- `version` is the format version, currently `1`. It can be left out, and any other value is refused.

Leave `exempt` out and Keycloak's own clients are used: `account`, `account-console`, `security-admin-console`, `admin-cli` and `broker`. A default rule that denies would otherwise lock users out of their account page and admins out of the console. Writing the key replaces that list, and `[]` exempts nothing.

Each client can have a list of allow and deny rules:

- a matching deny rule prevents the login
- if a client has allow rules, the user has to match at least one of them
- a client with no rules lets everyone in

A rule is one `allow` or one `deny`, plus the condition a user has to match:

- `{"realmRole": "staff"}` — a realm role
- `{"clientRole": "access"}` — a client role on the client being logged into, or `{"clientRole": "access", "client": "intranet"}` for a role on a client you name
- `{"group": "/board"}` — a group, including its subgroups
- `{"attribute": "department", "value": "finance"}` — an attribute set to that value, or `{"attribute": "department"}` for any value at all

Roles that a user holds through a group or through a composite role count. An attribute matches when any of its values matches, and values are compared exactly. Names and values are separate fields, so a group path or an attribute value can contain any character.

> [!IMPORTANT]
> Attribute conditions only work if the realm lets the provider read the attribute. Declare it in the realm's user profile, or enable unmanaged attributes. Keycloak drops undeclared attributes without a word, so a rule naming one silently never matches.

### Matching by pattern

`"match": "regex"` compares by regular expression instead of by exact text, against the role name, the group path or the attribute value:

```json
{ "allow": { "realmRole": "^tenant-[0-9]+-staff$", "match": "regex" } }
{ "allow": { "group": "^/tenants/[^/]+/staff$", "match": "regex" } }
```

The pattern has to match the whole name or path, otherwise `staff` would also match `not-staff`. A pattern is compiled when the document is read, so a broken one is a configuration error rather than a broken login.

Two differences to exact matching:

- a pattern on a group matches that one path, while a plain path also covers its subgroups
- a pattern on a role is slower: with a role named outright, Keycloak looks that one role up, while a pattern needs every role the user effectively holds

### Per-user exceptions

Two user attributes overrule the policy for one person, without touching the document. Both hold client ids, one value per client:

- `client-login-policy.allow` — this user gets in, whatever the client's rules say
- `client-login-policy.deny` — this user is kept out, whatever the client's rules say

A deny beats an allow, and both beat the client's rules. Ignored clients stay reachable even here, so an exception cannot lock someone out of the account console.

A user who is kept out gets an access denied page, and the login is recorded as a `not_allowed` event.

### When the policy document is broken

Keycloak has no way for a provider to check an authenticator's configuration while it is being saved, so the document is read on the next login instead. Until then the admin console accepts anything.

A document that cannot be read keeps everyone out, and the reason is logged at error level. Its own exempt list cannot be read either, so the built-in list of Keycloak's own clients applies — that is what keeps the admin console reachable while the document is being fixed.

## Setup

Take the jar from the [latest release](https://github.com/verdigado/keycloak-client-login-policy/releases/latest), copy it into the `providers/` directory of your Keycloak and restart it. A jar's filename says which Keycloak version it belongs on.

The policy is a step in an authentication flow, and Keycloak runs it only where you put it. Per realm:

1. Duplicate the browser flow.
2. Add a sub-flow at the top level, set it to Required, and move the existing top-level entries into it — Cookie, Kerberos, Identity Provider Redirector, Organization, forms. They keep their own requirements.
3. Add the `Client Login Policy` execution at the top level, below that sub-flow, and set it to Required.
4. Open its settings with the gear icon on its row, give the configuration an alias, and paste the [policy document](#the-policy-document) into the **Policy** field. It is stored with the flow, so a realm export takes it along.
5. Bind the copy as the realm's browser flow.

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

The extra sub-flow is needed. Keycloak ignores every Alternative on a level that also holds a Required step, so putting the policy next to Cookie and forms means no username form is ever shown and no user is ever set — the login fails before the policy decides anything.

At the top level and last, the policy runs whichever way the user got in: a fresh password login, an identity provider, or an SSO session reused for another client.

## Development

Needed: a JDK, 17 or newer — `sudo apt install openjdk-21-jdk-headless`, a JRE is not enough — and Docker with the compose plugin. Maven comes from the checked-in wrapper.

```sh
make up      # keycloak on :8080 (admin/password)
make build   # package, load the jar, restart keycloak
make test
make logs
```

A fresh `make up` starts Keycloak without the provider: it is picked up from `dev/providers/`, which stays empty until `make build` fills it. Java changes need `make build` too — Keycloak cannot reload providers while it runs. A remote debugger can attach on port 8787.

The `dev` realm in `dev/import/` is imported on first start; `make reset` wipes the database so a changed import is read again. It has two clients (`demo-app`, `restricted-app`), a `staff` realm role, two groups, and the users `alice` and `bob`, both with the password `password`. The flow above is already bound, with its document in the step's configuration, so logging in as alice leaves a line in `make logs`.

Optional: `make keycloak-src` clones the Keycloak this builds against into `.keycloak-src/`, so its SPI sources and its own providers can be read and searched locally. The build and the dev loop do not need it.

## Releases

The Keycloak this is built against lives in `<keycloak.version>` in [pom.xml](pom.xml) and nowhere else in prose. A version is `<keycloak.version>-<n>`: that Keycloak, plus a counter that starts at 1 for each new Keycloak and goes up with every release against it.

To release:

1. bump `<revision>` in [pom.xml](pom.xml), commit
2. `git tag v<revision> && git push origin v<revision>`

Pushing the tag builds, checks the tag against `<revision>`, and publishes the release with the jar attached. A Keycloak upgrade means bumping `<keycloak.version>` as well and restarting the counter at `-1`; the build refuses versions where the two disagree.
