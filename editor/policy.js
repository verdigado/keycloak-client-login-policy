/**
 * Reads and writes the policy document, the same way the provider does.
 *
 * `parse` turns a document into the model the form binds to, or throws with a
 * reason. `serialize` turns that model back into a document. The two are held
 * to the documents under `testdata/policies/`, which the provider's own tests
 * read as well: whatever this accepts, a realm can be run on.
 *
 * The model:
 *
 *     { version, exempt, fallback, clients }
 *
 * `exempt` is null when the document left it out, which means Keycloak's own
 * clients. `fallback` are the rules for clients without an entry. A rule is
 * `{ effect, condition }`, a condition `{ kind, name, ... , match }`.
 */

const VERSION = 1;

/**
 * What the provider leaves alone when a document names no exempt clients. A
 * document that names any replaces this list rather than adding to it.
 */
export const KEYCLOAK_CLIENTS = [
  "account",
  "account-console",
  "security-admin-console",
  "admin-cli",
  "broker",
];

export function parse(document) {
  const root = readJson(document);

  requireKnownVersion(root.version);

  return {
    version: VERSION,
    exempt: exempt(root.exempt),
    fallback: rules(root.default, "default"),
    clients: Object.fromEntries(
      Object.entries(asMap(root.clients, "clients"))
        .map(([clientId, entry]) => [clientId, rules(entry, `client ${clientId}`)])
    ),
  };
}

export function serialize(policy) {
  return JSON.stringify({
    version: VERSION,
    ...(policy.exempt === null ? {} : { exempt: policy.exempt }),
    ...(policy.fallback.length === 0 ? {} : { default: policy.fallback.map(writeRule) }),
    clients: Object.fromEntries(
      Object.entries(policy.clients).map(([clientId, list]) => [clientId, list.map(writeRule)])
    ),
  }, null, 2);
}

/** An empty document, ready for the form to fill. */
export function empty() {
  return { version: VERSION, exempt: null, fallback: [], clients: {} };
}

function readJson(document) {
  let root;
  try {
    root = JSON.parse(document);
  } catch (e) {
    throw new Error(`policy is not readable json: ${e.message}`);
  }
  if (!isMap(root)) {
    throw new Error("document must be a mapping");
  }
  return root;
}

function requireKnownVersion(value) {
  if (value === undefined || value === null) {
    return;
  }
  if (typeof value !== "number" || Math.trunc(value) !== VERSION) {
    throw new Error(
      `policy version ${JSON.stringify(value)} is not one this provider reads, which is ${VERSION}`);
  }
}

function exempt(value) {
  if (value === undefined || value === null) {
    return null;
  }
  if (!Array.isArray(value)) {
    throw new Error("exempt must be a list of client ids");
  }
  return value.map((entry) => {
    if (typeof entry !== "string") {
      throw new Error(`exempt lists client ids, got ${JSON.stringify(entry)}`);
    }
    return entry;
  });
}

function rules(value, where) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(`${where} must be a list of rules`);
  }
  return value.map((entry) => rule(entry, where));
}

function rule(entry, where) {
  const fields = asMap(entry, `${where} rule`);
  const keys = Object.keys(fields);
  if (keys.length !== 1) {
    throw new Error(`${where}: a rule is one allow or one deny, got [${keys.join(", ")}]`);
  }

  const [effect] = keys;
  if (effect !== "allow" && effect !== "deny") {
    throw new Error(`${where}: a rule is allow or deny, got '${effect}'`);
  }

  return { effect, condition: condition(asMap(fields[effect], `${where} condition`)) };
}

function condition(fields) {
  const mode = text(fields, "match");

  if ("realmRole" in fields) {
    only(fields, "realmRole", ["realmRole", "match"]);
    return { kind: "realmRole", name: required(fields, "realmRole"), match: match(fields.realmRole, mode) };
  }
  if ("clientRole" in fields) {
    only(fields, "clientRole", ["clientRole", "client", "match"]);
    return {
      kind: "clientRole",
      client: text(fields, "client") ?? null,
      name: required(fields, "clientRole"),
      match: match(fields.clientRole, mode),
    };
  }
  if ("group" in fields) {
    only(fields, "group", ["group", "match"]);
    const path = required(fields, "group");
    const how = match(path, mode);
    return { kind: "group", name: how === "regex" ? path : anchor(path), match: how };
  }
  if ("attribute" in fields) {
    only(fields, "attribute", ["attribute", "value", "match"]);
    const value = text(fields, "value") ?? null;
    return {
      kind: "attribute",
      name: required(fields, "attribute"),
      value,
      // With no value there is nothing to compare, so the provider never looks
      // at the mode either.
      match: value === null ? mode ?? "exact" : match(value, mode),
    };
  }
  throw new Error("a condition names a realmRole, a clientRole, a group or an attribute, got "
    + `[${Object.keys(fields).join(", ")}]`);
}

/** A path takes everything nested under it with it, so it starts at the root. */
function anchor(path) {
  return path.startsWith("/") ? path : `/${path}`;
}

function match(pattern, mode) {
  if (mode === undefined || mode === null || mode === "exact") {
    return "exact";
  }
  if (mode !== "regex") {
    throw new Error(`match is exact or regex, got '${mode}'`);
  }
  try {
    // Only to have a broken pattern reported here rather than at a login. The
    // provider compiles it with Java, which reads a few things differently.
    new RegExp(pattern);
  } catch (e) {
    throw new Error(`'${pattern}' is not a regular expression: ${e.message}`);
  }
  return "regex";
}

/** So that a stray or contradictory key is reported rather than ignored. */
function only(fields, kind, known) {
  for (const key of Object.keys(fields)) {
    if (!known.includes(key)) {
      throw new Error(`a ${kind} condition has no use for '${key}'`);
    }
  }
}

function required(fields, key) {
  const value = text(fields, key);
  if (value === null || value === undefined || value.trim() === "") {
    throw new Error(`${key} has no value`);
  }
  return value;
}

function text(fields, key) {
  const value = fields[key];
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "string") {
    throw new Error(`${key} must be text, got ${JSON.stringify(value)}`);
  }
  return value;
}

function asMap(value, where) {
  if (value === undefined || value === null) {
    return {};
  }
  if (!isMap(value)) {
    throw new Error(`${where} must be a mapping`);
  }
  return value;
}

function isMap(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function writeRule({ effect, condition }) {
  return { [effect]: writeCondition(condition) };
}

function writeCondition(condition) {
  const mode = condition.match === "exact" ? {} : { match: condition.match };

  switch (condition.kind) {
    case "realmRole":
      return { realmRole: condition.name, ...mode };
    case "clientRole":
      return {
        clientRole: condition.name,
        ...(condition.client === null ? {} : { client: condition.client }),
        ...mode,
      };
    case "group":
      return { group: condition.name, ...mode };
    case "attribute":
      return {
        attribute: condition.name,
        ...(condition.value === null ? {} : { value: condition.value }),
        ...mode,
      };
    default:
      throw new Error(`no such condition: ${condition.kind}`);
  }
}
