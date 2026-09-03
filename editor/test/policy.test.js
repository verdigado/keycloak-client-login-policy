import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { parse, serialize } from "../policy.js";

describe("what a document turns into", () => {
  test("a rule is an effect and a condition", () => {
    const policy = parse(`{ "clients": { "app": [{ "allow": { "realmRole": "staff" } }] } }`);

    assert.deepEqual(policy.clients.app, [
      { effect: "allow", condition: { kind: "realmRole", name: "staff", match: "exact" } },
    ]);
  });

  test("a client role names no client when it means the one being logged into", () => {
    assert.deepEqual(condition(`{ "clientRole": "access" }`),
      { kind: "clientRole", client: null, name: "access", match: "exact" });
    assert.deepEqual(condition(`{ "clientRole": "access", "client": "intranet" }`),
      { kind: "clientRole", client: "intranet", name: "access", match: "exact" });
  });

  test("an attribute without a value means set to anything", () => {
    assert.deepEqual(condition(`{ "attribute": "department" }`),
      { kind: "attribute", name: "department", value: null, match: "exact" });
  });

  test("a group path is anchored, unless it is a pattern", () => {
    assert.equal(condition(`{ "group": "board" }`).name, "/board");
    assert.equal(condition(`{ "group": "^board$", "match": "regex" }`).name, "^board$");
  });
});

describe("what a document leaves out", () => {
  test("no exempt list means Keycloak's own clients, and is not the same as an empty one", () => {
    assert.equal(parse("{}").exempt, null);
    assert.deepEqual(parse(`{ "exempt": [] }`).exempt, []);
  });

  test("a client with no rules is not the same as a client with no entry", () => {
    const policy = parse(`{ "clients": { "open-app": [] } }`);

    assert.deepEqual(policy.clients["open-app"], []);
    assert.equal("restricted-app" in policy.clients, false);
  });

  test("the order clients were written in is kept", () => {
    const policy = parse(`{ "clients": { "b": [], "a": [], "c": [] } }`);

    assert.deepEqual(Object.keys(policy.clients), ["b", "a", "c"]);
  });
});

describe("what it says when it cannot read a document", () => {
  test("it names the key it has no use for", () => {
    assert.match(refusal(`{ "clients": { "app": [{ "allow": { "realmRole": "staff", "client": "x" } }] } }`),
      /client/);
  });

  test("it names the client whose rules are wrong", () => {
    assert.match(refusal(`{ "clients": { "reporting": [{ "maybe": {} }] } }`), /reporting/);
  });

  test("it passes on why a pattern does not compile", () => {
    assert.match(refusal(`{ "clients": { "app": [{ "allow": { "group": "[", "match": "regex" } }] } }`),
      /\[/);
  });
});

describe("writing a document back out", () => {
  test("it comes back as readable json", () => {
    const text = serialize(parse(`{ "version": 1, "clients": { "app": [{ "deny": { "group": "/blocked" } }] } }`));

    assert.deepEqual(JSON.parse(text), {
      version: 1,
      clients: { app: [{ deny: { group: "/blocked" } }] },
    });
  });

  test("it leaves out what the document did not say", () => {
    assert.deepEqual(JSON.parse(serialize(parse("{}"))), { version: 1, clients: {} });
  });

  test("it keeps an exempt list that was written, empty or not", () => {
    assert.deepEqual(JSON.parse(serialize(parse(`{ "exempt": [] }`))).exempt, []);
  });
});

function condition(text) {
  return parse(`{ "clients": { "app": [{ "allow": ${text} }] } }`).clients.app[0].condition;
}

function refusal(text) {
  return assert.throws(() => parse(text), Error).message;
}
