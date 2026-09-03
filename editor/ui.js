import { KEYCLOAK_CLIENTS, empty, parse, serialize } from "./policy.js";

/**
 * The form and the document are two views of one draft. A change to either
 * redraws the other, so neither can go stale.
 *
 * The draft keeps clients as a list rather than a mapping, so that renaming one
 * cannot silently drop another and the order stays as it was typed.
 */
let draft = fromModel(empty());

const form = {
  exemptList: document.getElementById("exempt-list"),
  exemptNone: document.getElementById("exempt-none"),
  exemptHint: document.getElementById("exempt-hint"),
  fallback: document.getElementById("fallback"),
  clients: document.getElementById("clients"),
};
const json = document.getElementById("json");
const status = document.getElementById("status");

const KINDS = {
  realmRole: "realm role",
  clientRole: "client role",
  group: "group",
  attribute: "attribute",
};

function fromModel(model) {
  return {
    exempt: model.exempt,
    fallback: model.fallback,
    clients: Object.entries(model.clients).map(([id, rules]) => ({ id, rules })),
  };
}

function toModel() {
  return {
    version: 1,
    exempt: draft.exempt,
    fallback: draft.fallback,
    clients: Object.fromEntries(draft.clients.map(({ id, rules }) => [id, rules])),
  };
}

function el(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children.flat().filter((child) => child !== null));
  return node;
}

function select(options, chosen, onChange) {
  const node = el("select", { onchange: (event) => onChange(event.target.value) },
    Object.entries(options).map(([value, label]) => el("option", { value, textContent: label })));
  node.value = chosen;
  return node;
}

function textField(value, placeholder, onInput) {
  return el("input", {
    type: "text",
    value: value ?? "",
    placeholder,
    title: placeholder,
    ariaLabel: placeholder,
    spellcheck: false,
    oninput: (event) => {
      onInput(event.target.value);
      writeDocument();
    },
  });
}

function newCondition(kind) {
  switch (kind) {
    case "realmRole":
      return { kind, name: "", match: "exact" };
    case "clientRole":
      return { kind, client: null, name: "", match: "exact" };
    case "group":
      return { kind, name: "", match: "exact" };
    case "attribute":
      return { kind, name: "", value: null, match: "exact" };
  }
}

/**
 * The row reads as a sentence, so the comparison sits where it is spoken:
 * "allow realm role is staff", "allow attribute department is finance".
 */
function conditionFields(condition) {
  const how = select({ exact: "is", regex: "matches" }, condition.match, (value) => {
    condition.match = value;
    redraw();
  });

  switch (condition.kind) {
    case "realmRole":
      return [how, textField(condition.name, "role name", (value) => (condition.name = value))];
    case "clientRole":
      return [
        how,
        textField(condition.name, "role name", (value) => (condition.name = value)),
        textField(condition.client, "on the client entered", (value) => (condition.client = value || null)),
      ];
    case "group":
      return [how, textField(condition.name, "/path/to/group", (value) => (condition.name = value))];
    case "attribute":
      return [
        textField(condition.name, "attribute name", (value) => (condition.name = value)),
        how,
        textField(condition.value, "any value", (value) => (condition.value = value || null)),
      ];
  }
}

function ruleRow(rules, index) {
  const rule = rules[index];

  return el("div", { className: "rule" },
    select({ allow: "allow", deny: "deny" }, rule.effect, (value) => {
      rule.effect = value;
      redraw();
    }),
    select(KINDS, rule.condition.kind, (value) => {
      rule.condition = newCondition(value);
      redraw();
    }),
    conditionFields(rule.condition),
    el("button", {
      type: "button",
      className: "drop",
      title: "Remove this rule",
      textContent: "×",
      onclick: () => {
        rules.splice(index, 1);
        redraw();
      },
    }));
}

function rulesEditor(rules) {
  return el("div", {},
    rules.length === 0 ? el("p", { className: "empty", textContent: "No rules, so per default a client allows all logins." }) : null,
    rules.map((_, index) => ruleRow(rules, index)),
    el("button", {
      type: "button",
      textContent: "Add a rule",
      onclick: () => {
        rules.push({ effect: "allow", condition: newCondition("realmRole") });
        redraw();
      },
    }));
}

function clientEditor(client, index) {
  return el("div", { className: "client" },
    el("div", { className: "client-head" },
      textField(client.id, "client id", (value) => (client.id = value)),
      el("button", {
        type: "button",
        title: "Remove this client",
        textContent: "×",
        onclick: () => {
          draft.clients.splice(index, 1);
          redraw();
        },
      })),
    rulesEditor(client.rules));
}

function renderForm() {
  form.exemptList.value = (draft.exempt ?? []).join("\n");
  renderExempt();

  form.fallback.replaceChildren(rulesEditor(draft.fallback));
  form.clients.replaceChildren(
    draft.clients.length === 0
      ? el("p", { className: "empty", textContent: "No client has rules of its own yet." })
      : el("div", {}, draft.clients.map(clientEditor)));
}

/** Everything about the exempt card except the box itself, which is typed in. */
function renderExempt() {
  const listed = KEYCLOAK_CLIENTS.join(", ");
  const hint = form.exemptHint;

  form.exemptNone.checked = draft.exempt !== null && draft.exempt.length === 0;

  if (draft.exempt === null) {
    hint.textContent = `Left empty, the policy skips Keycloak's own clients: ${listed}. `
      + "That is what keeps an admin from being shut out of the console.";
    hint.classList.remove("warn");
    return;
  }
  if (draft.exempt.length === 0) {
    hint.textContent = "This document skips no client at all, not even Keycloak's own. "
      + "A default rule that keeps an admin out would keep them out of the console too.";
    hint.classList.add("warn");
    return;
  }
  const missing = KEYCLOAK_CLIENTS.filter((id) => !draft.exempt.includes(id));
  hint.textContent = missing.length === 0
    ? "This list replaces Keycloak's own clients rather than adding to them, and covers all of them."
    : "This list replaces Keycloak's own clients rather than adding to them, so "
      + `${missing.join(", ")} are now covered by the policy like any other client.`;
  hint.classList.toggle("warn", missing.length > 0);
}

function writeDocument() {
  json.value = serialize(toModel());
  report();
}

/** Says whether the document as it stands is one the provider would read. */
function report() {
  const repeated = draft.clients
    .map(({ id }) => id)
    .filter((id, index, all) => all.indexOf(id) !== index);

  if (repeated.length > 0) {
    return say(`'${repeated[0]}' is listed twice, and only the last of them would count.`, false);
  }

  try {
    parse(json.value);
    say("Ready to paste into the Policy field.", true);
  } catch (error) {
    say(error.message, false);
  }
}

function say(message, good) {
  status.textContent = message;
  status.classList.toggle("bad", !good);
}

function redraw() {
  renderForm();
  writeDocument();
}

form.exemptList.oninput = () => {
  const listed = form.exemptList.value.split("\n").map((line) => line.trim()).filter(Boolean);
  // An empty box on its own says nothing, which leaves Keycloak's own clients
  // exempt. Saying "nothing at all" is what the checkbox below is for.
  draft.exempt = listed.length > 0 ? listed : form.exemptNone.checked ? [] : null;
  renderExempt();
  writeDocument();
};

form.exemptNone.onchange = () => {
  draft.exempt = form.exemptNone.checked ? [] : null;
  redraw();
};

document.getElementById("add-client").onclick = () => {
  draft.clients.push({ id: "", rules: [] });
  redraw();
};

// The form follows the document, but the document is left exactly as typed —
// reformatting it under the cursor would make it unusable to type in.
json.oninput = () => {
  try {
    draft = fromModel(parse(json.value));
  } catch (error) {
    say(error.message, false);
    return;
  }
  renderForm();
  report();
};

document.getElementById("copy").onclick = async () => {
  try {
    await navigator.clipboard.writeText(json.value);
    say("Copied.", true);
  } catch {
    json.select();
    say("Could not reach the clipboard. The document is selected, so copy it yourself.", false);
  }
};

redraw();
