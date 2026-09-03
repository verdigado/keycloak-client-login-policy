import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";

import { parse, serialize } from "../policy.js";

const FIXTURES = fileURLToPath(new URL("../../testdata/policies/", import.meta.url));

function documentsIn(verdict) {
  const directory = join(FIXTURES, verdict);
  const names = readdirSync(directory).sort();
  assert.ok(names.length > 0, `no documents in testdata/policies/${verdict}/`);
  return names.map((name) => [name, readFileSync(join(directory, name), "utf8")]);
}

describe("the documents the provider accepts", () => {
  for (const [name, document] of documentsIn("accepted")) {
    test(name, () => {
      parse(document);
    });

    test(`${name}, written back out`, () => {
      const read = parse(document);
      assert.deepEqual(parse(serialize(read)), read);
    });
  }
});

describe("the documents the provider refuses", () => {
  for (const [name, document] of documentsIn("refused")) {
    test(name, () => {
      assert.throws(() => parse(document), (error) => {
        assert.ok(error instanceof Error);
        assert.ok(error.message.length > 0, "a refusal has to say something");
        return true;
      });
    });
  }
});
