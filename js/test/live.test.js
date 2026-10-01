// Opt-in: this one talks to a running deployment and to AMD.
//   LIBERTAI_ITEM_HASH=<hash> node --test test/live.test.js
import { test } from "node:test";
import assert from "node:assert/strict";

import { connect } from "../dist/index.js";

const itemHash = process.env.LIBERTAI_ITEM_HASH;

test("a live deployment can be reached only once it is proved", { skip: !itemHash }, async () => {
  const tee = await connect({ itemHash });
  assert.match(tee.baseURL, /^https:\/\/.+\/v1$/);
  assert.equal(tee.measurement.length, 96);

  const res = await tee.fetch(`${tee.baseURL}/models`);
  assert.equal(res.status, 200);
  assert.ok((await res.json()).data.length > 0);
});
