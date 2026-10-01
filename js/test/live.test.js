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
});

test("the enclave refuses an unauthenticated request", { skip: !itemHash }, async () => {
  // Proof that the API-key gateway is what answers, not vLLM: verification
  // succeeded, the channel is attested, and the request is still refused.
  const tee = await connect({ itemHash });
  const res = await tee.fetch(`${tee.baseURL}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model: "qwen3.8-27b", messages: [] }),
  });
  assert.equal(res.status, 401);
});
