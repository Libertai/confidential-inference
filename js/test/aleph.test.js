// The message is a real one, published by the account that runs the
// deployments, so these fail if Aleph's signing or hashing rules drift.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { verifyMessage, AlephError } from "../dist/aleph.js";

const message = JSON.parse(readFileSync(new URL("fixtures/vprogram-message.json", import.meta.url)));
const SENDER = "0x238224C744F4b90b4494516e074D2676ECfC6803";

test("a published message verifies against its sender", () => {
  const content = verifyMessage(message, SENDER);
  assert.equal(content.verification.backend, "sev_snp");
  assert.equal(content.verification.measurements.length, 2);
});

test("content that does not hash to the item hash is refused", () => {
  const tampered = { ...message, item_content: message.item_content.replace("sev_snp", "sev_snq") };
  assert.throws(() => verifyMessage(tampered, SENDER), AlephError);
});

test("a message is refused when another address claims it", () => {
  assert.throws(
    () => verifyMessage(message, "0x0000000000000000000000000000000000000001"),
    /published by 0x238224/,
  );
});

test("a forged signature is refused", () => {
  // Flipping a byte of r leaves a well-formed signature that recovers some
  // other key, which is the failure this has to catch.
  const sig = message.signature;
  const flipped = sig.slice(0, 10) + (sig[10] === "a" ? "b" : "a") + sig.slice(11);
  assert.throws(() => verifyMessage({ ...message, signature: flipped }, SENDER), AlephError);
});
