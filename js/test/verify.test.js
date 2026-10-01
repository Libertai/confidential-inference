// Fixtures captured from the live H200 deployment: the RA-TLS certificate it
// served and the VCEK AMD issued for that chip and firmware.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { verifyCertificate, reportFacts, AttestationError } from "../dist/verify.js";

const cert = new Uint8Array(readFileSync(new URL("fixtures/ratls-cert.der", import.meta.url)));
const vcek = new Uint8Array(readFileSync(new URL("fixtures/vcek.der", import.meta.url)));
const message = JSON.parse(readFileSync(new URL("fixtures/vprogram-message.json", import.meta.url)));
const MEASUREMENTS = JSON.parse(message.item_content).verification.measurements.map(
  (m) => m.registers.launch,
);

// Nothing here may reach AMD: the fixture VCEK is the only one these tests use.
const cache = { get: () => vcek, set: () => {} };

test("the live certificate verifies against its published measurements", async () => {
  const matched = await verifyCertificate(cert, { measurements: MEASUREMENTS, cache });
  assert.ok(MEASUREMENTS.includes(matched));
});

test("a peer running another image is refused", async () => {
  await assert.rejects(
    verifyCertificate(cert, { measurements: ["00".repeat(48)], cache }),
    AttestationError,
  );
});

test("a platform below the firmware floor is refused", async () => {
  const { reportedTcb } = reportFacts(cert);
  await assert.rejects(
    verifyCertificate(cert, {
      measurements: MEASUREMENTS,
      cache,
      tcbFloor: { ...reportedTcb, snp: reportedTcb.snp + 1 },
    }),
    /firmware is/,
  );
});

test("a report edited to claim a published measurement loses AMD's signature", async () => {
  // The closest thing to a real attack: take a genuine enclave's certificate
  // and rewrite the measurement to one the client accepts. The report is hex
  // inside the extension, so the edit is a single character.
  const text = Buffer.from(cert).toString("latin1");
  const data = text.indexOf('"data":"') + '"data":"'.length;
  assert.ok(data > 8, "report not found in certificate");
  const measurement = data + 0x90 * 2; // MEASUREMENT is at offset 0x90 of the report
  const forged = Uint8Array.from(cert);
  assert.match(String.fromCharCode(forged[measurement]), /[0-9a-f]/);
  forged[measurement] = forged[measurement] === 0x61 ? 0x62 : 0x61; // a <-> b

  const facts = reportFacts(forged);
  assert.notEqual(facts.measurement, reportFacts(cert).measurement, "the edit landed");
  await assert.rejects(
    verifyCertificate(forged, { measurements: [facts.measurement], cache }),
    /AMD does not endorse/,
  );
});

test("the report describes a non-debuggable Genoa guest", () => {
  const facts = reportFacts(cert);
  assert.equal(facts.product, "Genoa");
  assert.equal(facts.debugAllowed, false);
  assert.equal(facts.measurement.length, 96);
});
