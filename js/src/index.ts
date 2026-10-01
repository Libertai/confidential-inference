/**
 * Talk to LibertAI inference running in a confidential VM, having first
 * established what it is.
 *
 *   import OpenAI from "openai";
 *   import { connect } from "@libertai/confidential-inference";
 *
 *   const tee = await connect({ model: "qwen3.8-27b" });
 *   const openai = new OpenAI({ apiKey, baseURL: tee.baseURL, fetch: tee.fetch });
 *
 * The client talks to the enclave directly. Nothing in between can read the
 * prompt, including LibertAI: an intermediary that could would defeat the
 * point of running the model in a TEE at all.
 */
export { AlephError, fetchMessage, fetchAggregate, verifyMessage } from "./aleph.js";
export { resolveDeployment, type Deployment } from "./deployment.js";
export {
  activeDeployments,
  fetchManifest,
  type DeploymentEntry,
  type Manifest,
} from "./manifest.js";
export {
  AttestationError,
  reportFacts,
  verifyCertificate,
  type ReportFacts,
  type TcbFloor,
  type VcekCache,
} from "./verify.js";
export { confidentialAgent, confidentialFetch } from "./connect.js";

import { resolveDeployment } from "./deployment.js";
import { activeDeployments, fetchManifest, type Manifest } from "./manifest.js";
import { confidentialFetch } from "./connect.js";
import { AttestationError, type TcbFloor } from "./verify.js";

export interface ConnectOptions {
  /** Model to reach, looked up in the publisher's manifest. */
  model?: string;
  /** A specific V-PROGRAM, bypassing the manifest. */
  itemHash?: string;
  publisher?: string;
  /** Use this manifest instead of fetching one. */
  manifest?: Manifest;
  api?: string;
  scheduler?: string;
  /** Reject platforms below this firmware level. */
  tcbFloor?: TcbFloor;
  signal?: AbortSignal;
}

export interface ConfidentialEndpoint {
  /** Pass to an OpenAI-compatible client; ends in `/v1`, as they expect. */
  baseURL: string;
  /** Pass alongside it: plain `fetch` would reach the same host unverified. */
  fetch: typeof globalThis.fetch;
  /** V-PROGRAM that answered. */
  itemHash: string;
  /** Launch measurement it proved, which is what pins the image and flags. */
  measurement: string;
  /** Commit the images were built from, when the manifest names one. */
  sourceCommit?: string;
}

/**
 * Find a deployment, prove what it is, and return a client-ready endpoint.
 *
 * Attestation happens on connection, not once here: the returned `fetch`
 * re-proves every new connection, so a deployment that is replaced under a
 * long-lived client cannot be followed by an unattested one.
 */
export async function connect(opts: ConnectOptions): Promise<ConfidentialEndpoint> {
  const entries = opts.itemHash
    ? [{ item_hash: opts.itemHash, source_commit: undefined, status: "active" as const }]
    : activeDeployments(
        opts.manifest ?? (await fetchManifest(opts)),
        required(opts.model, "connect() needs a model or an itemHash"),
      );

  const failures: string[] = [];
  for (const entry of entries) {
    let deployment;
    try {
      deployment = await resolveDeployment(entry.item_hash, {
        ...opts,
        sender: opts.publisher,
      });
    } catch (e) {
      failures.push(`${short(entry.item_hash)}: ${(e as Error).message}`);
      continue;
    }
    for (const origin of deployment.candidates) {
      let measurement: string | undefined;
      const fetch = confidentialFetch({
        measurements: deployment.measurements,
        tcbFloor: opts.tcbFloor,
        signal: opts.signal,
        onVerified: (m) => (measurement = m),
      });
      try {
        // Proving the peer needs a connection, and a connection needs a
        // request: this one is the cheapest the server offers. Any answer at
        // all settles it, because attestation happened before the request was
        // written -- a 401 from a deployment that checks API keys means the
        // enclave is exactly who it claims to be.
        const res = await fetch(`${origin}/v1/models`, { signal: opts.signal });
        await res.arrayBuffer();
        if (!measurement) throw new Error("connection reused without attestation");
        return {
          baseURL: `${origin}/v1`,
          fetch,
          itemHash: entry.item_hash,
          measurement: measurement!,
          sourceCommit: entry.source_commit,
        };
      } catch (e) {
        failures.push(`${origin}: ${(e as Error).message}`);
      }
    }
  }
  throw new AttestationError(
    `no deployment could be verified and reached:\n  ${failures.join("\n  ")}`,
  );
}

function required<T>(value: T | undefined, message: string): T {
  if (value === undefined) throw new Error(message);
  return value;
}

function short(hash: string): string {
  return hash.slice(0, 12);
}
