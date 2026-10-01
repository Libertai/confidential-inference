/**
 * The verification itself, plus the one thing it deliberately cannot do:
 * fetch. The core is compiled to WebAssembly so a browser and a Node client
 * run identical checks; network access is the host's, so the VCEK arrives as
 * an argument.
 */
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import * as wasm from "./wasm.js";
import type { ReportFacts } from "./wasm.js";

export type { ReportFacts };

export interface TcbFloor {
  bootloader: number;
  tee: number;
  snp: number;
  microcode: number;
}

export class AttestationError extends Error {}

/** Read a peer's report without judging it. */
export function reportFacts(certDer: Uint8Array): ReportFacts {
  return wasm.reportFacts(certDer);
}

/**
 * A VCEK is per-chip and per-firmware-version, so a handful of URLs covers a
 * fleet for as long as it goes unpatched. AMD rate-limits the KDS hard (on the
 * order of one request every few seconds), which makes caching a requirement
 * rather than an optimisation.
 */
export interface VcekCache {
  get(url: string): Promise<Uint8Array | undefined> | Uint8Array | undefined;
  set(url: string, vcek: Uint8Array): Promise<void> | void;
}

const memory = new Map<string, Uint8Array>();

/**
 * Memory, backed by disk. A restarting process that re-fetched every VCEK
 * would run into the rate limit quickly, and so would many clients sharing one
 * egress address. VCEKs are public certificates, so there is nothing here worth
 * protecting -- only a signature that is checked before the bytes are used.
 */
export const defaultVcekCache: VcekCache = {
  async get(url) {
    const hit = memory.get(url);
    if (hit) return hit;
    try {
      const vcek = new Uint8Array(await fs.readFile(cachePath(url)));
      memory.set(url, vcek);
      return vcek;
    } catch {
      return undefined;
    }
  },
  async set(url, vcek) {
    memory.set(url, vcek);
    try {
      const file = cachePath(url);
      await fs.mkdir(path.dirname(file), { recursive: true });
      await fs.writeFile(file, vcek);
    } catch {
      // A read-only or full disk costs a round trip, not correctness.
    }
  },
};

function cachePath(url: string): string {
  const name = createHash("sha256").update(url).digest("hex").slice(0, 32);
  return path.join(os.tmpdir(), "libertai-vcek", `${name}.der`);
}

/** AMD asks for roughly one request per second per address, and says so with a 429. */
const RETRY_DELAYS_MS = [1000, 3000, 7000];

async function loadVcek(url: string, cache: VcekCache, signal?: AbortSignal): Promise<Uint8Array> {
  const cached = await cache.get(url);
  if (cached) return cached;

  let last = "";
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url, { signal });
    if (res.ok) {
      const vcek = new Uint8Array(await res.arrayBuffer());
      await cache.set(url, vcek);
      return vcek;
    }
    last = `AMD KDS returned ${res.status}`;
    const retryable = res.status === 429 || res.status >= 500;
    if (!retryable || attempt >= RETRY_DELAYS_MS.length) break;
    await new Promise((r) => setTimeout(r, RETRY_DELAYS_MS[attempt]));
  }
  throw new AttestationError(`${last} for ${url}`);
}

export interface VerifyOptions {
  /** Launch measurements the deployment published; one must match. */
  measurements: string[];
  /** Reject platforms below this firmware level. */
  tcbFloor?: TcbFloor;
  cache?: VcekCache;
  signal?: AbortSignal;
}

/**
 * Establish that this certificate belongs to a guest AMD endorses, that is not
 * debuggable, that serves the key it attests to, and that booted one of the
 * published images. Returns the measurement that matched.
 */
export async function verifyCertificate(
  certDer: Uint8Array,
  opts: VerifyOptions,
): Promise<string> {
  let url: string;
  try {
    url = wasm.vcekUrl(certDer);
  } catch (e) {
    throw new AttestationError(`peer served no usable attestation: ${(e as Error).message}`);
  }
  const vcek = await loadVcek(url, opts.cache ?? defaultVcekCache, opts.signal);
  try {
    const matched = wasm.verify(certDer, vcek, opts.measurements);
    if (opts.tcbFloor) {
      const f = opts.tcbFloor;
      wasm.checkTcb(certDer, f.bootloader, f.tee, f.snp, f.microcode);
    }
    return matched;
  } catch (e) {
    throw new AttestationError((e as Error).message);
  }
}
