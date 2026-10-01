/**
 * The verification itself, plus the one thing it deliberately cannot do:
 * fetch. The core is compiled to WebAssembly so a browser and a Node client
 * run identical checks; network access is the host's, so the VCEK arrives as
 * an argument.
 */
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const wasm = require("../vendor/node/cic.js") as {
  verify(cert: Uint8Array, vcek: Uint8Array, expected: string[]): string;
  vcekUrl(cert: Uint8Array): string;
  checkTcb(cert: Uint8Array, bl: number, tee: number, snp: number, ucode: number): void;
  reportFacts(cert: Uint8Array): ReportFacts;
};

export interface ReportFacts {
  product: string;
  measurement: string;
  chipId: string;
  reportData: string;
  debugAllowed: boolean;
  smtAllowed: boolean;
  reportedTcb: { bootloader: number; tee: number; snp: number; microcode: number };
}

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
export const defaultVcekCache: VcekCache = {
  get: (url) => memory.get(url),
  set: (url, vcek) => void memory.set(url, vcek),
};

async function loadVcek(url: string, cache: VcekCache, signal?: AbortSignal): Promise<Uint8Array> {
  const cached = await cache.get(url);
  if (cached) return cached;
  const res = await fetch(url, { signal });
  if (!res.ok) throw new AttestationError(`AMD KDS returned ${res.status} for ${url}`);
  const vcek = new Uint8Array(await res.arrayBuffer());
  await cache.set(url, vcek);
  return vcek;
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
