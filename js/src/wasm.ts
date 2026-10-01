/**
 * The verification core, compiled to WebAssembly. Everything security-critical
 * lives behind this boundary so that each client language wraps one
 * implementation instead of writing its own.
 */
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

export interface ReportFacts {
  product: string;
  measurement: string;
  chipId: string;
  reportData: string;
  debugAllowed: boolean;
  smtAllowed: boolean;
  reportedTcb: { bootloader: number; tee: number; snp: number; microcode: number };
}

interface Core {
  verify(cert: Uint8Array, vcek: Uint8Array, expected: string[]): string;
  vcekUrl(cert: Uint8Array): string;
  checkTcb(cert: Uint8Array, bl: number, tee: number, snp: number, ucode: number): void;
  reportFacts(cert: Uint8Array): ReportFacts;
  verifyAlephMessage(messageJson: string, sender?: string): string;
}

const core = require("../vendor/node/cic.js") as Core;

export const { verify, vcekUrl, checkTcb, reportFacts, verifyAlephMessage } = core;
