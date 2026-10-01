/**
 * Reading Aleph without trusting the node that serves it.
 *
 * Two properties make that possible: a message's item hash is the SHA-256 of
 * its content, and the message is signed by its sender's Ethereum key. So a
 * client can be handed a message by anyone and still establish that it is the
 * one a given address published.
 */
import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

/** Public Aleph API used when the caller names no other. */
export const DEFAULT_API = "https://api.aleph.im";

export interface AlephMessage {
  chain: string;
  sender: string;
  type: string;
  item_hash: string;
  item_type: string;
  item_content: string;
  signature: string;
  content?: unknown;
}

export class AlephError extends Error {}

/**
 * The content is what the hash names, and the sender really signed it.
 *
 * Only inline messages can be checked this way: a storage-backed one hashes
 * bytes that are not in the message, so its content would have to be fetched
 * and trusted separately.
 */
export function verifyMessage(message: AlephMessage, expectedSender?: string): unknown {
  if (message.item_type !== "inline") {
    throw new AlephError(`cannot verify a ${message.item_type} message offline`);
  }
  const digest = bytesToHex(sha256(utf8ToBytes(message.item_content)));
  if (digest !== message.item_hash) {
    throw new AlephError(`item hash mismatch: content hashes to ${digest}`);
  }
  const signer = recoverSender(message);
  if (signer.toLowerCase() !== message.sender.toLowerCase()) {
    throw new AlephError(`signed by ${signer}, not by ${message.sender}`);
  }
  if (expectedSender && signer.toLowerCase() !== expectedSender.toLowerCase()) {
    throw new AlephError(`published by ${signer}, not by ${expectedSender}`);
  }
  return JSON.parse(message.item_content);
}

/**
 * Aleph signs the fields that identify a message, not the content itself; the
 * content is covered because the item hash is part of the buffer.
 */
function recoverSender(message: AlephMessage): string {
  const buffer = [message.chain, message.sender, message.type, message.item_hash].join("\n");
  const prefixed = utf8ToBytes(`\x19Ethereum Signed Message:\n${buffer.length}${buffer}`);
  const digest = keccak_256(prefixed);

  const sig = hexToBytes(message.signature);
  if (sig.length !== 65) throw new AlephError(`signature is ${sig.length} bytes, expected 65`);
  // EIP-155 style v values also appear here; only the low bit is the parity.
  const recovery = sig[64] >= 27 ? sig[64] - 27 : sig[64];
  const point = secp256k1.Signature.fromCompact(sig.slice(0, 64))
    .addRecoveryBit(recovery)
    .recoverPublicKey(digest);
  // An Ethereum address is the last 20 bytes of the keccak of the raw point.
  const raw = point.toRawBytes(false).slice(1);
  return "0x" + bytesToHex(keccak_256(raw).slice(-20));
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function getJson(url: string, signal?: AbortSignal): Promise<any> {
  const res = await fetch(url, { signal });
  if (!res.ok) throw new AlephError(`${url} returned ${res.status}`);
  return res.json();
}

/** Fetch one message by hash and establish that it is what that hash names. */
export async function fetchMessage(
  itemHash: string,
  opts: { api?: string; sender?: string; signal?: AbortSignal } = {},
): Promise<unknown> {
  const api = opts.api ?? DEFAULT_API;
  const body = await getJson(`${api}/api/v0/messages.json?hashes=${itemHash}`, opts.signal);
  const message: AlephMessage | undefined = body.messages?.[0];
  if (!message) throw new AlephError(`message ${itemHash} not found`);
  return verifyMessage(message, opts.sender);
}

/**
 * The manifest this address published under `key`, verified.
 *
 * Aleph merges an aggregate from every message that ever targeted the key, so
 * a client that wants to verify signatures itself cannot use the merged view
 * the API serves: the merge is the node's work, not the publisher's. Instead,
 * each publish carries the complete manifest and the newest signed message
 * wins. The node can withhold an update, but it cannot forge one, and a
 * withheld update is why a deployment is revoked by deleting the V-PROGRAM
 * rather than by editing this.
 */
export async function fetchAggregate(
  address: string,
  key: string,
  opts: { api?: string; signal?: AbortSignal } = {},
): Promise<unknown> {
  const api = opts.api ?? DEFAULT_API;
  const url =
    `${api}/api/v0/messages.json?addresses=${address}&msgType=AGGREGATE&pagination=50&page=1`;
  const body = await getJson(url, opts.signal);

  let newest: { time: number; content: unknown } | undefined;
  for (const message of (body.messages ?? []) as AlephMessage[]) {
    let content: { key?: string; content?: unknown; time?: number };
    try {
      content = verifyMessage(message, address) as typeof content;
    } catch {
      // A message we cannot verify is one we must not read, but it says
      // nothing about the others.
      continue;
    }
    if (content.key !== key) continue;
    const time = content.time ?? 0;
    if (!newest || time > newest.time) newest = { time, content: content.content };
  }
  if (!newest) throw new AlephError(`${address} published no aggregate under key "${key}"`);
  return newest.content;
}
