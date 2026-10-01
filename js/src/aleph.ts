/**
 * Fetching Aleph messages. Deciding whether to believe them happens in the
 * verification core, which JavaScript, Rust and any future client share, so
 * that hashing and signature rules have one implementation rather than one per
 * language.
 */
import { verifyAlephMessage } from "./wasm.js";

/** Public Aleph API used when the caller names no other. */
export const DEFAULT_API = "https://api.aleph.im";

export class AlephError extends Error {}

/**
 * The content is what the hash names, and the sender really signed it.
 * Takes a message as the API returns it.
 */
export function verifyMessage(message: unknown, expectedSender?: string): unknown {
  let content: string;
  try {
    content = verifyAlephMessage(JSON.stringify(message), expectedSender);
  } catch (e) {
    throw new AlephError((e as Error).message);
  }
  return JSON.parse(content);
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
  const message = body.messages?.[0];
  if (!message) throw new AlephError(`message ${itemHash} not found`);
  return verifyMessage(message, opts.sender);
}

/**
 * The manifest this address published under `key`, verified.
 *
 * Aleph merges an aggregate from every message that ever targeted the key, so
 * a client that verifies signatures itself cannot use the merged view the API
 * serves: the merge is the node's work, not the publisher's. Instead, each
 * publish carries the complete manifest and the newest signed message wins. The
 * node can withhold an update but it cannot forge one, and a withheld update is
 * why a deployment is revoked by deleting the V-PROGRAM rather than by editing
 * this.
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
  for (const message of body.messages ?? []) {
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
