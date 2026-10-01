/**
 * Turning a published deployment into something a client can connect to.
 *
 * Only the measurements matter for trust, and they come from a message whose
 * hash the client recomputes. Everything else here -- which node runs it, which
 * address and port answer -- is a hint from an untrusted source: point the
 * client at the wrong machine and attestation fails, so a lie costs the liar a
 * failed connection, not a leaked prompt.
 */
import { fetchMessage, AlephError } from "./aleph.js";

/** Port the attest-agent listens on inside the guest; the only one open. */
const GUEST_PORT = 8443;

export const DEFAULT_SCHEDULER = "https://scheduler.api.aleph.cloud";

export interface Deployment {
  itemHash: string;
  /** Launch digests the deployment published, one per vCPU type. */
  measurements: string[];
  /** Publisher of the V-PROGRAM message. */
  sender: string;
  /** Origins to try, most widely reachable first. */
  candidates: string[];
}

interface Endpoint {
  host: string;
  port: number;
}

export async function resolveDeployment(
  itemHash: string,
  opts: { api?: string; scheduler?: string; sender?: string; signal?: AbortSignal } = {},
): Promise<Deployment> {
  const message = (await fetchMessage(itemHash, opts)) as any;
  const measurements: string[] = (message?.verification?.measurements ?? [])
    .map((m: any) => m?.registers?.launch)
    .filter((m: unknown): m is string => typeof m === "string");
  if (measurements.length === 0) {
    throw new AlephError(`${itemHash} publishes no launch measurement: not a confidential VM`);
  }

  const endpoints = await locate(itemHash, opts);
  return {
    itemHash,
    measurements,
    sender: message.address,
    candidates: endpoints.map((e) => `https://${format(e.host)}:${e.port}`),
  };
}

/** Ask the scheduler which node runs this, then that node how to reach it. */
async function locate(
  itemHash: string,
  opts: { scheduler?: string; signal?: AbortSignal },
): Promise<Endpoint[]> {
  const scheduler = opts.scheduler ?? DEFAULT_SCHEDULER;
  const res = await fetch(`${scheduler}/api/v0/allocation/${itemHash}`, { signal: opts.signal });
  if (!res.ok) throw new AlephError(`${itemHash} is not allocated to any node (${res.status})`);
  const allocation: any = await res.json();

  const endpoints: Endpoint[] = [];
  // The node forwards a host port to the guest's 8443. A client behind IPv4
  // only has no other way in, so this is tried first.
  const nodeUrl: string | undefined = allocation?.node?.url;
  if (nodeUrl) {
    try {
      const list = await fetch(new URL("/v2/about/executions/list", nodeUrl), {
        signal: opts.signal,
      });
      const net = (await list.json())?.[itemHash]?.networking;
      const mapped = net?.mapped_ports?.[String(GUEST_PORT)];
      if (net?.host_ipv4 && mapped?.host) {
        endpoints.push({ host: net.host_ipv4, port: mapped.host });
      }
    } catch {
      // The node being unreachable or terse is not fatal: IPv6 may still work.
    }
  }
  if (allocation?.vm_ipv6) endpoints.push({ host: allocation.vm_ipv6, port: GUEST_PORT });
  if (endpoints.length === 0) throw new AlephError(`no reachable address for ${itemHash}`);
  return endpoints;
}

function format(host: string): string {
  return host.includes(":") ? `[${host}]` : host;
}
