/**
 * A transport that attests before it speaks.
 *
 * The guest serves a self-signed certificate, so the usual PKI check is
 * meaningless here and is switched off. What replaces it is stronger: the
 * certificate carries an AMD-signed report that commits to the key being
 * served and to the image that booted. The socket is handed to the HTTP client
 * only once that check has passed, so a failed attestation means no request
 * bytes were ever written -- not a prompt sent and then regretted.
 */
import net from "node:net";
import tls from "node:tls";
import { Agent, fetch as undiciFetch } from "undici";

import { AttestationError, verifyCertificate, type VerifyOptions } from "./verify.js";

export interface TransportOptions extends VerifyOptions {
  /** Called with the launch measurement each new connection proved. */
  onVerified?: (measurement: string, host: string) => void;
  /**
   * How long one address may take to answer before the next is tried.
   *
   * A deployment publishes an IPv4 port mapping and an IPv6 address, and an
   * address that cannot be reached from here does not fail -- it goes quiet.
   * Left to the operating system that costs over a minute per address, so
   * candidates are given a deadline instead.
   */
  connectTimeoutMs?: number;
}

const DEFAULT_CONNECT_TIMEOUT_MS = 8000;

export function confidentialAgent(opts: TransportOptions): Agent {
  return new Agent({
    connect(options: any, callback: any) {
      let settled = false;
      const done = (err: Error | null, socket: tls.TLSSocket | null) => {
        if (settled) return;
        settled = true;
        callback(err, socket);
      };

      const host = options.hostname ?? options.host;
      const socket = tls.connect({
        host,
        port: Number(options.port),
        // An IP literal is not a valid SNI name, and the guest serves one
        // certificate regardless.
        servername: net.isIP(host) ? undefined : host,
        // Deliberate: attestation replaces hostname and CA checks. See above.
        rejectUnauthorized: false,
        ALPNProtocols: ["http/1.1"],
      });
      opts.signal?.addEventListener("abort", () => socket.destroy(), { once: true });

      socket.setTimeout(opts.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS, () => {
        socket.destroy();
        done(new Error(`${host} did not answer in time`), null);
      });
      // Past the handshake the deadline belongs to the request, not the socket:
      // a long completion is not an unreachable peer.
      socket.once("secureConnect", () => socket.setTimeout(0));

      socket.once("secureConnect", () => {
        const der = socket.getPeerCertificate()?.raw;
        if (!der?.length) {
          socket.destroy();
          return done(new AttestationError(`${host} presented no certificate`), null);
        }
        verifyCertificate(new Uint8Array(der), opts).then(
          (measurement) => {
            opts.onVerified?.(measurement, host);
            done(null, socket);
          },
          (err) => {
            socket.destroy();
            done(err, null);
          },
        );
      });
      socket.once("error", (err) => {
        socket.destroy();
        done(err, null);
      });
    },
  });
}

/** A `fetch` that only ever reaches an attested peer. */
export function confidentialFetch(opts: TransportOptions): typeof globalThis.fetch {
  const dispatcher = confidentialAgent(opts);
  return (async (input: any, init: any = {}) => {
    try {
      return await undiciFetch(input, { ...init, dispatcher });
    } catch (e) {
      throw attestationCause(e) ?? e;
    }
  }) as unknown as typeof globalThis.fetch;
}

/**
 * fetch reports anything that went wrong below it as "fetch failed", which
 * would leave a refused enclave indistinguishable from a flat tyre. The real
 * reason is somewhere down the cause chain.
 */
function attestationCause(error: unknown): AttestationError | undefined {
  for (let e = error; e instanceof Error; e = (e as Error).cause) {
    if (e instanceof AttestationError) return e;
  }
  return undefined;
}
