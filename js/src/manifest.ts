/**
 * Which deployments a publisher currently stands behind.
 *
 * The manifest holds item hashes, not measurements: a measurement is already
 * inside the V-PROGRAM message the hash names, and a hash is content-addressed,
 * so repeating the digest here would only create something to disagree with.
 * It holds no endpoints either -- those move -- and no versions: clients take
 * what is active.
 */
import { fetchAggregate } from "./aleph.js";

/** Address whose signature makes a manifest LibertAI's. */
export const DEFAULT_PUBLISHER = "0x238224C744F4b90b4494516e074D2676ECfC6803";
export const AGGREGATE_KEY = "confidential-inference";

export interface DeploymentEntry {
  /** Aleph V-PROGRAM message hash: names the image, the model and the flags. */
  item_hash: string;
  /** Commit of `source_repo` the images were built from, so anyone can rebuild
   *  them and check the measurement themselves. */
  source_commit: string;
  status: "active" | "deprecated";
}

export interface Manifest {
  source_repo: string;
  models: Record<string, { deployments: DeploymentEntry[] }>;
}

export async function fetchManifest(
  opts: { publisher?: string; api?: string; signal?: AbortSignal } = {},
): Promise<Manifest> {
  const publisher = opts.publisher ?? DEFAULT_PUBLISHER;
  return (await fetchAggregate(publisher, AGGREGATE_KEY, opts)) as Manifest;
}

export function activeDeployments(manifest: Manifest, model: string): DeploymentEntry[] {
  const entry = manifest.models?.[model];
  if (!entry) {
    const known = Object.keys(manifest.models ?? {}).join(", ") || "none";
    throw new Error(`no model "${model}" in the manifest (published: ${known})`);
  }
  const active = entry.deployments.filter((d) => d.status === "active");
  if (active.length === 0) throw new Error(`every deployment of "${model}" is deprecated`);
  return active;
}
