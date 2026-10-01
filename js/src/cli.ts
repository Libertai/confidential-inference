/**
 * Audit a deployment from a terminal:
 *
 *   npx @libertai/confidential-inference <item-hash|model>
 *
 * Prints what the peer proved, so a deployment can be checked without writing
 * a program. It says nothing about what the workload does with a prompt --
 * that is what `source_commit` and a rebuild are for.
 */
import { connect } from "./index.js";
import { fetchManifest } from "./manifest.js";

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    const manifest = await fetchManifest();
    console.log(`source: ${manifest.source_repo}`);
    for (const [model, { deployments }] of Object.entries(manifest.models ?? {})) {
      const active = deployments.filter((d) => d.status === "active").length;
      console.log(`  ${model}  ${active} active`);
    }
    console.log("\npass a model or an item hash to verify one");
    return;
  }

  const isHash = /^[0-9a-f]{64}$/.test(target);
  const tee = await connect(isHash ? { itemHash: target } : { model: target });
  console.log(`verified     ${tee.baseURL}`);
  console.log(`item hash    ${tee.itemHash}`);
  console.log(`measurement  ${tee.measurement}`);
  if (tee.sourceCommit) console.log(`built from   ${tee.sourceCommit}`);

  const res = await tee.fetch(`${tee.baseURL}/models`);
  const models = ((await res.json()) as any).data.map((m: any) => m.id);
  console.log(`serving      ${models.join(", ")}`);
}

main().catch((e) => {
  console.error(String(e?.message ?? e));
  process.exit(1);
});
