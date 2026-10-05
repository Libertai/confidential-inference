# Verifying a deployment

Two things have to hold, and neither implies the other:

1. **The peer is the enclave the deployment published.** AMD endorses its
   attestation report, the guest is not debuggable, the report commits to the
   TLS key being served, and the launch measurement is one the V-PROGRAM
   message published. The client libraries establish this on every connection.
2. **That deployment booted bytes you can read.** The images are rebuilt from
   this repository and checked against the dm-verity root hashes the deployment
   published. Done once per release, by anyone, offline.

(1) alone proves you are talking to *some* enclave whose operator published a
measurement. (2) is what makes that measurement mean something.

## 1. Verify the live endpoint

```python
from libertai_confidential import connect

tee = connect(item_hash="44a6d03ec5ab108a4aac13def0951714b209295d0acef1fcc2e979c4c1f2da39")
print(tee.base_url, tee.measurement)
```

```js
import { connect } from "@libertai/confidential-inference";
const tee = await connect({ itemHash: "44a6d03ec5ab108a4aac13def0951714b209295d0acef1fcc2e979c4c1f2da39" });
```

Either call throws unless every check passes. The V-PROGRAM message is
content-addressed and signed, so this trusts no Aleph node: see
[`README.md`](README.md).

A verified connection is not an authorised one. The enclave answers `401` until
LibertAI issues you an API key, which is checked by the gateway inside the
enclave rather than in front of it.

## 2. Check the images

Needs Linux on x86_64, [Nix](https://nixos.org/download/) with flakes,
`veritysetup`, and ~75 GB of free disk.

```bash
git clone https://github.com/Libertai/confidential-inference
cd confidential-inference
git checkout <source_commit from the manifest>

OUT=/var/tmp/cci ./deployment/build.sh          # ~55 GB of images
./deployment/verify-images.sh <item hash> /var/tmp/cci
```

`OUT` keeps the images out of the clone; it defaults to `./out`, which is
git-ignored.

`build.sh` prints the `libertai-models` revision it used. It defaults to the
commit in `deployment/flake.lock`, which is the one the published deployment
was built from; `--models-rev <sha|latest>` overrides it, and a different
revision produces different bytes.

`verify-images.sh` takes each root hash the deployment published and recomputes
it from the local file. All four matching means the workload and the volumes the
enclave booted are these exact bytes -- the model, the serving flags, the
gateway and the guest init. The firmware, kernel and initrd come from the Aleph
runtime bundle the message names; the measurement covers them, but nothing here
rebuilds them.

### Why the salt comes from the published hash tree

A dm-verity root hash is a hash of the image *and a salt*, and
`veritysetup format` picks a random salt unless told otherwise. The CLI that
publishes a V-PROGRAM does not tell it otherwise
([`aleph-cli/src/veritysetup.rs`](https://github.com/aleph-im/aleph-rs)), so
the root hash — and therefore the launch measurement — is different on every
publish of byte-identical images.

So a root hash cannot be recomputed from an image alone. It can be recomputed
from the image plus the salt the publisher used, and that salt is in the
superblock of the hash tree they published, which `verify-images.sh` downloads
and reads. The chain still closes:

```
rebuilt bytes --(published salt)--> published root hash
    --(in the kernel command line)--> published measurement
    --(SNP report)--> the enclave answering your request
```

What the random salt costs is not soundness but stability: identical images
publish under different measurements, so a measurement names one deployment
rather than a release, and it cannot be known before publishing. Passing a
fixed salt upstream would make it a function of the images alone.

## What is pinned, and why it has to be

The launch measurement covers the firmware, kernel, initrd, kernel command line
and the VMSA of every vCPU. The command line carries the dm-verity root hash of
the workload image and of each verified volume, so every byte below reaches the
digest.

| Input | Pinned in | Changing it changes |
| --- | --- | --- |
| vLLM runtime image digest | `build.sh` (`IMAGE`) | volume 0 |
| Model repository and revision | `build.sh` (`MODEL_REPO`, `MODEL_REV`) | volume 1 |
| `libertai-models` revision | `deployment/flake.lock` | volume 2 |
| nixpkgs revision | `deployment/flake.lock` | volume 2, via the Python closure |
| Gateway config (model id, upstream, backend URL, API public key) | `deployment/flake.nix` | volume 2 |
| vLLM serving flags | `deployment/model.conf` | the workload image |
| Guest init | `deployment/init.sh` | the workload image |
| vCPU count and memory | the publish command | the VMSA, so the digest directly |

The last row surprises people: asking for different memory or a different vCPU
count changes the measurement even though no file changed.

Images have to be byte-reproducible for any of this to work, which is why
`mkfs.ext4` gets a fixed UUID, a fixed non-zero hash seed, no journal and
non-lazy init, why trees are built under `fakeroot` so ownership does not depend
on who ran the build, and why `build.sh` pins its own `umask`: file modes land in
the image, and the umask decides them for anything the script creates.

## Current deployment

| | |
| --- | --- |
| Item hash | `44a6d03ec5ab108a4aac13def0951714b209295d0acef1fcc2e979c4c1f2da39` |
| Measurement (EPYC-Genoa) | `110c2983a25701d97e2364ab2ddaba1ba1a12cfb407c76a744791bf8f55ff0c72363226ae55a6f082028fc1604cea155` |
| Measurement (EPYC-v4) | `42945dab3d5940d6a58c16cfb30d8eeed688974418eff60bed7ac99e3a9cbfd2c41b520748d8eb8876575d790ffe904f` |
| `libertai-models` | `b403c1a5c873fcf7fa2170c2a6de825fdf59ed27` |
| nixpkgs | `3ed67ec0a4d3c7ab4ae1f04f8ee8df07bfa506a2` |
| vLLM image | `vllm/vllm-openai@sha256:5f5e535216848d0c52159c8c13a0af04be5f6fe1a84e79914300610796f76d40` |
| Model | `Qwen/Qwen3.8-27B-FP8` at `017b9c7af6b5689d5dd426a76e0bc077eb5ca20a` |
| Shape | 32 vCPU, 64 GiB, 1× H200 (`10de:233b`) in CC mode |
| Runtime bundle | `1a5ee478326730db94f8674d9756bbdcfbf52aa54953a081da42bcfe46308de1` |

## What this does not establish

- **That the model behaves.** The measurement pins which weights and which
  serving flags booted, not what the model says.
- **That the platform is patched.** A chip on vulnerable firmware still gets a
  valid VCEK. That is policy, so the clients take a `tcbFloor` from the caller
  instead of deciding it.
- **That the deployment still exists.** A deployment is revoked by deleting its
  V-PROGRAM, not by editing the manifest: a stale manifest can be served to a
  client, but a deleted enclave cannot answer it.
- **The runtime bundle.** Firmware, kernel and initrd come from the Aleph
  runtime named above, not from this repository, and reproducing those is a
  question for [aleph-vm](https://github.com/aleph-im/aleph-vm).
