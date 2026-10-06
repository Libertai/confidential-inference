# Verifying a deployment

There are two separate checks, and you need both:

1. **The server you reach is the enclave the deployment published.** The client
   libraries do this on every connection.
2. **That deployment booted images you can rebuild from this repository.** Done
   once per release, offline, by anyone.

The first identifies the enclave. The second tells you what is inside it.

## 1. Check the live endpoint

```python
from libertai_confidential import connect

tee = connect(item_hash="66871efa64d1f42ffd43c88670f6930397d5992bdb78910dc4ff708f45b5c7bb")
print(tee.base_url, tee.measurement)
```

```js
import { connect } from "@libertai/confidential-inference";
const tee = await connect({ itemHash: "66871efa64d1f42ffd43c88670f6930397d5992bdb78910dc4ff708f45b5c7bb" });
```

Either call fails unless every check passes. The deployment message is
content-addressed and signed, so this trusts no Aleph node; the checks
themselves are listed in [`README.md`](README.md).

## 2. Rebuild the images

Needs Linux on x86_64, [Nix](https://nixos.org/download/) with flakes,
`veritysetup`, and about 75 GB of free disk.

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
commit in `deployment/flake.lock`, which is the one the published deployment was
built from. `--models-rev <sha|latest>` overrides it, and a different revision
produces different bytes.

`verify-images.sh` takes each dm-verity root hash the deployment published and
recomputes it from the local file. Four matches mean the workload and volumes
the enclave booted are these exact bytes: the model, the serving flags, the
gateway and the guest init. Firmware, kernel and initrd come from the Aleph
runtime bundle the message names; the measurement covers them, but nothing here
rebuilds them.

### Where the salt comes from

A dm-verity root hash covers the image and a salt, and `veritysetup format`
picks a random salt unless told otherwise. The CLI that publishes a V-PROGRAM
does not tell it otherwise
([`aleph-rs`](https://github.com/aleph-im/aleph-rs)), so byte-identical images
publish under a different root hash, and therefore a different measurement,
every time.

A root hash is therefore not recomputable from an image alone, but it is from
the image plus the salt the publisher used. That salt sits in the superblock of
the hash tree they published, which `verify-images.sh` downloads and reads. The
chain still closes:

```
rebuilt bytes --(published salt)--> published root hash
    --(in the kernel command line)--> published measurement
    --(SNP report)--> the enclave answering your request
```

The random salt costs stability rather than soundness: a measurement names one
deployment rather than a release, and cannot be known before publishing. Passing
a fixed salt upstream would make it a function of the images alone.

## What goes into the measurement

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

The last row catches people out: asking for different memory or a different vCPU
count changes the measurement even though no file changed.

The images have to be byte-reproducible for any of this to work. That is why
`mkfs.ext4` gets a fixed UUID, a fixed non-zero hash seed, no journal and
non-lazy init; why trees are built under `fakeroot`, so ownership does not depend
on who ran the build; and why `build.sh` pins its own `umask`, since file modes
land in the image.

## Current deployment

| | |
| --- | --- |
| Item hash | `66871efa64d1f42ffd43c88670f6930397d5992bdb78910dc4ff708f45b5c7bb` |
| Measurement (EPYC-Genoa) | `925def0a98b84cdf5bce410d06f62f8b94b2a5591238ed014c6f944293c3b4e14fc6d79daa9bd3d49975c4a9fa4e90f0` |
| Measurement (EPYC-v4) | `52097f20d264d9765c39f382d885d701a1b8a93e3ddcbc583983e3d777dca38e965a331156c5351ade5c06c0bf4c329e` |
| `libertai-models` | `b403c1a5c873fcf7fa2170c2a6de825fdf59ed27` |
| nixpkgs | `3ed67ec0a4d3c7ab4ae1f04f8ee8df07bfa506a2` |
| vLLM image | `vllm/vllm-openai@sha256:5f5e535216848d0c52159c8c13a0af04be5f6fe1a84e79914300610796f76d40` |
| Model | `Qwen/Qwen3.8-27B-FP8` at `017b9c7af6b5689d5dd426a76e0bc077eb5ca20a` |
| Shape | 16 vCPU, 32 GiB, 1× H200 (`10de:233b`) in CC mode |
| Runtime bundle | `1a5ee478326730db94f8674d9756bbdcfbf52aa54953a081da42bcfe46308de1` |

## Limits

- The measurement pins which weights and which serving flags booted, not what
  the model says.
- A chip running vulnerable firmware still gets a valid VCEK, so firmware
  currency is a policy decision the clients take from the caller as `tcbFloor`.
- A deployment is revoked by deleting it, not by editing the manifest: a stale
  manifest can be served to a client, but a deleted enclave cannot answer it.
- Firmware, kernel and initrd come from the Aleph runtime bundle named above
  rather than from this repository. Reproducing those is a question for
  [aleph-vm](https://github.com/aleph-im/aleph-vm).
