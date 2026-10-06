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

tee = connect(item_hash="99e3274fdc1c9c9aa23f94633113dc96840e28735cb3e7ccd7cfc54d517af8a5")
print(tee.base_url, tee.measurement)
```

```js
import { connect } from "@libertai/confidential-inference";
const tee = await connect({ itemHash: "99e3274fdc1c9c9aa23f94633113dc96840e28735cb3e7ccd7cfc54d517af8a5" });
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

OUT=/var/tmp/cci ./deployment/build.sh --model qwen3.8-27b-tee   # ~55 GB
./deployment/verify-images.sh <item hash> /var/tmp/cci
```

`--model` names a directory under `deployment/models/`, and can be left out
while there is only one. `OUT` keeps the images out of the clone; it defaults to
`./out/<model>`, which is git-ignored.

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

A root hash covers the image and a salt, and the salt is random per publish, so
`verify-images.sh` reads it from the published hash tree rather than recomputing
it. That costs nothing: a salt is a parameter, not a secret, and finding a
different image that hashes to the published root under it is the preimage
problem.

## What goes into the measurement

The launch measurement covers the firmware, kernel, initrd, kernel command line
and the VMSA of every vCPU. The command line carries the dm-verity root hash of
the workload image and of each verified volume, so every byte below reaches the
digest.

| Input | Pinned in | Changing it changes |
| --- | --- | --- |
| vLLM runtime image digest | `models/<model>/model.json` | volume 0 |
| Model repository and revision | `models/<model>/model.json` | volume 1 |
| `libertai-models` revision | `deployment/flake.lock` | volume 2 |
| nixpkgs revision | `deployment/flake.lock` | volume 2, via the Python closure |
| Gateway config (model id, upstream, backend URL, API public key) | `deployment/flake.nix` | volume 2 |
| vLLM serving flags | `models/<model>/model.conf` | the workload image |
| Guest init | `deployment/init.sh` | the workload image |
| Gateway alias | `models/<model>/model.json` and `model.conf` | volume 2 and the workload image |
| vCPU count and memory | the publish command | the VMSA, so the digest directly |

The last row catches people out: asking for different memory or a different vCPU
count changes the measurement even though no file changed.

The images have to be byte-reproducible for any of this to work. That is why
`mkfs.ext4` gets a fixed UUID, a fixed non-zero hash seed, no journal and
non-lazy init; why trees are built under `fakeroot`, so ownership does not depend
on who ran the build; and why `build.sh` pins its own `umask`, since file modes
land in the image.

## Deployments

`manifest.json` is the list, and it is what `connect(model=...)` reads. A model
can have several deployments at once; a client tries each active one until it
reaches one it can verify.

| Model | Item hash | Source commit | Shape |
| --- | --- | --- | --- |
| `qwen3.8-27b-tee` | `99e3274fdc1c9c9aa23f94633113dc96840e28735cb3e7ccd7cfc54d517af8a5` | `904b51d` | 16 vCPU, 32 GiB, 1× H200 (`10de:233b`) in CC mode |

Each deployment publishes its own launch measurements, since the verity salt is
random per publish; they are in the V-PROGRAM message, which is what the clients
and `verify-images.sh` read.

Everything a deployment was built from is in this repository at its
`source_commit`, so checking that commit out is how you see it:

| What | Where, at that commit |
| --- | --- |
| vLLM image digest, checkpoint repository and revision | `deployment/models/<model>/model.json` |
| vLLM serving flags and the alias | `deployment/models/<model>/model.conf` |
| `libertai-models` and nixpkgs revisions | `deployment/flake.lock` |

`build.sh` prints the `libertai-models` revision it builds with, so you can see
it matches without reading the lock file.

Runtime bundle for all of them:
`1a5ee478326730db94f8674d9756bbdcfbf52aa54953a081da42bcfe46308de1`.

## Limits

- A chip running vulnerable firmware still gets a valid VCEK, so firmware
  currency is a policy decision the clients take from the caller as `tcbFloor`.
- A deployment is revoked by deleting it, not by editing the manifest: a stale
  manifest can be served to a client, but a deleted enclave cannot answer it.
- Firmware, kernel and initrd come from the Aleph runtime bundle named above
  rather than from this repository. Reproducing those is a question for
  [aleph-vm](https://github.com/aleph-im/aleph-vm).
