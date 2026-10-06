#!/usr/bin/env bash
# Builds the four images of a confidential-GPU vLLM V-PROGRAM into $OUT
# (default ./out/<model>):
#
#   workload.ext4   busybox + init.sh + model.conf
#   vllm-runtime.ext4   root filesystem of the pinned vllm-openai image
#   model-*.ext4        the HF checkpoint, at the pinned revision
#   gateway.ext4        the libertai-models gateway and its Python closure
#
# Every input that ends up inside the launch measurement is pinned here or in
# flake.lock, so the same commit of this repository rebuilds the same images.
# See ../VERIFYING.md for how to check that against a published deployment.
#
# Usage: build.sh [--model <alias>] [--models-rev <sha|latest>]
#
#   --model       Which directory under models/ to build. Optional while there
#                 is only one.
#   --models-rev  The gateway's source revision. Defaults to the commit in
#                 flake.lock, which is what lets a rebuild reproduce a published
#                 measurement; `latest` takes the newest commit on the default
#                 branch instead, for cutting a new one.
#
# Needs ~75 GB free. The checkpoint tree and the rootfs tarball are each
# removed as soon as their image exists; the four images then take ~55 GB.
set -euo pipefail

# Image bytes depend on file modes, modes depend on the umask, and the verity
# root hashes -- so the launch measurement -- depend on the bytes. mkfs.ext4 -d
# copies whatever modes the tree has, and `mkdir`/`curl -o` take theirs from the
# umask, so an independent rebuild under a different umask produces a different
# measurement. 0002 is the value the published images were built with: the
# directories in them are 775 and the fetched model files 664. Group-writability
# is immaterial in an image mounted read-only under dm-verity; reproducibility
# is not.
umask 0002

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

ALIAS=
MODELS_REV=
while [ $# -gt 0 ]; do
    case $1 in
        --model)
            ALIAS=$2
            shift 2
            ;;
        --models-rev)
            MODELS_REV=$2
            shift 2
            ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$ALIAS" ]; then
    for d in "$here"/models/*/; do
        [ -f "$d/model.json" ] || continue
        [ -z "$ALIAS" ] || { echo "several models: pass --model <alias>" >&2; ls "$here/models" >&2; exit 2; }
        ALIAS=$(basename "$d")
    done
fi
model_dir=$here/models/$ALIAS
[ -f "$model_dir/model.json" ] || { echo "no models/$ALIAS/model.json" >&2; exit 2; }

field() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$model_dir/model.json" "$1"; }
# Pinned by digest and revision: both are inside the launch measurement, so a
# floating tag would silently change what a client is asked to trust.
IMAGE=$(field image)
MODEL_REPO=$(field modelRepo)
MODEL_REV=$(field modelRev)
MODEL_NAME=$(field modelName)

# The gateway reads the alias from model.json and vLLM from model.conf. They
# have to be the same string or the gateway proxies to a model vLLM does not
# serve, which only shows up as a 404 at request time.
conf_alias=$(. "$model_dir/model.conf" >/dev/null 2>&1; echo "$MODEL_ALIAS")
[ "$conf_alias" = "$(field alias)" ] ||
    { echo "models/$ALIAS: model.conf says $conf_alias, model.json says $(field alias)" >&2; exit 2; }

OUT=${OUT:-$PWD/out/$ALIAS}
mkdir -p "$OUT"

LOCKED_REV=$(python3 -c '
import json, sys
lock = json.load(open(sys.argv[1]))
print(lock["nodes"]["libertai-models"]["locked"]["rev"])
' "$here/flake.lock")
MODELS_REV=${MODELS_REV:-$LOCKED_REV}
if [ "$MODELS_REV" = latest ]; then
    MODELS_REV=$(curl -fsSL https://api.github.com/repos/Libertai/libertai-models/commits/main |
        python3 -c 'import json,sys;print(json.load(sys.stdin)["sha"])')
fi
# Printed because a deployment is only reproducible if this is recorded with it.
echo "==> model $ALIAS"
echo "==> libertai-models $MODELS_REV"

export SOURCE_DATE_EPOCH=0
MKFS_FLAGS=(-b 4096 -U 00000000-0000-0000-0000-000000000000
  -E hash_seed=a1e5c0de-1111-2222-3333-444455556666,lazy_itable_init=0,lazy_journal_init=0
  -O ^has_journal)

nixsh() { nix shell nixpkgs#e2fsprogs nixpkgs#fakeroot nixpkgs#bash nixpkgs#coreutils nixpkgs#gnutar -c "$@"; }

mkfs_from_dir() {
    local src=$1 img=$2 mib
    mib=$(( $(du -sm "$src" | cut -f1) * 103 / 100 + 16 ))
    rm -f "$img"
    nixsh sh -c "fakeroot \$(command -v bash) -c \"\$(command -v chown) -R 0:0 '$src' && \
        \$(command -v mkfs.ext4) -q ${MKFS_FLAGS[*]} -N 256 -d '$src' '$img' ${mib}M\""
}

echo "==> workload"
wl=$(mktemp -d)
trap 'rm -rf "$wl"' EXIT
mkdir -p "$wl"/{bin,sbin,etc/libertai,volumes,proc,sys,dev,run,mnt,tmp/secrets,opt/nvidia/lib}
# The gateway's interpreter refers to /nix/store by absolute path, and it lives
# on volume 2. A symlink costs nothing in a read-only image and saves a mount.
ln -s /volumes/2/nix "$wl/nix"
cp "$(nix build --no-link --print-out-paths nixpkgs#pkgsStatic.busybox)/bin/busybox" "$wl/bin/busybox"
cp "$here/init.sh" "$wl/sbin/init"
cp "$model_dir/model.conf" "$wl/etc/libertai/model.conf"
touch "$wl/etc/resolv.conf"
chmod 0755 "$wl/bin/busybox" "$wl/sbin/init"
mkfs_from_dir "$wl" "$OUT/workload.ext4"

echo "==> model volume ($MODEL_REPO@${MODEL_REV:0:8})"
# Guarded as a whole: the checkpoint tree is deleted once its image exists, so
# checking for the tree instead of the image would re-download 30 GB on every
# later run.
if [ ! -f "$OUT/model-$MODEL_NAME.ext4" ]; then
    md=$OUT/model-$MODEL_NAME
    mkdir -p "$md"
    curl -fsSL "https://huggingface.co/api/models/$MODEL_REPO/revision/$MODEL_REV" |
        python3 -c 'import json,sys;[print(s["rfilename"]) for s in json.load(sys.stdin)["siblings"]]' |
        while read -r f; do
            [ -s "$md/$f" ] && continue
            mkdir -p "$md/$(dirname "$f")"
            curl -fsSL -o "$md/$f" "https://huggingface.co/$MODEL_REPO/resolve/$MODEL_REV/$f"
        done
    mkfs_from_dir "$md" "$OUT/model-$MODEL_NAME.ext4"
    # Peak disk is the binding constraint (~75 GB): the checkpoint tree is only
    # needed until its image exists, and re-downloading it is cheaper than a disk.
    [ -n "${KEEP_MODEL_SRC:-}" ] || rm -rf "$md"
fi

echo "==> runtime volume ($IMAGE)"
rt=$OUT/vllm-runtime.ext4
if [ ! -f "$rt" ]; then
    tar=$OUT/vllm-rootfs.tar
    [ -f "$tar" ] || nix shell nixpkgs#crane -c crane export --platform linux/amd64 "$IMAGE" "$tar"
    # The image has no /opt/nvidia: append the mount point the second chroot
    # needs, root-owned, before the tarball becomes a read-only filesystem.
    stage=$(mktemp -d)
    mkdir -p "$stage/opt/nvidia/lib"
    nixsh sh -c "fakeroot \$(command -v bash) -c \"\$(command -v chown) -R 0:0 '$stage' && \
        \$(command -v tar) --append --file '$tar' --directory '$stage' opt\""
    rm -rf "$stage"
    # mkfs.ext4 -d reads a tarball directly (e2fsprogs >= 1.47.1), keeping the
    # image's ownership and modes without unpacking as root.
    nixsh mkfs.ext4 -q "${MKFS_FLAGS[@]}" -d "$tar" "$rt" \
        "$(( $(du -sm "$tar" | cut -f1) * 104 / 100 + 256 ))M"
    rm -f "$tar"
fi

echo "==> gateway volume (libertai-models $MODELS_REV)"
gw=$OUT/gateway.ext4
if [ ! -f "$gw" ]; then
    # --override-input rather than editing flake.lock: the lock stays the
    # record of what the published deployment was built from.
    override=()
    [ "$MODELS_REV" = "$LOCKED_REV" ] ||
        override=(--override-input libertai-models "github:Libertai/libertai-models/$MODELS_REV")
    # The attribute name is quoted because an alias contains dots, and nix
    # splits an unquoted attribute path on them.
    cp "$(nix build --no-link --print-out-paths "${override[@]}" "$here#\"gateway-$ALIAS\"")" "$gw"
    chmod 644 "$gw"
fi

echo "==> done"
ls -la "$OUT"/*.ext4
