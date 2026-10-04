#!/usr/bin/env bash
# Checks that locally built images are the ones a published V-PROGRAM booted.
#
#   ./verify-images.sh <item-hash> [out-dir]
#
# For each image it takes the dm-verity root hash the deployment published, and
# recomputes it from the local file. Matching root hashes mean the workload and
# volumes the deployment booted are these exact bytes. The firmware, kernel and
# initrd come from the runtime bundle the message names, which this does not
# rebuild.
#
# The salt comes from the published hash tree rather than from here, because
# `veritysetup format` picks a random one unless told otherwise and the CLI that
# published this did not tell it otherwise. So the root hash cannot be
# recomputed from the image alone -- but it can be recomputed from the image
# plus the salt the publisher used, which is in the superblock of the hash tree
# they published. See ../VERIFYING.md.
#
# Needs: veritysetup, curl, python3. No root.
set -euo pipefail

hash=${1:?usage: verify-images.sh <item-hash> [out-dir]}
out=${2:-$PWD/out}
api=${ALEPH_API:-https://api.aleph.im}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsSL "$api/api/v0/messages.json?hashes=$hash" -o "$work/message.json"

# Image order is fixed by the message: the workload, then the volumes as they
# mount at /volumes/0../volumes/N-1.
python3 - "$work/message.json" > "$work/images" <<'PY'
import json, sys

message = json.load(open(sys.argv[1]))["messages"][0]
content = json.loads(message["item_content"])
print("workload", content["workload"]["roothash"], content["workload"]["hash_tree"])
for i, volume in enumerate(content["volumes"]):
    print(f"volume{i}", volume["roothash"], volume["hash_tree"])
PY

# Same order as the message; a deployment that adds a volume adds a line here.
names=(workload.ext4 vllm-runtime.ext4 "" gateway.ext4)
model=$(ls "$out"/model-*.ext4 2>/dev/null | head -1 || true)
names[2]=${model##*/}

failed=0
i=0
while read -r label roothash tree_message; do
    file=$out/${names[$i]}
    i=$((i + 1))
    if [ ! -f "$file" ]; then
        echo "MISSING  $label: $file"
        failed=1
        continue
    fi

    # The hash tree is itself a STORE message, so its content has to be looked
    # up before it can be fetched.
    content_hash=$(curl -fsSL "$api/api/v0/messages.json?hashes=$tree_message" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["messages"][0]["content"]["item_hash"])')
    curl -fsSL "$api/api/v0/storage/raw/$content_hash" -o "$work/tree"
    salt=$(veritysetup dump "$work/tree" | awk '/^Salt:/ {print $2}')

    got=$(veritysetup format --salt="$salt" "$file" "$work/recomputed" |
        awk '/^Root hash:/ {print $3}')
    rm -f "$work/recomputed"

    if [ "$got" = "$roothash" ]; then
        echo "OK       $label  ${names[$((i - 1))]}  $roothash"
    else
        echo "MISMATCH $label  ${names[$((i - 1))]}"
        echo "         published $roothash"
        echo "         rebuilt   $got"
        failed=1
    fi
done < "$work/images"

if [ "$failed" -eq 0 ]; then
    echo
    echo "every image matches what $hash published"
else
    echo
    echo "at least one image is not what $hash published"
fi
exit "$failed"
