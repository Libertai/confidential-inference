#!/bin/busybox sh
# /sbin/init for the confidential-GPU vLLM V-PROGRAM workload (aleph.exec/1,
# gpu-1.0 runtime).
#
# /volumes/0: root filesystem of the vllm/vllm-openai CUDA image (read-only).
# /volumes/1: the HF checkpoint served.
# /volumes/2: the libertai-models gateway and its Python closure. /nix is a
#             symlink into it, because the interpreter's store paths are
#             absolute.
#
# The runtime's init loads the NVIDIA modules, verifies the card against
# NVIDIA's reference manifests and powers the VM off on any GPU error, then
# bind-mounts the driver userland into this image at /opt/nvidia/lib before
# chrooting here. vLLM runs chrooted one level further, into /volumes/0, so
# that mount has to be carried across.

export PATH=/bin

. /etc/libertai/model.conf

fatal() {
    echo "libertai-init: FATAL: $1"
    exit 1
}

R=/volumes/0
G=/volumes/2/opt/libertai-models
[ -x "$R/usr/local/bin/vllm" ] || [ -x "$R/usr/bin/vllm" ] || fatal "vLLM runtime volume missing at $R"
[ -f /volumes/1/config.json ] || fatal "model volume missing at /volumes/1"
[ -f "$G/src/server.py" ] || fatal "gateway volume missing at /volumes/2"
[ -x /volumes/2/bin/python ] || fatal "gateway interpreter missing at /volumes/2/bin/python"
# The driver libraries the runtime bound in; without them libcuda is absent and
# vLLM would fall back to a CPU-only torch and serve nothing on the GPU.
[ -d /opt/nvidia/lib ] || fatal "/opt/nvidia/lib not mounted: no GPU driver userland"
[ -e /dev/nvidia0 ] || fatal "/dev/nvidia0 missing: the GPU was not attached"

# Mountpoints must already exist in the read-only image: /proc /sys /dev /tmp
# /mnt, and /opt/nvidia/lib, which build.sh adds to it.
busybox mount -t proc proc "$R/proc" || fatal "mount proc failed"
busybox mount -o rbind /sys "$R/sys" || fatal "bind /sys failed"
busybox mount -o rbind /dev "$R/dev" || fatal "bind /dev failed"
busybox mkdir -p "$R/dev/shm"
busybox mount -t tmpfs -o mode=1777 tmpfs "$R/dev/shm" || fatal "mount /dev/shm failed"
busybox mount -t tmpfs -o mode=1777 tmpfs "$R/tmp" || fatal "mount /tmp failed"
busybox mount -o bind,ro /opt/nvidia/lib "$R/opt/nvidia/lib" || fatal "bind driver libs failed"
busybox mount -o bind,ro /volumes/1 "$R/mnt" || fatal "bind model failed"

# The gateway first: it is what the backend pushes API keys to, and the keys
# should be in place before the model finishes loading. Until a distribution
# arrives every key is unknown, so the instance answers 401 -- loading order
# cannot open a window where requests pass unchecked.
#
# 8080 is load-bearing: the guest firewall admits only tcp/8443 (the
# attest-agent), which proxies to that port. So the gateway is the only thing a
# client can reach, and every request is API-key checked before it reaches
# vLLM. PYTHONDONTWRITEBYTECODE because the volume is read-only under
# dm-verity; without it every import logs a warning.
# A subshell rather than `env`: this image ships busybox and nothing else, so
# every command outside the chroot is either a shell builtin, a busybox applet,
# or the interpreter on volume 2.
(
    cd "$G" || exit 1
    PATH=/volumes/2/bin:/bin
    HOME=/tmp
    PYTHONDONTWRITEBYTECODE=1
    PYTHONUNBUFFERED=1
    export PATH HOME PYTHONDONTWRITEBYTECODE PYTHONUNBUFFERED
    exec /volumes/2/bin/python -m uvicorn src.server:app --host 127.0.0.1 --port 8080
) &
gateway_pid=$!

echo "libertai-init: gateway=$gateway_pid, starting vLLM ($MODEL_ALIAS) on GPU"

# The image ENV is not applied outside a container runtime: reproduce the parts
# vLLM needs. The driver lives at /opt/nvidia/lib here, not the
# /usr/local/nvidia/lib64 the image's LD_LIBRARY_PATH expects, so libcuda is
# found through the former and the CUDA runtime through the latter.
#
# vLLM binds 8005, not 8080: the gateway owns the reachable port. Binding vLLM
# anywhere else would be unreachable, not more exposed -- but it would also be
# unmetered and unauthenticated.
busybox chroot "$R" /usr/bin/env -i \
    PATH=/usr/local/cuda/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/tmp/home \
    XDG_CACHE_HOME=/tmp/cache \
    CUDA_HOME=/usr/local/cuda \
    LD_LIBRARY_PATH=/opt/nvidia/lib:/usr/local/cuda/lib64 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    VLLM_NO_USAGE_STATS=1 \
    DO_NOT_TRACK=1 \
    $VLLM_ENV \
    vllm serve /mnt \
    --host 127.0.0.1 \
    --port 8005 \
    --served-model-name "$MODEL_ALIAS" \
    $VLLM_ARGS &
vllm_pid=$!

echo "libertai-init: vllm=$vllm_pid gateway=$gateway_pid"

# Fail closed, mirroring the platform init: if either process dies the VM must
# come down rather than leave an attested endpoint serving unmetered requests
# or proxying to nothing.
while kill -0 "$vllm_pid" 2>/dev/null && kill -0 "$gateway_pid" 2>/dev/null; do
    busybox sleep 5
done
fatal "a service exited (vllm or gateway); powering off"
