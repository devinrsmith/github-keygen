# Run COMMAND confined by Landlock (landrun) inside a bubblewrap namespace.
#
# The Nix expression prepends these definitions to this file:
#   CLOSURE       closureInfo of everything the sandbox may execute
#   TOOLS_PATH    PATH entries put first inside the sandbox (curl)
#   FALLBACK_PATH PATH entries put last (bundled openssh, gzip, grep)
#   CACERT        CA bundle used by curl inside the sandbox
#   SH_BIN        shell mounted at /bin/sh (perl runs "ssh -Q ..." through it)
#   PERL, BWRAP, LANDRUN
#   COMMAND       array: the command to confine
#   OFFLINE_ARGS  array: arguments prepended to "$@" in offline mode
#
# Usage: <wrapper> [--online] [arguments for COMMAND...]
#
# Offline (default): no network at all (empty network namespace).
# --online: outbound TCP to port 443 only, plus what DNS resolution needs.
#
# In both modes the only writable path is ~/.ssh. Readable/executable: the
# Nix store closure of the bundled tools, plus the host's system directories
# when the host's ssh is used (see below).

prog=${0##*/}

die() {
    printf '%s: %s\n' "$prog" "$*" >&2
    exit 1
}

online=0
if [[ ${1:-} == --online ]]; then
    online=1
    shift
fi

[[ ${HOME:-} == /* ]] || die "HOME must be set to an absolute path"
ssh_dir=$HOME/.ssh

# landrun --best-effort silently runs *unconfined* on a kernel without
# Landlock, so check the ABI ourselves and fail closed.
# 444 is landlock_create_ruleset on every architecture; flag 1
# (LANDLOCK_CREATE_RULESET_VERSION) makes it return the ABI version.
#   ABI 3: truncate(2) is restricted (needed to protect files outside ~/.ssh)
#   ABI 4: TCP connect is restricted (needed for --online)
abi=$("$PERL" -e 'print syscall(444, 0, 0, 1)')
min_abi=3
((online)) && min_abi=4
((abi >= min_abi)) ||
    die "kernel Landlock ABI is $abi, at least $min_abi is required; refusing to run unconfined"

# github-keygen deletes or overwrites a ~/.ssh/config it cannot read
# (see AUDIT.md, F1)
if [[ -e $ssh_dir/config && ! -r $ssh_dir/config ]]; then
    die "$ssh_dir/config exists but is not readable; refusing to run (github-keygen would overwrite or delete it)"
fi

# landrun needs the directory to exist to grant access to it
if [[ ! -d $ssh_dir ]]; then
    mkdir -m 700 -- "$ssh_dir"
fi

landrun_args=(--best-effort)

# grant MODE PATH: grant access to the resolved PATH, if it exists.
# Landlock checks the resolved path, so a symlink (like a systemd-resolved
# /etc/resolv.conf) needs its target granted.
grant() {
    local real
    real=$(readlink -f -- "$2") || return 0
    [[ -e $real ]] || return 0
    # landrun splits its arguments on commas
    [[ $real != *,* ]] || die "unsupported path (contains a comma): $real"
    landrun_args+=("$1" "$real")
}

while IFS= read -r p; do
    landrun_args+=(--rox "$p")
done <"$CLOSURE/store-paths"

# The generated config is read by the host's ssh, so github-keygen must check
# the version, algorithms and man page of *that* ssh: use the host's ssh,
# ssh-keygen, man and zgrep, found through the host's PATH. The bundled
# tools are only a fallback, at the end of PATH.
host_path=
for tool in ssh ssh-keygen; do
    p=$(command -v "$tool") || continue
    [[ $p == /* ]] || continue
    dir=$(dirname -- "$p")
    [[ :$host_path: == *:"$dir":* ]] || host_path+=${host_path:+:}$dir
    grant --rox "$dir"
    if [[ $(readlink -f -- "$p") == /nix/store/* ]]; then
        # The store is world-readable: no secrets there
        grant --rox /nix/store
    fi
done
if [[ -n $host_path ]]; then
    # System programs and libraries, and the man pages
    for d in /usr /bin /sbin /lib /lib32 /lib64 /libx32; do
        grant --rox "$d"
    done
    grant --ro /etc/ld.so.cache
    grant --ro /etc/manpath.config
    grant --ro /etc/man_db.conf
else
    echo "$prog: no ssh found in PATH; the configuration is generated for the bundled OpenSSH" >&2
fi

grant --rw "$ssh_dir"
grant --rw /dev/null
grant --ro /dev/urandom
# Lets ssh-keygen prompt for the passphrase (prefer this over -p, which
# exposes the passphrase in the process list)
if { : </dev/tty; } 2>/dev/null; then
    grant --rw /dev/tty
fi
# User database lookups (ssh-keygen needs getpwuid to succeed)
grant --ro /etc/passwd
grant --ro /etc/group
grant --ro /etc/nsswitch.conf
if [[ -S /var/run/nscd/socket ]]; then
    landrun_args+=(--unix "$(readlink -f /var/run/nscd/socket)")
fi

if ((online)); then
    landrun_args+=(--connect-tcp 443)
    grant --ro /etc/resolv.conf
    grant --ro /etc/hosts
    grant --ro /etc/host.conf
fi

# Only these variables reach the confined process
[[ $HOME != *,* ]] || die "unsupported HOME (contains a comma): $HOME"
[[ $host_path != *,* ]] || die "unsupported PATH entry (contains a comma): $host_path"
landrun_args+=(
    --env "HOME=$HOME"
    --env "PATH=$TOOLS_PATH${host_path:+:$host_path}:$FALLBACK_PATH"
    --env "SSL_CERT_FILE=$CACERT"
)
if [[ -n ${XDG_RUNTIME_DIR:-} && $XDG_RUNTIME_DIR != *,* ]]; then
    # Only used as text for ControlPath in the generated config
    landrun_args+=(--env "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR")
fi

# perl runs commands through /bin/sh: replace it by our shell. bwrap cannot
# mount over a symlink (/bin/sh is one on NixOS), so mount over its target.
host_sh=$(readlink -f /bin/sh) || die "/bin/sh not found"
# Landlock checks the mount point's path, not the source's
landrun_args+=(--rox "$host_sh")

bwrap_args=(
    --dev-bind / /
    --ro-bind "$SH_BIN" "$host_sh"
    # A fresh /proc to match the new pid namespace (landrun reads
    # /proc/self/task)
    --unshare-pid
    --proc /proc
    --unshare-ipc
    --die-with-parent
)
args=("$@")
if ((!online)); then
    bwrap_args+=(--unshare-net)
    args=("${OFFLINE_ARGS[@]}" "$@")
fi

exec "$BWRAP" "${bwrap_args[@]}" -- \
    "$LANDRUN" "${landrun_args[@]}" -- \
    "${COMMAND[@]}" "${args[@]}"
