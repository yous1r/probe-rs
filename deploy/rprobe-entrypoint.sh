#!/bin/sh
# Run as an entrypoint, never source this file. All agent work is done in a child.
# The foreground command is exec'd immediately and retains its arguments/signals/status.

rprobe_log() {
    printf '%s\n' "rprobe-bootstrap: $*" >&2
}

rprobe_verified() {
    [ -f "$rprobe_binary" ] && [ ! -L "$rprobe_binary" ] && [ -x "$rprobe_binary" ] || return 1
    rprobe_actual=$(sha256sum "$rprobe_binary" 2>/dev/null) || return 1
    [ "${rprobe_actual%% *}" = "$rprobe_sha256" ]
}

rprobe_install() (
    set -eu
    # Restrict download/extraction output without changing the application or agent limits.
    ulimit -f 32768 || exit 1
    command -v curl >/dev/null 2>&1 || { rprobe_log 'curl unavailable; cannot install agent'; exit 1; }
    case "$rprobe_format" in
        zip) command -v unzip >/dev/null 2>&1 && command -v tar >/dev/null 2>&1 || exit 1 ;;
        tar.gz) command -v tar >/dev/null 2>&1 || exit 1 ;;
        binary) ;;
        *) rprobe_log 'unsupported package format'; exit 1 ;;
    esac
    rprobe_stage=$(mktemp -d "$rprobe_dir/.install.XXXXXX") || exit 1
    trap 'rm -rf "$rprobe_stage"' 0
    trap 'exit 1' HUP INT TERM
    # -q ignores ~/.curlrc. Redirects can only stay on HTTPS. Never disable TLS validation.
    if ! curl -q --fail --silent --location --proto '=https' --proto-redir '=https' \
        --max-redirs 3 --connect-timeout 5 --max-time 30 --max-filesize 16777216 \
        --output "$rprobe_stage/download" "$rprobe_url"; then
        rprobe_log 'agent download failed; main application is unaffected'
        exit 1
    fi
    case "$rprobe_format" in
        zip)
            # Read only the expected member; never extract archive paths to the filesystem.
            unzip -p "$rprobe_stage/download" "rprobe-agent-$rprobe_target.tar.gz" > "$rprobe_stage/package.tar.gz" 2>/dev/null || exit 1
            tar -xzOf "$rprobe_stage/package.tar.gz" rprobe-agent > "$rprobe_stage/agent" 2>/dev/null || exit 1
            ;;
        tar.gz) tar -xzOf "$rprobe_stage/download" rprobe-agent > "$rprobe_stage/agent" 2>/dev/null || exit 1 ;;
        binary) mv "$rprobe_stage/download" "$rprobe_stage/agent" || exit 1 ;;
    esac
    rprobe_actual=$(sha256sum "$rprobe_stage/agent") || exit 1
    if [ "${rprobe_actual%% *}" != "$rprobe_sha256" ]; then
        rprobe_log 'agent SHA-256 mismatch; refusing to execute downloaded content'
        exit 1
    fi
    chmod 700 "$rprobe_stage/agent" || exit 1
    mv -fT "$rprobe_stage/agent" "$rprobe_binary" || exit 1
    rprobe_log 'verified agent installed'
)

rprobe_worker() (
    set -eu
    umask 077
    rprobe_owner=$1
    rprobe_child=
    rprobe_runtime=
    rprobe_cleanup() {
        trap - 0 HUP INT TERM
        if [ -n "$rprobe_child" ]; then
            kill "$rprobe_child" 2>/dev/null || :
            rprobe_ticks=0
            while kill -0 "$rprobe_child" 2>/dev/null && [ "$rprobe_ticks" -lt 3 ]; do
                sleep 1
                rprobe_ticks=$((rprobe_ticks + 1))
            done
            kill -KILL "$rprobe_child" 2>/dev/null || :
            wait "$rprobe_child" 2>/dev/null || :
        fi
        if [ -n "$rprobe_runtime" ]; then rm -rf "$rprobe_runtime"; fi
    }
    trap rprobe_cleanup 0
    trap 'exit 0' HUP INT TERM

    if [ -z "${RPROBE_SERVER:-}" ] || [ -z "${RPROBE_AGENT_ID:-}" ] || [ -z "${RPROBE_TOKEN_FILE:-}" ]; then
        rprobe_log 'agent disabled: set RPROBE_SERVER, RPROBE_AGENT_ID and RPROBE_TOKEN_FILE'
        exit 0
    fi
    for rprobe_tool in uname id stat sha256sum flock mkdir mktemp dd wc chmod mv rm sleep; do
        command -v "$rprobe_tool" >/dev/null 2>&1 || { rprobe_log "missing prerequisite: $rprobe_tool; agent skipped"; exit 0; }
    done
    [ "$(uname -s)" = Linux ] || { rprobe_log 'agent requires Linux'; exit 0; }
    case "$(uname -m)" in
        x86_64|amd64) rprobe_target=x86_64-unknown-linux-musl ;;
        aarch64|arm64) rprobe_target=aarch64-unknown-linux-musl ;;
        *) rprobe_log 'unsupported CPU architecture; agent skipped'; exit 0 ;;
    esac
    # Use an explicitly pinned binary hash; never download a checksum from the same untrusted URL.
    if [ -n "${RPROBE_AGENT_URL:-}" ] || [ -n "${RPROBE_AGENT_SHA256:-}" ]; then
        [ -n "${RPROBE_AGENT_URL:-}" ] && [ -n "${RPROBE_AGENT_SHA256:-}" ] || {
            rprobe_log 'custom downloads require both RPROBE_AGENT_URL and RPROBE_AGENT_SHA256'; exit 0;
        }
        rprobe_url=$RPROBE_AGENT_URL
        rprobe_sha256=$RPROBE_AGENT_SHA256
    elif [ "$rprobe_target" = x86_64-unknown-linux-musl ]; then
        # CI commit a38f4350c09706194271daf286cab2dfef1cf60f. Artifact retention is 14 days.
        rprobe_url=https://nightly.link/yous1r/probe-rs/actions/runs/45958389504/rprobe-agent-x86_64-unknown-linux-musl.zip
        rprobe_sha256=0f04bc74887ca4b7aae5b63d989b06466e15b1d1834604352561e0cf2dcd30cc
    else
        rprobe_log 'no bundled arm64 release; provide its HTTPS URL and binary SHA-256'; exit 0
    fi
    case "$rprobe_url" in https://*) ;; *) rprobe_log 'download URL must use HTTPS'; exit 0 ;; esac
    case "$rprobe_sha256" in *[!0-9a-f]*|'') rprobe_log 'binary SHA-256 must be lowercase hex'; exit 0 ;; esac
    [ "${#rprobe_sha256}" -eq 64 ] || { rprobe_log 'binary SHA-256 must have 64 characters'; exit 0; }
    rprobe_format=${RPROBE_AGENT_FORMAT:-zip}
    rprobe_dir=${RPROBE_AGENT_DIR:-/tmp/rprobe-agent-$(id -u)}
    case "$rprobe_dir" in /*) ;; *) rprobe_log 'RPROBE_AGENT_DIR must be an absolute path'; exit 0 ;; esac
    [ ! -L "$rprobe_dir" ] || { rprobe_log 'refusing symlink agent directory'; exit 0; }
    mkdir -p "$rprobe_dir" || { rprobe_log 'agent directory is not writable'; exit 0; }
    [ "$(stat -c '%u:%a' "$rprobe_dir")" = "$(id -u):700" ] || {
        rprobe_log 'agent directory must belong to this user and have mode 0700'; exit 0;
    }
    rprobe_dir=$(cd "$rprobe_dir" && pwd -P)
    rprobe_binary=$rprobe_dir/rprobe-agent
    if [ -L "$rprobe_binary" ] || { [ -e "$rprobe_binary" ] && [ ! -f "$rprobe_binary" ]; }; then
        rprobe_log 'agent install target must be a regular file'; exit 0
    fi
    [ ! -L "$rprobe_dir/agent.lock" ] || exit 0
    exec 9>"$rprobe_dir/agent.lock"
    flock -n 9 || exit 0 # Kernel-held lock, no stale PID file; shared by all starts in this directory.
    kill -0 "$rprobe_owner" 2>/dev/null || exit 0

    # Docker secrets are commonly mounted 0444. Copy, don't chmod the mounted source.
    [ -f "$RPROBE_TOKEN_FILE" ] && [ -r "$RPROBE_TOKEN_FILE" ] || {
        rprobe_log 'token file unavailable; agent skipped'; exit 0;
    }
    rprobe_runtime_base=${RPROBE_RUNTIME_DIR:-/dev/shm}
    case "$rprobe_runtime_base" in /*) ;; *) rprobe_log 'runtime directory must be absolute'; exit 0 ;; esac
    [ "$(stat -f -c '%T' "$rprobe_runtime_base")" = tmpfs ] || {
        rprobe_log 'private credential copy requires a writable container-private tmpfs'; exit 0;
    }
    rprobe_runtime=$(mktemp -d "$rprobe_runtime_base/rprobe-runtime.XXXXXX")
    dd if="$RPROBE_TOKEN_FILE" of="$rprobe_runtime/token" bs=1025 count=1 2>/dev/null || exit 0
    rprobe_token_bytes=$(wc -c < "$rprobe_runtime/token")
    [ "$rprobe_token_bytes" -ge 16 ] && [ "$rprobe_token_bytes" -le 1024 ] || {
        rprobe_log 'token file size is invalid'; exit 0;
    }
    chmod 600 "$rprobe_runtime/token"
    RPROBE_CGROUP_SCOPE=${RPROBE_CGROUP_SCOPE:-process}
    export RPROBE_CGROUP_SCOPE

    while kill -0 "$rprobe_owner" 2>/dev/null; do
        if rprobe_verified || rprobe_install; then
            kill -0 "$rprobe_owner" 2>/dev/null || exit 0
            set -- "$rprobe_binary" --server "$RPROBE_SERVER" --id "$RPROBE_AGENT_ID" \
                --token-file "$rprobe_runtime/token" --interval "${RPROBE_INTERVAL:-5}"
            if [ -n "${RPROBE_GROUP:-}" ]; then set -- "$@" --group "$RPROBE_GROUP"; fi
            "$@" </dev/null &
            rprobe_child=$!
            while kill -0 "$rprobe_owner" 2>/dev/null && kill -0 "$rprobe_child" 2>/dev/null; do sleep 2; done
            kill -0 "$rprobe_owner" 2>/dev/null || exit 0
            if wait "$rprobe_child"; then rprobe_status=0; else rprobe_status=$?; fi
            rprobe_child=
            rprobe_log "agent exited (status $rprobe_status); retrying in 60 seconds"
        else
            rprobe_log 'agent installation unavailable; retrying in 60 seconds'
        fi
        rprobe_ticks=0
        while [ "$rprobe_ticks" -lt 30 ] && kill -0 "$rprobe_owner" 2>/dev/null; do
            sleep 2
            rprobe_ticks=$((rprobe_ticks + 1))
        done
    done
)

rprobe_background() {
    (
        # Do not keep a command-substitution or pipeline open after --start-only returns.
        if [ -w /proc/1/fd/2 ]; then exec >/proc/1/fd/2 2>&1; else exec >/dev/null 2>&1; fi
        rprobe_worker "$1"
    ) </dev/null &
}

if [ "${1:-}" = '--start-only' ]; then
    # Container-only mode: a short-lived entrypoint helper must not own the agent lifetime.
    if [ "${RPROBE_ENABLED:-1}" != 0 ]; then rprobe_background 1; fi
    exit 0
fi
if [ "${1:-}" = '--' ]; then shift; fi
if [ "$#" -eq 0 ]; then
    printf '%s\n' 'Usage: rprobe-entrypoint.sh [--] command [args...] | --start-only' >&2
    exit 64
fi
if [ "${RPROBE_ENABLED:-1}" != 0 ]; then rprobe_background "$$"; fi
exec "$@"
