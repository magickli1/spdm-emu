#!/bin/sh
# Shared helpers for .github/workflows/build_CI_TPM.yml emu steps.
# Source from CI: . ../../script/ci_tpm_emu_helpers.sh

# Kill a background responder PID if still running.
ci_tpm_cleanup_responder() {
    if [ -n "${RESPONDER_PID:-}" ] && kill -0 "${RESPONDER_PID}" 2>/dev/null; then
        kill "${RESPONDER_PID}" 2>/dev/null || true
        wait "${RESPONDER_PID}" 2>/dev/null || true
    fi
    RESPONDER_PID=""
}

# Wait until TCP connect to host:port succeeds (platform listen ready).
# Usage: ci_tpm_wait_tcp_ready [host] [port] [timeout_sec]
ci_tpm_wait_tcp_ready() {
    _host="${1:-127.0.0.1}"
    _port="${2:-2323}"
    _timeout_sec="${3:-30}"
    _i=0
    while [ "${_i}" -lt "${_timeout_sec}" ]; do
        if nc -z "${_host}" "${_port}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        _i=$((_i + 1))
    done
    echo "Timed out waiting for ${_host}:${_port}" >&2
    return 1
}

# Start responder in background, wait until listen port is ready.
# Args are passed to ./spdm_responder_emu.
# Env: RESPONDER_LOG (default responder.log), SPDM_EMU_PORT (default 2323)
ci_tpm_start_responder() {
    RESPONDER_LOG="${RESPONDER_LOG:-responder.log}"
    SPDM_EMU_PORT="${SPDM_EMU_PORT:-2323}"
    ./spdm_responder_emu "$@" >"${RESPONDER_LOG}" 2>&1 &
    RESPONDER_PID=$!
    if ! ci_tpm_wait_tcp_ready 127.0.0.1 "${SPDM_EMU_PORT}" 30; then
        echo "Responder failed to become ready; log:" >&2
        cat "${RESPONDER_LOG}" >&2 || true
        ci_tpm_cleanup_responder
        return 1
    fi
    return 0
}
