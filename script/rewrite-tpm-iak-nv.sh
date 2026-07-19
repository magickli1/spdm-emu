#!/bin/sh -eu
#
# Rewrite the IAK certificate NV index from a DER blob.
# Intended for CI: sample setup remains leaf-only; this helper can load
# intermediate||leaf (iak_nv_chain.der) or restore iak_cert.der.
#

IAK_CERT=0x01C90100

if [ $# -ne 1 ]; then
    echo "Usage: $0 <iak-nv.der>" >&2
    exit 1
fi

nv_blob="$1"
if [ ! -f "${nv_blob}" ]; then
    echo "Missing IAK NV blob: ${nv_blob}" >&2
    exit 1
fi

nv_size="$(stat -c %s "${nv_blob}")"
if [ "${nv_size}" -eq 0 ]; then
    echo "IAK NV blob is empty: ${nv_blob}" >&2
    exit 1
fi

tpm2_nvundefine -C o "${IAK_CERT}" 2>/dev/null || true
tpm2_nvdefine "${IAK_CERT}" -C o -s "${nv_size}" \
    -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite "${IAK_CERT}" -C o -i "${nv_blob}"

tmp_dir="$(mktemp -d /tmp/spdm-tpm-iak-nv.XXXXXXXXXX)"
trap 'rm -rf "${tmp_dir}"' EXIT INT TERM
tpm2_nvread "${IAK_CERT}" -C o -o "${tmp_dir}/iak-cert-nv.der"
cmp "${tmp_dir}/iak-cert-nv.der" "${nv_blob}"

echo "IAK NV rewritten from ${nv_blob} (${nv_size} bytes)"
