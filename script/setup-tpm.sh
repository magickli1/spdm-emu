#!/bin/sh -e

SWTPM_STATE_DIR=""
KEY_ALGORITHM=ecc
HASH_ALGORITHM=256

ROOT_CTX=0x81000000
ROOT_KEY=0x81000001
REQU_CTX=0x81000010
REQU_KEY=0x81000011
RESP_CTX=0x81000020
RESP_KEY=0x81000021
IAK_KEY=0x81020001
LEGACY_IAK_KEY=0x81010100

ROOT_CERT=0x1500000
REQU_CERT=0x1500010
RESP_CERT=0x1500020

REQU_CERT_CHAIN=0x1500011
RESP_CERT_CHAIN=0x1500021
IAK_CERT=0x01C90100

while [ $# -gt 0 ] ; do
    case "$1" in
        --start-swtpm)
            START_SWTPM=1
            ;;
        --key-algorithm=*)
            KEY_ALGORITHM=${1#*=}
            ;;
        --hash-algorithm=*)
            HASH_ALGORITHM=${1#*=}
            ;;
        --wait-swtpm)
            WAIT_SWTPM=1
            ;;
        --cleanup)
            CLEANUP=1
            ;;
    esac
    shift
done

cat > openssl.cnf << EOF
[v3_ca]
basicConstraints = critical,CA:true

[ v3_req ]
basicConstraints = critical,CA:false
EOF

if [ -n "$START_SWTPM" ] ; then
    SWTPM_STATE_DIR="$(mktemp -d /tmp/swtpm-state.XXXXXXXXXX)"
    mkdir -p "${SWTPM_STATE_DIR}"

    echo "Starting SWTPM"
    swtpm socket \
        --tpm2 \
        --flags not-need-init,startup-clear \
        --tpmstate dir="${SWTPM_STATE_DIR}" \
        --server type=tcp,port=2321 \
        --ctrl type=tcp,port=2322  &
    SWTPM_PID="$!"
    sleep 1

    # INT/TERM only: CI relies on swtpm surviving after a successful Setup exit.
    cleanup() {
        if [ -n "${CLEANUP_DONE:-}" ]; then
            return 0
        fi
        CLEANUP_DONE=1
        echo "Killing swtpm ${SWTPM_PID}..."
        kill -9 "${SWTPM_PID}" 2>/dev/null || true
        echo "Cleaning up cache"
        rm -rf "${SWTPM_STATE_DIR}"
    }
    trap cleanup INT TERM

    sleep 1
fi

echo "Checking tpm availability...."
tpm2_getcap properties-fixed || {
    echo "tpm2_getcap failed"
    exit 1
}

if [ -n "$CLEANUP" ] ; then
    echo "Cleaning up persistent handles"
    for i in $ROOT_CTX $ROOT_KEY $REQU_CTX $REQU_KEY $RESP_CTX $RESP_KEY \
        $IAK_KEY $LEGACY_IAK_KEY ; do
        tpm2_evictcontrol -C o -c "$i" || true
    done
    for i in $ROOT_CERT $REQU_CERT $RESP_CERT $REQU_CERT_CHAIN \
        $RESP_CERT_CHAIN $IAK_CERT ; do
        tpm2_nvundefine -C o "$i" || true
    done
    tpm2_flushcontext --transient-object
fi

echo "Flushing any pre-existing transient/session handles..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

#
# Root CA
#

echo "Creating root ca context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} -c root_ca.ctx

echo "Creating root keys..."
tpm2_create -C root_ca.ctx -G ${KEY_ALGORITHM} -u root_ca.pub \
    -r root_ca.priv -c root_ca_key.ctx

echo "Persisting root ca at 0x81000001..."
tpm2_evictcontrol -C o -c root_ca_key.ctx ${ROOT_KEY}
tpm2_flushcontext --transient-object

echo "Generating root ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Root CA" \
    -key "handle:${ROOT_KEY}" \
    -config openssl.cnf \
    -extensions v3_ca \
    -out root_ca_cert.csr

echo "Generating root ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in root_ca_cert.csr \
    -signkey "handle:${ROOT_KEY}" \
    -extfile openssl.cnf \
    -extensions v3_ca \
    -days 365 \
    -out root_ca_cert.pem

echo "Converting pem certificate to der..."
openssl x509 \
    -outform DER \
    -in root_ca_cert.pem \
    -out root_ca_cert.der

echo "Storing root ca into TPM NVram"
tpm2_nvdefine ${ROOT_CERT} -C o -s "$(stat -c %s root_ca_cert.der)" -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${ROOT_CERT} -C o -i root_ca_cert.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

#
# Requester
#

echo "Creating requester ca context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} -c requester.ctx

echo "Creating requester keys..."
tpm2_create -C requester.ctx -G ${KEY_ALGORITHM} -u requester.pub \
    -r requester.priv -c requester_key.ctx

echo "Persisting requester ca at 0x81000011..."
tpm2_evictcontrol -C o -c requester_key.ctx ${REQU_KEY}
tpm2_flushcontext --transient-object

echo "Generating requester ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Requester Certificates" \
    -config openssl.cnf \
    -extensions v3_req \
    -key "handle:${REQU_KEY}" \
    -out requester_cert.csr

echo "Generating requester ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in requester_cert.csr \
    -CA root_ca_cert.pem \
    -CAkey "handle:${ROOT_KEY}" \
    -days 365 \
    -extfile openssl.cnf \
    -extensions v3_req \
    -out requester_cert.pem

echo "Converting pem certificate to der..."
openssl x509 \
    -outform DER \
    -in requester_cert.pem \
    -out requester_cert.der

echo "Creating certificate chain..."
cat root_ca_cert.der requester_cert.der > requester_certchain.der

# echo "Converting pem certchain to der..."
# openssl x509 \
#    -outform DER \
#    -in requester_certchain.pem \
#    -out requester_certchain.der

echo "Storing requester ca into TPM NVram"
tpm2_nvdefine ${REQU_CERT} -C o -s "$(stat -c %s requester_cert.der)" -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${REQU_CERT} -C o -i requester_cert.der

echo "Storing requester ca chain into TPM NVram"
tpm2_nvdefine ${REQU_CERT_CHAIN} -C o -s "$(stat -c %s requester_certchain.der)" -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${REQU_CERT_CHAIN} -C o -i requester_certchain.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

#
# Responder
#

echo "Creating responder ca context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} -c responder.ctx

echo "Creating responder keys..."
tpm2_create -C responder.ctx -G ${KEY_ALGORITHM} -u responder.pub \
    -r responder.priv -c responder_key.ctx

echo "Persisting responder ca at 0x81000021..."
tpm2_evictcontrol -C o -c responder_key.ctx ${RESP_KEY}
tpm2_flushcontext --transient-object

echo "Generating responder ca certificate request..."
openssl req \
    -provider tpm2 \
    -provider default \
    -new \
    -subj "/CN=Responder Certificates" \
    -config openssl.cnf \
    -extensions v3_req \
    -key "handle:${RESP_KEY}" \
    -out responder_cert.csr

echo "Generating responder ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in responder_cert.csr \
    -CA root_ca_cert.pem \
    -CAkey "handle:${ROOT_KEY}" \
    -extfile openssl.cnf \
    -extensions v3_req \
    -days 365 \
    -out responder_cert.pem

echo "Converting pem certificate to der..."
openssl x509 \
    -outform DER \
    -in responder_cert.pem \
    -out responder_cert.der

echo "Creating certificate chain..."
cat root_ca_cert.der responder_cert.der > responder_certchain.der

# echo "Converting pem certchain to der..."
# openssl x509 \
#     -outform DER \
#     -in responder_certchain.pem \
#     -out responder_certchain.der

echo "Storing responder ca into TPM NVram"
tpm2_nvdefine ${RESP_CERT} -C o -s "$(stat -c %s responder_cert.der)" -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${RESP_CERT} -C o -i responder_cert.der

echo "Storing responder ca chain into TPM NVram"
tpm2_nvdefine ${RESP_CERT_CHAIN} -C o -s "$(stat -c %s responder_certchain.der)" -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${RESP_CERT_CHAIN} -C o -i responder_certchain.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object || true

#
# Initial Attestation Key (IAK)
#

echo "Creating restricted TPM attestation key..."
tpm2_createek \
    -G ecc \
    -c iak_ek.ctx \
    -u iak_ek.pub
tpm2_createak \
    -C iak_ek.ctx \
    -G ecc \
    -g sha256 \
    -s ecdsa \
    -u iak.pub \
    -r iak.priv \
    -c iak.ctx \
    -n iak.name
echo "Creating IAK certificate from its TPM public key..."
tpm2_readpublic -c iak.ctx -f pem -o iak_public.pem
openssl x509 \
    -provider tpm2 \
    -provider default \
    -new \
    -force_pubkey iak_public.pem \
    -subj "/CN=Responder Initial Attestation Key" \
    -CA root_ca_cert.pem \
    -CAkey "handle:${ROOT_KEY}" \
    -extfile openssl.cnf \
    -extensions v3_req \
    -days 365 \
    -out iak_cert.pem

# Persist IAK before optional CI artifacts so TPM CA signing has free slots.
echo "Persisting runtime IAK at ${IAK_KEY}..."
tpm2_evictcontrol -C o -c iak.ctx ${IAK_KEY}
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

# Optional multi-cert IAK NV artifact (intermediate || leaf). Sample default NV
# remains leaf-only; CI/scripts may rewrite IAK NV from iak_nv_chain.der.
echo "Creating optional IAK intermediate||leaf NV chain artifact..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out iak_intermediate.key
openssl req -new -key iak_intermediate.key \
    -subj "/CN=IAK Intermediate CA" \
    -out iak_intermediate.csr
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in iak_intermediate.csr \
    -CA root_ca_cert.pem \
    -CAkey "handle:${ROOT_KEY}" \
    -extfile openssl.cnf \
    -extensions v3_ca \
    -days 365 \
    -out iak_intermediate.pem
# Intermediate-signed leaf uses software CA key (no TPM context pressure).
openssl x509 \
    -new \
    -force_pubkey iak_public.pem \
    -subj "/CN=Responder Initial Attestation Key" \
    -CA iak_intermediate.pem \
    -CAkey iak_intermediate.key \
    -extfile openssl.cnf \
    -extensions v3_req \
    -days 365 \
    -out iak_cert_via_intermediate.pem
openssl x509 -outform DER -in iak_intermediate.pem -out iak_intermediate.der
openssl x509 -outform DER -in iak_cert_via_intermediate.pem \
    -out iak_cert_via_intermediate.der
cat iak_intermediate.der iak_cert_via_intermediate.der > iak_nv_chain.der

# OOB chain for CI: root || intermediate || intermediate-signed leaf.
# Used when NV holds only the intermediate-signed leaf.
cat root_ca_cert.der iak_intermediate.der iak_cert_via_intermediate.der \
    > iak_oob_via_intermediate.der

# Wrong-leaf OOB chain for CI leaf-mismatch: verifies to root, leaf != IAK.
# Sign with the software intermediate CA to avoid further TPM context load.
echo "Creating CI wrong-leaf OOB chain artifact..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out iak_wrong_leaf.key
openssl req -new -key iak_wrong_leaf.key \
    -subj "/CN=IAK CI Wrong Leaf" \
    -out iak_wrong_leaf.csr
openssl x509 \
    -req \
    -in iak_wrong_leaf.csr \
    -CA iak_intermediate.pem \
    -CAkey iak_intermediate.key \
    -extfile openssl.cnf \
    -extensions v3_req \
    -days 365 \
    -out iak_wrong_leaf.pem
openssl x509 -outform DER -in iak_wrong_leaf.pem -out iak_wrong_leaf.der
# OOB file still starts with the configured root so chain verify + leaf
# mismatch hit the intended Quote branch (not RootHash / untrusted).
cat root_ca_cert.der iak_intermediate.der iak_wrong_leaf.der \
    > iak_wrong_leaf_chain.der

echo "Removing provisioning CA key (IAK already persisted)..."
tpm2_evictcontrol -C o -c ${ROOT_KEY}
tpm2_flushcontext --transient-object

openssl x509 -outform DER -in iak_cert.pem -out iak_cert.der
# Optional requester convenience file (root || leaf). Sample TPM IAK NV stores
# leaf only; the responder also accepts a TCG-style chain-except-root
# (intermediates || leaf). LIBSPDM_TPM_IAK_CERT_CHAIN_FILE remains optional
# when the served chain verifies to the configured root.
cat root_ca_cert.der iak_cert.der > iak_certchain.der

echo "Storing IAK leaf certificate in TPM NVram (sample: leaf-only; chain-except-root also supported)..."
tpm2_nvdefine ${IAK_CERT} -C o -s "$(stat -c %s iak_cert.der)" \
    -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${IAK_CERT} -C o -i iak_cert.der
tpm2_flushcontext --transient-object 2>/dev/null || true

if [ -n "$START_SWTPM" ] ; then
    echo "Export both TCTI variables before using swtpm:"
    echo "  export TPM2TOOLS_TCTI=swtpm:port=2321"
    echo "  export TPM2OPENSSL_TCTI=swtpm:port=2321"

    if [ -n "$WAIT_SWTPM" ] ; then
        echo "Press CTRL+C to stop swtpm"
        wait $SWTPM_PID
    fi
else
    echo "Export both TCTI variables for your TPM before running the emulators:"
    echo "  export TPM2TOOLS_TCTI=<your-tcti>"
    echo "  export TPM2OPENSSL_TCTI=<your-tcti>"
fi

echo "Done"
