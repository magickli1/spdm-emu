#!/bin/sh -e

# Enrollment credentials and TPM context files are local to the provisioning user.
umask 077

SWTPM_STATE_DIR="$(mktemp -d /tmp/swtpm-state.XXXXXXXXXX)"
KEY_ALGORITHM=ecc
HASH_ALGORITHM=256
# Device serial number: X520SerialNumber in the IDevID/IAK certificate Subject
# (TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.10, sec. 8).
DEVICE_SERIAL="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"

ROOT_CTX=0x81000000
ROOT_KEY=0x81000001
REQU_CTX=0x81000010
REQU_KEY=0x81000011
RESP_CTX=0x81000020
RESP_KEY=0x81000021

# The existing responder child key signs SPDM transcripts (slots 0/1/4).
# The separate restricted IAK signs TPM2_Quote evidence (slot 5).
IAK_KEY=0x81020001

ROOT_CERT=0x1500000
REQU_CERT=0x1500010
REQU_CERT_CHAIN=0x1500011
RESP_CERT=0x1500020
RESP_CERT_CHAIN=0x1500021

# TCG DevID certificate chains (sec. 7.3.2 Table 4): DER, leaf at index 0,
# without the Root CA certificate.
IAK_CERT_CHAIN=0x01C90100

# Obsolete provisioning layouts, removed by --cleanup.
OLD_HANDLES="0x81020000 0x81000031"
OLD_NV="0x01C90200 0x1500030 0x1500031"

DEVID_TOOL="$(dirname "$0")/tpm-devid.sh"

mkdir -p "${SWTPM_STATE_DIR}"

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
        --device-serial=*)
            DEVICE_SERIAL=${1#*=}
            ;;
    esac
    shift
done

# DevID signing algorithms: ECC NIST P256 / P384 or
# RSA 2048 (H-1). ECC: TPM_ALG_ECDSA for IDevID and IAK (the hash of the
# scheme follows nameAlg). RSA: IDevID scheme NULL, IAK RSAPSS-SHA256.
case "${KEY_ALGORITHM}" in
    rsa*)
        IDEVID_ALG="rsa2048:null:null"
        IAK_ALG="rsa2048:rsapss-sha256:null"
        UNIQUE_ALG=rsa
        CERTIFY_SCHEME=rsapss
        ;;
    *)
        IDEVID_ALG="ecc${HASH_ALGORITHM}:ecdsa-sha${HASH_ALGORITHM}:null"
        IAK_ALG="ecc${HASH_ALGORITHM}:ecdsa-sha${HASH_ALGORITHM}:null"
        UNIQUE_ALG=ecc
        CERTIFY_SCHEME=ecdsa
        ;;
esac
# Template H-0 objectAttributes (noDA = 0, restricted only for the IAK)
DEVID_ATTRS="fixedtpm|fixedparent|sensitivedataorigin|userwithauth|adminwithpolicy|sign"

cat > openssl.cnf << EOF
[v3_ca]
basicConstraints = critical,CA:true

[ v3_req ]
basicConstraints = critical,CA:false
EOF

if [ -n "$START_SWTPM" ] ; then
    
    echo "Starting SWTPM"
    swtpm socket \
        --tpm2 \
        --flags not-need-init,startup-clear \
        --tpmstate dir="${SWTPM_STATE_DIR}" \
        --server type=tcp,port=2321 \
        --ctrl type=tcp,port=2322  &
    SWTPM_PID="$!"
    sleep 1

    cleanup() {
        setup_status=$?
        trap - EXIT INT TERM
        # A successful setup leaves this swtpm available to the emulators.
        if [ "$setup_status" -ne 0 ]; then
            if kill -0 "$SWTPM_PID" 2>/dev/null; then
                kill "$SWTPM_PID" 2>/dev/null || true
                wait "$SWTPM_PID" 2>/dev/null || true
            fi
            rm -rf -- "$SWTPM_STATE_DIR"
        fi
        exit "$setup_status"
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    # Never provision another TPM when our simulator failed to bind its ports.
    kill -0 "$SWTPM_PID"

fi

echo "Checking tpm availability...."
tpm2_getcap properties-fixed || {
    echo "tpm2_getcap failed"
    exit 1
}

if [ -n "$CLEANUP" ] ; then
    echo "Cleaning up pesistent handles"
    # free object slots left by an interrupted run before EvictControl needs one
    tpm2_flushcontext --transient-object || true
    for i in $ROOT_CTX $ROOT_KEY $REQU_CTX $REQU_KEY $RESP_CTX $RESP_KEY $IAK_KEY $OLD_HANDLES ; do
        tpm2_evictcontrol -C o -c "$i" || true
    done
    for i in $ROOT_CERT $REQU_CERT $REQU_CERT_CHAIN $RESP_CERT $RESP_CERT_CHAIN $IAK_CERT_CHAIN $OLD_NV ; do
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
tpm2_evictcontrol -C o -c root_ca.ctx ${ROOT_CTX}

tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

echo "Creating root keys..."
tpm2_create -C ${ROOT_CTX} -G ${KEY_ALGORITHM} -u root_ca.pub -r root_ca.priv

echo "Loading root key..."
tpm2_load -C ${ROOT_CTX} -u root_ca.pub -r root_ca.priv -c root_ca_key.ctx

echo "Persisting root ca at 0x8010001..."
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

echo "Generatng root ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in root_ca_cert.csr \
    -signkey "handle:${ROOT_KEY}" \
    -extfile openssl.cnf \
    -extensions v3_ca \
    -days 356 \
    -out root_ca_cert.pem

echo "Converting pem certificate to der..."
openssl x509 \
    -outform DER \
    -in root_ca_cert.pem \
    -out root_ca_cert.der

echo "Storing root ca into TPM NVram"
tpm2_nvdefine ${ROOT_CERT} -C o -s $(stat -c %s root_ca_cert.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${ROOT_CERT} -C o -i root_ca_cert.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

#
# Requester
#

echo "Creating requester ca context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} -c requester.ctx
tpm2_evictcontrol -C o -c requester.ctx ${REQU_CTX}

tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

echo "Creating requester keys..."
tpm2_create -C ${REQU_CTX} -G ${KEY_ALGORITHM} -u requester.pub -r requester.priv

echo "Loading requester key..."
tpm2_load -C ${REQU_CTX} -u requester.pub -r requester.priv -c requester_key.ctx

echo "Persisting requester ca at 0x8010001..."
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

echo "Generatng requester ca certificate..."
openssl x509 \
    -provider tpm2 \
    -provider default \
    -req \
    -in requester_cert.csr \
    -CA root_ca_cert.pem \
    -CAkey "handle:${ROOT_KEY}" \
    -days 356 \
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
tpm2_nvdefine ${REQU_CERT} -C o -s $(stat -c %s requester_cert.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${REQU_CERT} -C o -i requester_cert.der

echo "Storing requester ca chain into TPM NVram"
tpm2_nvdefine ${REQU_CERT_CHAIN} -C o -s $(stat -c %s requester_certchain.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${REQU_CERT_CHAIN} -C o -i requester_certchain.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object 2>/dev/null || true
tpm2_flushcontext --loaded-session 2>/dev/null || true

#
# Keep the existing responder parent/child key layout. The child identity key
# uses the DevID signing attributes and policy needed for CA enrollment checks.
# The restricted IAK is created separately as an Endorsement Primary key and
# stored at 0x81020001, with its certificate chain in NV 0x01C90100.
# Only the responder identity key signs SPDM transcripts; the IAK signs Quotes.
#

echo "Computing DevID key policies (PolicyIDevIDKey)..."
bash "${DEVID_TOOL}" policy --role idevid --hash sha${HASH_ALGORITHM} --out-dir .
bash "${DEVID_TOOL}" policy --role iak --hash sha${HASH_ALGORITHM} --out-dir .
bash "${DEVID_TOOL}" unique --role iak --alg ${UNIQUE_ALG} --out iak_unique.bin

echo "Creating EK (hwSerialNum source)..."
tpm2_createek -c ek.ctx -G ${KEY_ALGORITHM} -u ek.pub
tpm2_readpublic -c ek.ctx -f der -o ek_pub.der
tpm2_flushcontext --transient-object

echo "Creating responder parent context..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${KEY_ALGORITHM} -c responder.ctx
tpm2_evictcontrol -C o -c responder.ctx ${RESP_CTX}
tpm2_flushcontext --transient-object

echo "Creating responder identity key (${IDEVID_ALG})..."
tpm2_create -C ${RESP_CTX} -g sha${HASH_ALGORITHM} -G ${IDEVID_ALG} \
    -a "${DEVID_ATTRS}" -L idevid_policy_key.bin -u responder.pub -r responder.priv
tpm2_load -C ${RESP_CTX} -u responder.pub -r responder.priv -c responder_key.ctx
tpm2_evictcontrol -C o -c responder_key.ctx ${RESP_KEY}
tpm2_flushcontext --transient-object

echo "Creating IAK primary key (${IAK_ALG}) in the Endorsement Hierarchy..."
tpm2_createprimary -C e -g sha${HASH_ALGORITHM} -G ${IAK_ALG} \
    -a "${DEVID_ATTRS}|restricted" -L iak_policy_key.bin -u iak_unique.bin \
    -c iak.ctx
tpm2_evictcontrol -C o -c iak.ctx ${IAK_KEY}
tpm2_flushcontext --transient-object

echo "Exporting IDevID and IAK public areas..."
tpm2_readpublic -c ${RESP_KEY} -f pem -o idevid_pub.pem
tpm2_readpublic -c ${RESP_KEY} -f tss -o idevid_public.tpm2b
tpm2_readpublic -c ${IAK_KEY} -f pem -o iak_pub.pem
tpm2_readpublic -c ${IAK_KEY} -f tss -o iak_public.tpm2b -n iak.name

#
# CA checks before issuing the certificates (the TCG-CSR-IDEVID protocol is not
# emulated). adminWithPolicy = 1, so the ADMIN role of the DevID keys
# (TPM2_Certify object, TPM2_ActivateCredential key) needs the matching
# PolicyIDevIDKey branch: PolicySecret(EH) + PolicyCommandCode + PolicyOR.
#
echo "CA check 1/2: EK credential activation for the IAK..."
# the EK is a Primary key derived from the EH seed: re-creating it gives the same key
tpm2_createek -c ek.ctx -G ${KEY_ALGORITHM} -u ek.pub
head -c 16 /dev/urandom > ca_secret.bin
tpm2_makecredential -T none -e ek.pub -s ca_secret.bin \
    -n "$(xxd -p -c 256 iak.name)" -o ca_credential.bin
tpm2_startauthsession --policy-session -S iak_admin.ctx -g sha${HASH_ALGORITHM}
tpm2_policysecret -S iak_admin.ctx -c e
tpm2_policycommandcode -S iak_admin.ctx TPM2_CC_ActivateCredential
tpm2_policyor -S iak_admin.ctx -l sha${HASH_ALGORITHM}:iak_policy_user.bin,iak_policy_certify.bin,iak_policy_activate.bin,iak_policy_delegation.bin
tpm2_startauthsession --policy-session -S ek_session.ctx
tpm2_policysecret -S ek_session.ctx -c e
tpm2_activatecredential -c ${IAK_KEY} -C ek.ctx -i ca_credential.bin \
    -o ca_secret_recovered.bin -p "session:iak_admin.ctx" -P "session:ek_session.ctx" > /dev/null
# policy sessions are closed by the TPM after use (continueSession clear)
tpm2_flushcontext --transient-object
cmp -s ca_secret.bin ca_secret_recovered.bin || {
    echo "CA enrollment check FAILED: EK credential activation for the IAK"
    exit 1
}

# tpm2-tools 5.x tpm2_certify takes no qualifyingData; freshness comes from the
# fresh EK credential secret above.
echo "CA check 2/2: TPM2_Certify of the IDevID by the IAK..."
tpm2_startauthsession --policy-session -S idevid_admin.ctx -g sha${HASH_ALGORITHM}
tpm2_policysecret -S idevid_admin.ctx -c e
tpm2_policycommandcode -S idevid_admin.ctx TPM2_CC_Certify
tpm2_policyor -S idevid_admin.ctx -l sha${HASH_ALGORITHM}:idevid_policy_user.bin,idevid_policy_certify.bin,idevid_policy_activate.bin,idevid_policy_delegation.bin
tpm2_certify -c ${RESP_KEY} -C ${IAK_KEY} -P "session:idevid_admin.ctx" \
    --scheme ${CERTIFY_SCHEME} -g sha${HASH_ALGORITHM} -o idevid_certify.attest -s idevid_certify.sig -f plain
bash "${DEVID_TOOL}" enroll-check \
    --iak-public iak_public.tpm2b --iak-pem iak_pub.pem \
    --idevid-public idevid_public.tpm2b \
    --attest idevid_certify.attest --signature idevid_certify.sig \
    --hash sha${HASH_ALGORITHM}

echo "Generating IDevID and IAK certificates (TCG sec. 8 fields)..."
bash "${DEVID_TOOL}" cert --role idevid --pubkey idevid_pub.pem --ek-der ek_pub.der \
    --ca-cert root_ca_cert.pem --ca-key "handle:${ROOT_KEY}" \
    --provider tpm2 --provider default --hash sha${HASH_ALGORITHM} \
    --common-name "SPDM-EMU IDevID" --device-serial "${DEVICE_SERIAL}" \
    --out idevid_cert.der
bash "${DEVID_TOOL}" cert --role iak --pubkey iak_pub.pem --ek-der ek_pub.der \
    --ca-cert root_ca_cert.pem --ca-key "handle:${ROOT_KEY}" \
    --provider tpm2 --provider default --hash sha${HASH_ALGORITHM} \
    --common-name "SPDM-EMU IAK" --device-serial "${DEVICE_SERIAL}" --out iak_cert.der
openssl x509 -inform DER -in idevid_cert.der -out idevid_cert.pem
openssl x509 -inform DER -in iak_cert.der -out iak_cert.pem
openssl verify -CAfile root_ca_cert.pem idevid_cert.pem iak_cert.pem

# Preserve the existing responder certificate and Root-first chain NV layout.
echo "Storing responder certificate into TPM NV ${RESP_CERT}"
tpm2_nvdefine ${RESP_CERT} -C o -s $(stat -c %s idevid_cert.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${RESP_CERT} -C o -i idevid_cert.der
cat root_ca_cert.der idevid_cert.der > responder_certchain.der
echo "Storing responder certificate chain into TPM NV ${RESP_CERT_CHAIN}"
tpm2_nvdefine ${RESP_CERT_CHAIN} -C o -s $(stat -c %s responder_certchain.der) -a "ownerread|ownerwrite|authread|authwrite"
tpm2_nvwrite ${RESP_CERT_CHAIN} -C o -i responder_certchain.der

# TCG IAK chain: DER, leaf first, without the Root CA certificate.
echo "Storing IAK certificate chain into TPM NV ${IAK_CERT_CHAIN}"
tpm2_nvdefine ${IAK_CERT_CHAIN} -C o -s $(stat -c %s iak_cert.der) -a "ownerread|ownerwrite|authread|no_da"
tpm2_nvwrite ${IAK_CERT_CHAIN} -C o -i iak_cert.der

echo "Flushing transient objects..."
tpm2_flushcontext --transient-object || true

echo "Device serial (IDevID/IAK Subject serialNumber): ${DEVICE_SERIAL}"

if [ -n "$START_SWTPM" ] ; then
    echo "Run following command before using SWTPM via tpm2-tools"
    echo "  $ export TMP2TOOLS_TCTI=swtpm:port=2321"

    if [ -n "$WAIT_SWTPM" ] ; then
        echo "Press CTRL+C to stop swtpm"
        wait $SWTPM_PID
    fi
fi

echo "Done"