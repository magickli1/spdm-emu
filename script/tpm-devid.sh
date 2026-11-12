#!/bin/bash
#
#  Copyright Notice:
#  Copyright 2026 DMTF. All rights reserved.
#  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
#
# TCG DevID helper for setup-tpm.sh (IDevID = SPDM slot 0 identity, IAK = Quote key).
#
# Implements the parts of TCG "TPM 2.0 Keys for Device Identity and Attestation"
# v1.10 r9 that the emulator provisioning needs (the TCG-CSR-IDEVID enrollment
# protocol itself is out of scope):
#
#   policy        authPolicy PolicyIDevIDKey (sec. 7.4.6) and the PolicyOR branch
#                 digests, for the Recoverable IDevID/IAK key templates (sec. 7.4.4)
#   unique        template unique field 'IDEVID' / 'IAK' (sec. 7.4.1)
#   cert          IDevID / IAK certificate with the fields of sec. 8
#   enroll-check  CA-side check that the IDevID and the IAK are in the same TPM
#
# Needs bash, openssl, xxd and tpm2_print. Binary data uses lower-case hex strings.

set -euo pipefail

fail() {
    echo "tpm-devid: FAILED: $*" >&2
    exit 1
}

# ---------------------------------------------------------------- hex helpers

h2b() { printf '%s' "$1" | xxd -r -p; }
b2h() { xxd -p | tr -d '\n'; }
file_hex() { xxd -p "$1" | tr -d '\n'; }
hex_len() { echo $((${#1} / 2)); }
# hex_sub HEX OFFSET LENGTH (in bytes)
hex_sub() { printf '%s' "${1:$((2 * $2)):$((2 * $3))}"; }
hex_u16() { echo $((16#$(hex_sub "$1" "$2" 2))); }
hex_u32() { echo $((16#$(hex_sub "$1" "$2" 4))); }
u16() { printf '%04x' "$1"; }
u32() { printf '%08x' "$1"; }
str_hex() { printf '%s' "$1" | b2h; }
# hash_hex ALG HEX
hash_hex() { h2b "$2" | openssl dgst "-$1" -binary | b2h; }

# ---------------------------------------------------------------- constants

tpm_alg() {
    case $1 in
    sha256) echo 000b ;;
    sha384) echo 000c ;;
    sha512) echo 000d ;;
    *) fail "unsupported hash $1" ;;
    esac
}
alg_name() {
    case $1 in
    000b) echo sha256 ;;
    000c) echo sha384 ;;
    000d) echo sha512 ;;
    *) fail "unsupported nameAlg 0x$1" ;;
    esac
}

TPM_RH_ENDORSEMENT=4000000b
TPM_CC_POLICY_SECRET=00000151
TPM_CC_POLICY_COMMAND_CODE=0000016c
TPM_CC_POLICY_OR=00000171
TPM_CC_POLICY_AUTHORIZE_NV=00000192
TPM_CC_CERTIFY=00000148
TPM_CC_ACTIVATE_CREDENTIAL=00000147

# sec. 7.4.3 / 7.4.5: Policy NV indices (signing key DSx, attestation key DAx)
policy_nv_index() {
    case $1-$2 in
    idevid-sha256) echo 01c90010 ;;
    idevid-sha384) echo 01c90011 ;;
    idevid-sha512) echo 01c90012 ;;
    iak-sha256) echo 01c90018 ;;
    iak-sha384) echo 01c90019 ;;
    iak-sha512) echo 01c9001a ;;
    *) fail "no policy NV index for $1 / $2" ;;
    esac
}
POLICY_NV_ATTRIBUTES=220f1008 # Table 14

# Table 24, used as a self-check of the computation
policy_idevid_key_expected() {
    case $1-$2 in
    idevid-sha256) echo ad6b3a2284fd698a0710bf5cc1b9bdf15e2532e3f601fa4b93a6a8fa8de579ea ;;
    iak-sha256) echo 5437182326e414fca797d5f174615a1641f61255797c3a2b22c21d120b2d1e07 ;;
    *) echo "" ;;
    esac
}

TPM_GENERATED_VALUE=$((0xFF544347))
TPM_ST_ATTEST_CERTIFY=$((0x8017))
FIXED_TPM=$((0x00000002))
FIXED_PARENT=$((0x00000010))
SENSITIVE_DATA_ORIGIN=$((0x00000020))
USER_WITH_AUTH=$((0x00000040))
ADMIN_WITH_POLICY=$((0x00000080))
NO_DA=$((0x00000400))
RESTRICTED=$((0x00010000))
DECRYPT=$((0x00020000))
SIGN=$((0x00040000))

OID_HW_MODULE_NAME=1.3.6.1.5.5.7.8.4          # RFC 4108 id-on-hardwareModuleName
OID_PERMANENT_ID=1.3.6.1.5.5.7.8.3            # RFC 4043 id-on-permanentIdentifier
OID_TCG_TPM20=2.23.133.1.2                    # hwType TPM 2.0 (sec. 8.1)
OID_TCG_PERM_ID_SHA256=2.23.133.12.1          # tcg-on-ekPermIdSha256 (Table 28)
OID_TCG_VERIFIED_TPM_RESIDENCY=2.23.133.11.1.1
OID_TCG_VERIFIED_TPM_FIXED=2.23.133.11.1.2
OID_TCG_VERIFIED_TPM_RESTRICTED=2.23.133.11.1.3
OID_TCG_INTENDED_USE_DEVID=2.23.133.11.1.4
OID_DMTF_DEVICE_INFO=1.3.6.1.4.1.412.274.1   # DSP0274 SubjectAltName otherName
OID_DMTF_EKU_RESPONDER_AUTH=1.3.6.1.4.1.412.274.3
OID_KP_CLIENT_AUTH=1.3.6.1.5.5.7.3.2
OID_CN=2.5.4.3
OID_SERIAL_NUMBER=2.5.4.5
OID_ORGANIZATION=2.5.4.10
OID_BASIC_CONSTRAINTS=2.5.29.19
OID_KEY_USAGE=2.5.29.15
OID_EXT_KEY_USAGE=2.5.29.37
OID_SAN=2.5.29.17
OID_CERT_POLICIES=2.5.29.32
OID_SKI=2.5.29.14
OID_AKI=2.5.29.35

sig_alg_oid() {
    case $1-$2 in
    ec-sha256) echo 1.2.840.10045.4.3.2 ;;
    ec-sha384) echo 1.2.840.10045.4.3.3 ;;
    ec-sha512) echo 1.2.840.10045.4.3.4 ;;
    rsa-sha256) echo 1.2.840.113549.1.1.11 ;;
    rsa-sha384) echo 1.2.840.113549.1.1.12 ;;
    rsa-sha512) echo 1.2.840.113549.1.1.13 ;;
    *) fail "unsupported CA key / hash $1 / $2" ;;
    esac
}

# ---------------------------------------------------------------- DER encoding

der_len() {
    local n=$1 b=""
    if [ "$n" -lt 128 ]; then
        printf '%02x' "$n"
        return
    fi
    while [ "$n" -gt 0 ]; do
        b=$(printf '%02x' $((n & 0xff)))$b
        n=$((n >> 8))
    done
    printf '%02x%s' $((0x80 | ${#b} / 2)) "$b"
}
tlv() { printf '%s%s%s' "$1" "$(der_len "$(hex_len "$2")")" "$2"; }
seq() { tlv 30 "$(printf '%s' "$@")"; }
oid() {
    local IFS=. parts body="" p enc
    read -r -a parts <<< "$1"
    body=$(printf '%02x' $((40 * parts[0] + parts[1])))
    for p in "${parts[@]:2}"; do
        enc=$(printf '%02x' $((p & 0x7f)))
        p=$((p >> 7))
        while [ "$p" -gt 0 ]; do
            enc=$(printf '%02x' $((0x80 | (p & 0x7f))))$enc
            p=$((p >> 7))
        done
        body=$body$enc
    done
    tlv 06 "$body"
}
octet_string() { tlv 04 "$1"; }
bit_string() { tlv 03 "$(printf '%02x' "${2:-0}")$1"; }
utf8() { tlv 0c "$(str_hex "$1")"; }
name_attr() { tlv 31 "$(seq "$(oid "$1")" "$(tlv "${3:-0c}" "$(str_hex "$2")")")"; }
extension() { # oid value-hex [critical]
    if [ "${3:-}" = critical ]; then
        seq "$(oid "$1")" 0101ff "$(octet_string "$2")"
    else
        seq "$(oid "$1")" "$(octet_string "$2")"
    fi
}
other_name() { tlv a0 "$(oid "$1")$(tlv a0 "$2")"; }

# ---------------------------------------------------------------- DER parsing

# der_list DER-FILE: "offset depth header-length length" of every element (absolute offsets),
# from openssl asn1parse.
der_list() {
    openssl asn1parse -inform DER -in "$1" |
        awk '{
            off = $1; sub(":.*", "", off)
            line = $0
            match(line, /d= *[0-9]+/); d = substr(line, RSTART, RLENGTH); gsub(/[^0-9]/, "", d)
            match(line, /hl= *[0-9]+/); hl = substr(line, RSTART, RLENGTH); gsub(/[^0-9]/, "", hl)
            match(line, / l= *[0-9]+/); l = substr(line, RSTART, RLENGTH); gsub(/[^0-9]/, "", l)
            print off, d, hl, l
        }'
}

# der_children DER-FILE PARENT-OFFSET: "offset header-length length" of the direct children of
# the constructed element at PARENT-OFFSET.
der_children() {
    der_list "$1" | awk -v p="$2" '
        $1 == p { pd = $2; end = $1 + $3 + $4; found = 1; next }
        found && $1 >= end { exit }
        found && $2 == pd + 1 { print $1, $3, $4 }'
}

# der_child_hex DER-FILE PARENT-OFFSET INDEX: raw TLV hex of a direct child of an element.
der_child_hex() {
    local file=$1 parent=$2 index=$3 line off hl l
    line=$(der_children "$file" "$parent" | sed -n "$((index + 1))p")
    [ -n "$line" ] || fail "$file: DER child $index of offset $parent missing"
    read -r off hl l <<< "$line"
    hex_sub "$(file_hex "$file")" "$off" $((hl + l))
}

# tlv_value HEX: value of a single TLV.
tlv_value() {
    local hex=$1 len hdr n
    len=$((16#${hex:2:2}))
    hdr=2
    if [ $((len & 0x80)) -ne 0 ]; then
        n=$((len & 0x7f))
        len=$((16#${hex:4:$((2 * n))}))
        hdr=$((2 + n))
    fi
    hex_sub "$hex" "$hdr" "$len"
}

# spki_bits DER-FILE: subjectPublicKey BIT STRING value of a SubjectPublicKeyInfo, without the
# unused-bits byte (which must be 0).
spki_bits() {
    local bits
    bits=$(tlv_value "$(der_child_hex "$1" 0 1)")
    [ "${bits:0:2}" = 00 ] || fail "$1: public key is not a BIT STRING with unused-bits 0"
    printf '%s' "${bits:2}"
}

# ---------------------------------------------------------------- policy (sec. 7.4.6)

# policy_branches ROLE HASH: sets P_USER P_CERTIFY P_ACTIVATE P_DELEGATION P_KEY
policy_branches() {
    local role=$1 hash=$2 alg size zero nv_public nv_name expected
    alg=$(tpm_alg "$hash")
    size=$(hex_len "$(hash_hex "$hash" "")")
    zero=$(printf '%0*d' $((2 * size)) 0)
    P_USER=$(hash_hex "$hash" "$(hash_hex "$hash" "$zero$TPM_CC_POLICY_SECRET$TPM_RH_ENDORSEMENT")")
    P_CERTIFY=$(hash_hex "$hash" "$P_USER$TPM_CC_POLICY_COMMAND_CODE$TPM_CC_CERTIFY")
    P_ACTIVATE=$(hash_hex "$hash" "$P_USER$TPM_CC_POLICY_COMMAND_CODE$TPM_CC_ACTIVATE_CREDENTIAL")
    nv_public=$(policy_nv_index "$role" "$hash")$alg$POLICY_NV_ATTRIBUTES$(u16 "$size")$P_USER$(u16 $((size + 2)))
    nv_name=$alg$(hash_hex "$hash" "$nv_public")
    P_DELEGATION=$(hash_hex "$hash" "$zero$TPM_CC_POLICY_AUTHORIZE_NV$nv_name")
    P_KEY=$(hash_hex "$hash" "$zero$TPM_CC_POLICY_OR$P_USER$P_CERTIFY$P_ACTIVATE$P_DELEGATION")
    expected=$(policy_idevid_key_expected "$role" "$hash")
    if [ -n "$expected" ] && [ "$P_KEY" != "$expected" ]; then
        fail "PolicyIDevIDKey self-check against TCG Table 24 failed"
    fi
}

cmd_policy() {
    local role="" hash=sha256 out_dir=""
    while [ $# -gt 0 ]; do
        case $1 in
        --role) role=$2; shift ;;
        --hash) hash=$2; shift ;;
        --out-dir) out_dir=$2; shift ;;
        *) fail "policy: unknown argument $1" ;;
        esac
        shift
    done
    check_role "$role"
    [ -n "$out_dir" ] || fail "policy: --out-dir is required"
    policy_branches "$role" "$hash"
    mkdir -p "$out_dir"
    h2b "$P_USER" > "$out_dir/${role}_policy_user.bin"
    h2b "$P_CERTIFY" > "$out_dir/${role}_policy_certify.bin"
    h2b "$P_ACTIVATE" > "$out_dir/${role}_policy_activate.bin"
    h2b "$P_DELEGATION" > "$out_dir/${role}_policy_delegation.bin"
    h2b "$P_KEY" > "$out_dir/${role}_policy_key.bin"
    echo "$role PolicyIDevIDKey ($hash): $P_KEY"
}

check_role() {
    case $1 in
    idevid | iak) ;;
    *) fail "--role must be idevid or iak" ;;
    esac
}

# ---------------------------------------------------------------- unique (sec. 7.4.1)

cmd_unique() {
    local role="" alg="" out="" value
    while [ $# -gt 0 ]; do
        case $1 in
        --role) role=$2; shift ;;
        --alg) alg=$2; shift ;;
        --out) out=$2; shift ;;
        *) fail "unique: unknown argument $1" ;;
        esac
        shift
    done
    check_role "$role"
    [ -n "$out" ] || fail "unique: --out is required"
    if [ "$role" = idevid ]; then value=$(str_hex IDEVID); else value=$(str_hex IAK); fi
    # tpm2-tools -u expects TPMU_PUBLIC_ID with little-endian size words
    case $alg in
    ecc) h2b "$(printf '%02x00' "$(hex_len "$value")")${value}0000" > "$out" ;;
    rsa) h2b "$(printf '%02x00' "$(hex_len "$value")")${value}" > "$out" ;;
    *) fail "unique: --alg must be ecc or rsa" ;;
    esac
}

# ---------------------------------------------------------------- cert (sec. 8)

cmd_cert() {
    local role="" pubkey="" ek_der="" ca_cert="" ca_key="" hash=sha256 organization=SPDM-EMU
    local common_name="" device_serial="" dmtf_identity="" out="" providers=()
    while [ $# -gt 0 ]; do
        case $1 in
        --role) role=$2; shift ;;
        --pubkey) pubkey=$2; shift ;;
        --ek-der) ek_der=$2; shift ;;
        --ca-cert) ca_cert=$2; shift ;;
        --ca-key) ca_key=$2; shift ;;
        --provider) providers+=(-provider "$2"); shift ;;
        --hash) hash=$2; shift ;;
        --organization) organization=$2; shift ;;
        --common-name) common_name=$2; shift ;;
        --device-serial) device_serial=$2; shift ;;
        --dmtf-identity) dmtf_identity=$2; shift ;;
        --out) out=$2; shift ;;
        *) fail "cert: unknown argument $1" ;;
        esac
        shift
    done
    check_role "$role"
    for v in pubkey ek_der ca_cert ca_key common_name device_serial out; do
        [ -n "${!v}" ] || fail "cert: --${v//_/-} is required"
    done

    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN

    # CA certificate: subject, key type and key identifier
    openssl x509 -in "$ca_cert" -outform DER -out "$tmp/ca.der"
    local tbs_offset idx ca_subject ca_type ca_key_id
    tbs_offset=$(der_children "$tmp/ca.der" 0 | sed -n 1p | awk '{print $1}')
    if [ "$(der_child_hex "$tmp/ca.der" "$tbs_offset" 0 | cut -c1-2)" = a0 ]; then idx=1; else idx=0; fi
    ca_subject=$(der_child_hex "$tmp/ca.der" "$tbs_offset" $((idx + 4)))
    openssl x509 -in "$ca_cert" -noout -pubkey | openssl pkey -pubin -outform DER -out "$tmp/ca_spki.der"
    if openssl x509 -in "$ca_cert" -noout -text | grep -q "Public Key Algorithm: id-ecPublicKey"; then
        ca_type=ec
    elif openssl x509 -in "$ca_cert" -noout -text | grep -q "Public Key Algorithm: rsaEncryption"; then
        ca_type=rsa
    else
        fail "unsupported CA key algorithm"
    fi
    ca_key_id=$(openssl x509 -in "$ca_cert" -noout -ext subjectKeyIdentifier 2> /dev/null |
        sed -n '2p' | tr -d ' :\n' | tr 'A-F' 'a-f')
    if [ -z "$ca_key_id" ]; then
        # RFC 5280 4.2.1.2 method (1): SHA-1 of the subjectPublicKey BIT STRING value
        ca_key_id=$(hash_hex sha1 "$(spki_bits "$tmp/ca_spki.der")")
    fi

    # Subject key and EK
    openssl pkey -pubin -in "$pubkey" -outform DER -out "$tmp/spki.der"
    local spki ek_pub sig_alg
    spki=$(file_hex "$tmp/spki.der")
    ek_pub=$(spki_bits "$ek_der")
    if [ "$ca_type" = rsa ]; then
        sig_alg=$(seq "$(oid "$(sig_alg_oid "$ca_type" "$hash")")" 0500)
    else
        sig_alg=$(seq "$(oid "$(sig_alg_oid "$ca_type" "$hash")")")
    fi

    # serialNumber: unique, non-negative, 64..160 bits (Table 26): 127 random bits, bit 126 set
    local serial
    serial=$(openssl rand -hex 16)
    serial=$(printf '%02x' $(((16#${serial:0:2} & 0x7f) | 0x40)))${serial:2}

    local not_before validity subject
    if [ "$(date -u +%Y)" -lt 2050 ]; then
        not_before=$(tlv 17 "$(str_hex "$(date -u +%y%m%d%H%M%SZ)")")
    else
        not_before=$(tlv 18 "$(str_hex "$(date -u +%Y%m%d%H%M%SZ)")")
    fi
    validity=$(seq "$not_before" "$(tlv 18 "$(str_hex 99991231235959Z)")")

    # Subject: unique DN with the device serial number as X520SerialNumber (sec. 8)
    subject=$(seq "$(name_attr "$OID_ORGANIZATION" "$organization")" \
        "$(name_attr "$OID_CN" "$common_name")" \
        "$(name_attr "$OID_SERIAL_NUMBER" "$device_serial" 13)")

    # subjectAltName is not critical: the Subject already has a value.
    # hardwareModuleName (sec. 8.1 method 2: hwSerialNum = SHA-256(EK public key)) SHALL
    # identify the TPM. PermanentIdentifier MAY correlate certificates to that TPM; an
    # IDevID/IAK that includes it SHALL carry both identifierValue and assigner.
    local hw_serial perm_id general_names
    hw_serial=$(hash_hex sha256 "$ek_pub")
    perm_id=$(hash_hex sha256 "$(str_hex EkPubkey)$ek_pub")
    general_names=$(other_name "$OID_HW_MODULE_NAME" "$(seq "$(oid "$OID_TCG_TPM20")" "$(octet_string "$hw_serial")")")
    general_names=$general_names$(other_name "$OID_PERMANENT_ID" "$(seq "$(utf8 "$perm_id")" "$(oid "$OID_TCG_PERM_ID_SHA256")")")
    if [ -n "$dmtf_identity" ]; then
        general_names=$general_names$(other_name "$OID_DMTF_DEVICE_INFO" "$(utf8 "$dmtf_identity")")
    fi

    local policies p policy_seq="" exts
    if [ "$role" = iak ]; then
        policies="$OID_TCG_VERIFIED_TPM_RESIDENCY $OID_TCG_VERIFIED_TPM_RESTRICTED"
    else
        policies="$OID_TCG_VERIFIED_TPM_RESIDENCY $OID_TCG_VERIFIED_TPM_FIXED $OID_TCG_INTENDED_USE_DEVID"
    fi
    for p in $policies; do
        policy_seq=$policy_seq$(seq "$(oid "$p")")
    done

    exts=$(extension "$OID_BASIC_CONSTRAINTS" "$(seq)" critical)
    # keyUsage MUST be included: digitalSignature (IDevID and IAK)
    exts=$exts$(extension "$OID_KEY_USAGE" "$(bit_string 80 7)" critical)
    exts=$exts$(extension "$OID_SAN" "$(seq "$general_names")")
    # certificatePolicies MUST be present; policyIdentifier only, no qualifier
    exts=$exts$(extension "$OID_CERT_POLICIES" "$(seq "$policy_seq")")
    exts=$exts$(extension "$OID_SKI" "$(octet_string "$(hash_hex sha1 "$(spki_bits "$tmp/spki.der")")")")
    exts=$exts$(extension "$OID_AKI" "$(seq "$(tlv 80 "$ca_key_id")")")
    if [ "$role" = idevid ]; then
        # id-kp-clientAuth RECOMMENDED for IDevID; DMTF responder auth for SPDM
        exts=$exts$(extension "$OID_EXT_KEY_USAGE" "$(seq "$(oid "$OID_KP_CLIENT_AUTH")" "$(oid "$OID_DMTF_EKU_RESPONDER_AUTH")")")
    fi

    local tbs signature
    tbs=$(seq "$(tlv a0 "$(tlv 02 02)")" "$(tlv 02 "$serial")" "$sig_alg" "$ca_subject" \
        "$validity" "$subject" "$spki" "$(tlv a3 "$(seq "$exts")")")
    h2b "$tbs" > "$tmp/tbs.der"
    openssl dgst "-$hash" "${providers[@]}" -sign "$ca_key" -out "$tmp/tbs.sig" "$tmp/tbs.der"
    signature=$(file_hex "$tmp/tbs.sig")

    h2b "$(seq "$tbs" "$sig_alg" "$(bit_string "$signature")")" > "$out"
    echo "$role certificate: serial 0x${serial#"${serial%%[!0]*}"}, notAfter 99991231235959Z, hwSerialNum $hw_serial"
}

# ---------------------------------------------------------------- enroll-check

# read_tpm2b_public FILE: TPMT_PUBLIC hex of a TPM2B_PUBLIC file
read_tpm2b_public() {
    local hex
    hex=$(file_hex "$1")
    [ $(($(hex_u16 "$hex" 0) + 2)) -eq "$(hex_len "$hex")" ] || fail "$1: TPM2B_PUBLIC size mismatch"
    printf '%s' "${hex:4}"
}

# check_template LABEL ROLE TPMT_PUBLIC-HEX: template H-0 attributes and the PolicyIDevIDKey
# authPolicy; prints the Name of the public area.
check_template() {
    local label=$1 role=$2 pub=$3 name_alg hash attributes policy_size auth_policy required forbidden
    name_alg=$(hex_sub "$pub" 2 2)
    hash=$(alg_name "$name_alg")
    attributes=$(hex_u32 "$pub" 4)
    policy_size=$(hex_u16 "$pub" 8)
    auth_policy=$(hex_sub "$pub" 10 "$policy_size")
    required=$((FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | ADMIN_WITH_POLICY | SIGN))
    forbidden=$((NO_DA | DECRYPT))
    if [ "$role" = iak ]; then
        required=$((required | RESTRICTED))
    else
        forbidden=$((forbidden | RESTRICTED))
    fi
    if [ $((attributes & required)) -ne $required ] || [ $((attributes & forbidden)) -ne 0 ]; then
        fail "$label attributes $(printf '0x%08x' "$attributes") do not match template H-0"
    fi
    policy_branches "$role" "$hash"
    [ "$auth_policy" = "$P_KEY" ] || fail "$label authPolicy is not PolicyIDevIDKey"
    printf '%s%s' "$name_alg" "$(hash_hex "$hash" "$pub")"
}

# The caller first authenticates the IAK Name through EK credential activation
# (setup-tpm.sh does this). This step binds the supplied key to that public area
# and verifies its TPM2_Certify proof for the IDevID.
cmd_enroll_check() {
    local iak_public="" iak_pem="" idevid_public="" attest="" signature="" hash=sha256
    while [ $# -gt 0 ]; do
        case $1 in
        --iak-public) iak_public=$2; shift ;;
        --iak-pem) iak_pem=$2; shift ;;
        --idevid-public) idevid_public=$2; shift ;;
        --attest) attest=$2; shift ;;
        --signature) signature=$2; shift ;;
        --hash) hash=$2; shift ;;
        *) fail "enroll-check: unknown argument $1" ;;
        esac
        shift
    done
    for v in iak_public iak_pem idevid_public attest signature; do
        [ -n "${!v}" ] || fail "enroll-check: --${v//_/-} is required"
    done

    local idevid_name att off size certified_name iak_area expected_spki supplied_spki
    local verify_options=()
    iak_area=$(read_tpm2b_public "$iak_public")
    check_template IAK iak "$iak_area" > /dev/null
    # Bind the signature verification key to the public area whose TPM attributes
    # and policy were checked. A separately supplied software key is not an IAK.
    expected_spki=$(tpm2_print -t TPM2B_PUBLIC -f pem "$iak_public" |
        openssl pkey -pubin -outform DER | b2h)
    supplied_spki=$(openssl pkey -pubin -in "$iak_pem" -outform DER | b2h)
    [ "$expected_spki" = "$supplied_spki" ] || fail "IAK PEM does not match TPM public area"
    if [ "$(hex_sub "$iak_area" 0 2)" = 0001 ]; then
        verify_options=(-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest)
    fi
    idevid_name=$(check_template IDevID idevid "$(read_tpm2b_public "$idevid_public")")

    # TPMS_ATTEST: magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion,
    # TPMS_CERTIFY_INFO {name, qualifiedName}
    att=$(file_hex "$attest")
    [ "$(hex_u32 "$att" 0)" -eq $TPM_GENERATED_VALUE ] && [ "$(hex_u16 "$att" 4)" -eq $TPM_ST_ATTEST_CERTIFY ] ||
        fail "not a TPM-generated certify attestation"
    off=6
    off=$((off + 2 + $(hex_u16 "$att" $off))) # qualifiedSigner
    off=$((off + 2 + $(hex_u16 "$att" $off))) # extraData
    off=$((off + 8 + 4 + 4 + 1 + 8))           # clockInfo, firmwareVersion
    size=$(hex_u16 "$att" $off)
    certified_name=$(hex_sub "$att" $((off + 2)) "$size")
    off=$((off + 2 + size))
    off=$((off + 2 + $(hex_u16 "$att" $off))) # qualifiedName
    [ $off -eq "$(hex_len "$att")" ] || fail "trailing bytes in TPMS_ATTEST"
    [ "$certified_name" = "$idevid_name" ] || fail "certified Name != Name(IDevID public area)"
    openssl dgst "-$hash" "${verify_options[@]}" -verify "$iak_pem" -signature "$signature" "$attest" > /dev/null 2>&1 ||
        fail "certify signature does not verify with the IAK"
    echo "CA enrollment check passed: IDevID and IAK follow the TCG templates and are in the same TPM"
}

usage() {
    sed -n '7,19p' "$0" | sed 's/^# \{0,1\}//'
    echo "usage: $0 {policy|unique|cert|enroll-check} [options]"
}

[ $# -ge 1 ] || { usage >&2; exit 1; }
cmd=$1
shift
case $cmd in
policy) cmd_policy "$@" ;;
unique) cmd_unique "$@" ;;
cert) cmd_cert "$@" ;;
enroll-check) cmd_enroll_check "$@" ;;
-h | --help) usage ;;
*) usage >&2; exit 1 ;;
esac
