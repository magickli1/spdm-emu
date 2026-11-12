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

hex_to_binary() { printf '%s' "$1" | xxd -r -p; }
binary_to_hex() { xxd -p | tr -d '\n'; }
read_file_hex() { xxd -p "$1" | tr -d '\n'; }
hex_byte_length() { echo $((${#1} / 2)); }
# hex_slice HEX OFFSET LENGTH (in bytes)
hex_slice() { printf '%s' "${1:$((2 * $2)):$((2 * $3))}"; }
read_u16_be() { echo $((16#$(hex_slice "$1" "$2" 2))); }
read_u32_be() { echo $((16#$(hex_slice "$1" "$2" 4))); }
encode_u16_be_hex() { printf '%04x' "$1"; }
encode_u32_be_hex() { printf '%08x' "$1"; }
string_to_hex() { printf '%s' "$1" | binary_to_hex; }
# hash_hex_data ALG HEX
hash_hex_data() { hex_to_binary "$2" | openssl dgst "-$1" -binary | binary_to_hex; }

# ---------------------------------------------------------------- constants

get_tpm_hash_algorithm_id() {
    case $1 in
    sha256) echo 000b ;;
    sha384) echo 000c ;;
    sha512) echo 000d ;;
    *) fail "unsupported hash $1" ;;
    esac
}
get_tpm_hash_algorithm_name() {
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
get_policy_nv_index() {
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
get_expected_key_policy_digest() {
    case $1-$2 in
    idevid-sha256) echo ad6b3a2284fd698a0710bf5cc1b9bdf15e2532e3f601fa4b93a6a8fa8de579ea ;;
    iak-sha256) echo 5437182326e414fca797d5f174615a1641f61255797c3a2b22c21d120b2d1e07 ;;
    idevid-sha384) echo 4db1aa836d0b5615df6ee53a40ef70c61c217f4303d44695925972bc927006cfa5cbdf6dc18c4dbe329b2f1542c3dd33 ;;
    iak-sha384) echo 129d94ebf84556652c6eef43bbb757512ac87e52be7b349ca6ce4d826f749fcf672f51716c5cbb605f313bf345aab312 ;;
    idevid-sha512) echo 7dd7500fd6c1b94f97a6af910da147301ef28f662fee06f225a4ccadda3b4e6b38e66b2f3ad5dee1a0503cd2daedb1e68cfe4f84b03a8cd22bb6a976f071a72f ;;
    iak-sha512) echo 8060d1fb31716a29e48a6e5fece088bcfc1b278fc162255e81c3eca3544cd44af94410c3715d561cccd9e39a6cb2646d43535bb54ea88710deb5f7836bd9b586 ;;
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
RESTRICTED=$((0x00010000))
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

get_signature_algorithm_oid() {
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

der_encode_length() {
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
der_encode_tlv() { printf '%s%s%s' "$1" "$(der_encode_length "$(hex_byte_length "$2")")" "$2"; }
der_encode_sequence() { der_encode_tlv 30 "$(printf '%s' "$@")"; }
der_encode_oid() {
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
    der_encode_tlv 06 "$body"
}
der_encode_octet_string() { der_encode_tlv 04 "$1"; }
der_encode_bit_string() { der_encode_tlv 03 "$(printf '%02x' "${2:-0}")$1"; }
der_encode_utf8_string() { der_encode_tlv 0c "$(string_to_hex "$1")"; }
der_encode_name_attribute() { der_encode_tlv 31 "$(der_encode_sequence "$(der_encode_oid "$1")" "$(der_encode_tlv "${3:-0c}" "$(string_to_hex "$2")")")"; }
der_encode_extension() { # oid value-hex [critical]
    if [ "${3:-}" = critical ]; then
        der_encode_sequence "$(der_encode_oid "$1")" 0101ff "$(der_encode_octet_string "$2")"
    else
        der_encode_sequence "$(der_encode_oid "$1")" "$(der_encode_octet_string "$2")"
    fi
}
der_encode_other_name() { der_encode_tlv a0 "$(der_encode_oid "$1")$(der_encode_tlv a0 "$2")"; }

# ---------------------------------------------------------------- DER parsing

# der_list_elements DER-FILE: "offset depth header-length length" of every element (absolute offsets),
# from openssl asn1parse.
der_list_elements() {
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

# der_list_children DER-FILE PARENT-OFFSET: "offset header-length length" of the direct children of
# the constructed element at PARENT-OFFSET.
der_list_children() {
    der_list_elements "$1" | awk -v p="$2" '
        $1 == p { pd = $2; end = $1 + $3 + $4; found = 1; next }
        found && $1 >= end { exit }
        found && $2 == pd + 1 { print $1, $3, $4 }'
}

# der_read_child_hex DER-FILE PARENT-OFFSET INDEX: raw TLV hex of a direct child of an element.
der_read_child_hex() {
    local file=$1 parent=$2 index=$3 line off hl l
    line=$(der_list_children "$file" "$parent" | sed -n "$((index + 1))p")
    [ -n "$line" ] || fail "$file: DER child $index of offset $parent missing"
    read -r off hl l <<< "$line"
    hex_slice "$(read_file_hex "$file")" "$off" $((hl + l))
}

# der_decode_value HEX: value of a single TLV.
der_decode_value() {
    local hex=$1 len hdr n
    len=$((16#${hex:2:2}))
    hdr=2
    if [ $((len & 0x80)) -ne 0 ]; then
        n=$((len & 0x7f))
        len=$((16#${hex:4:$((2 * n))}))
        hdr=$((2 + n))
    fi
    hex_slice "$hex" "$hdr" "$len"
}

# read_spki_public_key_hex DER-FILE: subjectPublicKey BIT STRING value of a SubjectPublicKeyInfo, without the
# unused-bits byte (which must be 0).
read_spki_public_key_hex() {
    local bits
    bits=$(der_decode_value "$(der_read_child_hex "$1" 0 1)")
    [ "${bits:0:2}" = 00 ] || fail "$1: public key is not a BIT STRING with unused-bits 0"
    printf '%s' "${bits:2}"
}

# ---------------------------------------------------------------- policy (sec. 7.4.6)

# compute_key_policy_digests ROLE HASH: sets P_USER P_CERTIFY P_ACTIVATE P_DELEGATION P_KEY
compute_key_policy_digests() {
    local role=$1 hash=$2 alg size zero nv_public nv_name expected
    alg=$(get_tpm_hash_algorithm_id "$hash")
    size=$(hex_byte_length "$(hash_hex_data "$hash" "")")
    zero=$(printf '%0*d' $((2 * size)) 0)
    P_USER=$(hash_hex_data "$hash" "$(hash_hex_data "$hash" "$zero$TPM_CC_POLICY_SECRET$TPM_RH_ENDORSEMENT")")
    P_CERTIFY=$(hash_hex_data "$hash" "$P_USER$TPM_CC_POLICY_COMMAND_CODE$TPM_CC_CERTIFY")
    P_ACTIVATE=$(hash_hex_data "$hash" "$P_USER$TPM_CC_POLICY_COMMAND_CODE$TPM_CC_ACTIVATE_CREDENTIAL")
    nv_public=$(get_policy_nv_index "$role" "$hash")$alg$POLICY_NV_ATTRIBUTES$(encode_u16_be_hex "$size")$P_USER$(encode_u16_be_hex $((size + 2)))
    nv_name=$alg$(hash_hex_data "$hash" "$nv_public")
    P_DELEGATION=$(hash_hex_data "$hash" "$zero$TPM_CC_POLICY_AUTHORIZE_NV$nv_name")
    P_KEY=$(hash_hex_data "$hash" "$zero$TPM_CC_POLICY_OR$P_USER$P_CERTIFY$P_ACTIVATE$P_DELEGATION")
    expected=$(get_expected_key_policy_digest "$role" "$hash")
    if [ -n "$expected" ] && [ "$P_KEY" != "$expected" ]; then
        fail "PolicyIDevIDKey self-check against TCG Table 24 failed"
    fi
}

cmd_generate_policy() {
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
    validate_key_role "$role"
    [ -n "$out_dir" ] || fail "policy: --out-dir is required"
    compute_key_policy_digests "$role" "$hash"
    mkdir -p "$out_dir"
    hex_to_binary "$P_USER" > "$out_dir/${role}_policy_user.bin"
    hex_to_binary "$P_CERTIFY" > "$out_dir/${role}_policy_certify.bin"
    hex_to_binary "$P_ACTIVATE" > "$out_dir/${role}_policy_activate.bin"
    hex_to_binary "$P_DELEGATION" > "$out_dir/${role}_policy_delegation.bin"
    hex_to_binary "$P_KEY" > "$out_dir/${role}_policy_key.bin"
    echo "$role PolicyIDevIDKey ($hash): $P_KEY"
}

validate_key_role() {
    case $1 in
    idevid | iak) ;;
    *) fail "--role must be idevid or iak" ;;
    esac
}

# ---------------------------------------------------------------- unique (sec. 7.4.1)

cmd_generate_unique_field() {
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
    validate_key_role "$role"
    [ -n "$out" ] || fail "unique: --out is required"
    if [ "$role" = idevid ]; then value=$(string_to_hex IDEVID); else value=$(string_to_hex IAK); fi
    # tpm2-tools -u expects TPMU_PUBLIC_ID with little-endian size words
    case $alg in
    ecc) hex_to_binary "$(printf '%02x00' "$(hex_byte_length "$value")")${value}0000" > "$out" ;;
    rsa) hex_to_binary "$(printf '%02x00' "$(hex_byte_length "$value")")${value}" > "$out" ;;
    *) fail "unique: --alg must be ecc or rsa" ;;
    esac
}

# ---------------------------------------------------------------- cert (sec. 8)

# A restricted IAK cannot sign a normal CSR. Build the certificate from its
# public key, then sign the TBS with the CA. DER encoding stays in these helpers
# so both roles can use the exact validity and extension forms required by TCG.

# TCG sec. 8.1 defines two TPM identifier forms, depending on whether the
# TPM has an EK certificate. Return hwSerialNum (hex) and PermanentIdentifier.
build_tpm_certificate_identifiers() {
    local ek_der=$1 ek_cert=$2 vendor=$3 ek_pub aki serial cert_spki
    ek_pub=$(read_spki_public_key_hex "$ek_der")
    if [ -z "$ek_cert" ]; then
        printf '%s %s' "$(hash_hex_data sha256 "$ek_pub")" \
            "$(hash_hex_data sha256 "$(string_to_hex EkPubkey)$ek_pub")"
        return
    fi

    # The EK certificate must describe the key used for credential activation.
    cert_spki=$(openssl x509 -inform DER -in "$ek_cert" -noout -pubkey |
        openssl pkey -pubin -outform DER | binary_to_hex)
    [ "$cert_spki" = "$(read_file_hex "$ek_der")" ] || fail "EK certificate does not match EK public key"
    case "$vendor" in
    ''|*[!A-Z0-9\ ]*) fail "EK certificate requires an upper-case TPM vendor ID" ;;
    esac
    aki=$(openssl x509 -inform DER -in "$ek_cert" -noout -ext authorityKeyIdentifier |
        sed -n '2{s/^[[:space:]]*keyid://;s/[ :\r]//g;p;}' | tr 'a-f' 'A-F')
    serial=$(openssl x509 -inform DER -in "$ek_cert" -noout -serial | cut -d= -f2 | tr 'a-f' 'A-F')
    case "$aki:$serial" in
    :*|*:|*[!0-9A-F:]*) fail "EK certificate requires a key identifier and serial number" ;;
    esac
    printf '%s %s' "$(string_to_hex "$vendor:$aki:$serial")" "$(hash_hex_data sha256 "$(read_file_hex "$ek_cert")")"
}

# DER validity: creation time, followed by the IEEE 802.1AR no-expiry value.
build_certificate_validity() {
    local not_before
    if [ "$(date -u +%Y)" -lt 2050 ]; then
        not_before=$(der_encode_tlv 17 "$(string_to_hex "$(date -u +%y%m%d%H%M%SZ)")")
    else
        not_before=$(der_encode_tlv 18 "$(string_to_hex "$(date -u +%Y%m%d%H%M%SZ)")")
    fi
    der_encode_sequence "$not_before" "$(der_encode_tlv 18 "$(string_to_hex 99991231235959Z)")"
}

# DER extensions for the two certificate roles. Policy OIDs have no qualifiers
# and are non-critical; Fixed and Restricted must never appear together.
build_certificate_extensions() {
    local role=$1 spki_file=$2 ca_key_id=$3 hw_serial=$4 perm_id=$5 dmtf_identity=$6
    local general_names hardware_name permanent_name policies policy policy_seq="" exts
    hardware_name=$(der_encode_sequence "$(der_encode_oid "$OID_TCG_TPM20")" "$(der_encode_octet_string "$hw_serial")")
    permanent_name=$(der_encode_sequence "$(der_encode_utf8_string "$perm_id")" "$(der_encode_oid "$OID_TCG_PERM_ID_SHA256")")
    general_names=$(der_encode_other_name "$OID_HW_MODULE_NAME" "$hardware_name")
    general_names=$general_names$(der_encode_other_name "$OID_PERMANENT_ID" "$permanent_name")
    if [ -n "$dmtf_identity" ]; then
        general_names=$general_names$(der_encode_other_name "$OID_DMTF_DEVICE_INFO" "$(der_encode_utf8_string "$dmtf_identity")")
    fi
    if [ "$role" = iak ]; then
        policies="$OID_TCG_VERIFIED_TPM_RESIDENCY $OID_TCG_VERIFIED_TPM_RESTRICTED"
    else
        policies="$OID_TCG_VERIFIED_TPM_RESIDENCY $OID_TCG_VERIFIED_TPM_FIXED $OID_TCG_INTENDED_USE_DEVID"
    fi
    for policy in $policies; do
        policy_seq=$policy_seq$(der_encode_sequence "$(der_encode_oid "$policy")")
    done
    exts=$(der_encode_extension "$OID_BASIC_CONSTRAINTS" "$(der_encode_sequence)" critical)
    exts=$exts$(der_encode_extension "$OID_KEY_USAGE" "$(der_encode_bit_string 80 7)" critical) # digitalSignature only
    exts=$exts$(der_encode_extension "$OID_SAN" "$(der_encode_sequence "$general_names")")
    exts=$exts$(der_encode_extension "$OID_CERT_POLICIES" "$(der_encode_sequence "$policy_seq")")
    exts=$exts$(der_encode_extension "$OID_SKI" "$(der_encode_octet_string "$(hash_hex_data sha1 "$(read_spki_public_key_hex "$spki_file")")")")
    exts=$exts$(der_encode_extension "$OID_AKI" "$(der_encode_sequence "$(der_encode_tlv 80 "$ca_key_id")")")
    if [ "$role" = idevid ]; then
        exts=$exts$(der_encode_extension "$OID_EXT_KEY_USAGE" "$(der_encode_sequence "$(der_encode_oid "$OID_KP_CLIENT_AUTH")" "$(der_encode_oid "$OID_DMTF_EKU_RESPONDER_AUTH")")")
    fi
    printf '%s' "$exts"
}

cmd_generate_certificate() {
    local role="" pubkey="" ek_der="" ca_cert="" ca_key="" hash=sha256 organization=SPDM-EMU
    local common_name="" device_serial="" dmtf_identity="" out="" providers=()
    local ek_cert="" tpm_vendor=""
    while [ $# -gt 0 ]; do
        case $1 in
        --role) role=$2; shift ;;
        --pubkey) pubkey=$2; shift ;;
        --ek-der) ek_der=$2; shift ;;
        --ek-cert) ek_cert=$2; shift ;;
        --tpm-vendor) tpm_vendor=$2; shift ;;
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
    validate_key_role "$role"
    for v in pubkey ek_der ca_cert ca_key common_name device_serial out; do
        [ -n "${!v}" ] || fail "cert: --${v//_/-} is required"
    done

    # The provisioning interface takes the device serial as hex. This also
    # ensures it is valid PrintableString data for X520SerialNumber.
    case "$device_serial" in
    *[!0-9a-fA-F]*) fail "--device-serial must be hexadecimal" ;;
    esac

    local tmp
    tmp=$(mktemp -d)
    trap "$(printf 'rm -rf -- %q' "$tmp")" EXIT

    # CA certificate: subject, key type and key identifier
    openssl x509 -in "$ca_cert" -outform DER -out "$tmp/ca.der"
    local tbs_offset idx ca_subject ca_type ca_key_id
    tbs_offset=$(der_list_children "$tmp/ca.der" 0 | sed -n 1p | awk '{print $1}')
    if [ "$(der_read_child_hex "$tmp/ca.der" "$tbs_offset" 0 | cut -c1-2)" = a0 ]; then idx=1; else idx=0; fi
    ca_subject=$(der_read_child_hex "$tmp/ca.der" "$tbs_offset" $((idx + 4)))
    openssl x509 -in "$ca_cert" -noout -pubkey | openssl pkey -pubin -outform DER -out "$tmp/ca_spki.der"
    case "$(openssl x509 -in "$ca_cert" -noout -text)" in
    *"Public Key Algorithm: id-ecPublicKey"*) ca_type=ec ;;
    *"Public Key Algorithm: rsaEncryption"*) ca_type=rsa ;;
    *) fail "unsupported CA key algorithm" ;;
    esac
    ca_key_id=$(openssl x509 -in "$ca_cert" -noout -ext subjectKeyIdentifier 2> /dev/null |
        sed -n '2p' | tr -d ' :\n' | tr 'A-F' 'a-f')
    if [ -z "$ca_key_id" ]; then
        # RFC 5280 4.2.1.2 method (1): SHA-1 of the subjectPublicKey BIT STRING value
        ca_key_id=$(hash_hex_data sha1 "$(read_spki_public_key_hex "$tmp/ca_spki.der")")
    fi

    # Subject key and EK
    openssl pkey -pubin -in "$pubkey" -outform DER -out "$tmp/spki.der"
    local spki sig_alg
    spki=$(read_file_hex "$tmp/spki.der")
    if [ "$ca_type" = rsa ]; then
        sig_alg=$(der_encode_sequence "$(der_encode_oid "$(get_signature_algorithm_oid "$ca_type" "$hash")")" 0500)
    else
        sig_alg=$(der_encode_sequence "$(der_encode_oid "$(get_signature_algorithm_oid "$ca_type" "$hash")")")
    fi

    # serialNumber: unique, non-negative, 64..160 bits (Table 26): 127 random bits, bit 126 set
    local serial
    serial=$(openssl rand -hex 16)
    serial=$(printf '%02x' $(((16#${serial:0:2} & 0x7f) | 0x40)))${serial:2}

    local validity subject identifiers hw_serial perm_id exts
    validity=$(build_certificate_validity)
    subject=$(der_encode_sequence "$(der_encode_name_attribute "$OID_ORGANIZATION" "$organization")" \
        "$(der_encode_name_attribute "$OID_CN" "$common_name")" \
        "$(der_encode_name_attribute "$OID_SERIAL_NUMBER" "$device_serial" 13)")
    identifiers=$(build_tpm_certificate_identifiers "$ek_der" "$ek_cert" "$tpm_vendor")
    read -r hw_serial perm_id <<< "$identifiers"
    exts=$(build_certificate_extensions "$role" "$tmp/spki.der" "$ca_key_id" "$hw_serial" "$perm_id" "$dmtf_identity")

    local tbs signature
    tbs=$(der_encode_sequence "$(der_encode_tlv a0 "$(der_encode_tlv 02 02)")" "$(der_encode_tlv 02 "$serial")" "$sig_alg" "$ca_subject" \
        "$validity" "$subject" "$spki" "$(der_encode_tlv a3 "$(der_encode_sequence "$exts")")")
    hex_to_binary "$tbs" > "$tmp/tbs.der"
    openssl dgst "-$hash" "${providers[@]}" -sign "$ca_key" -out "$tmp/tbs.sig" "$tmp/tbs.der"
    signature=$(read_file_hex "$tmp/tbs.sig")

    hex_to_binary "$(der_encode_sequence "$tbs" "$sig_alg" "$(der_encode_bit_string "$signature")")" > "$out"
    echo "$role certificate: serial 0x${serial}, notAfter 99991231235959Z, hwSerialNum $hw_serial"
}

# ---------------------------------------------------------------- enroll-check

# read_tpm_public_area_hex FILE: TPMT_PUBLIC hex of a TPM2B_PUBLIC file
read_tpm_public_area_hex() {
    local hex
    hex=$(read_file_hex "$1")
    [ $(($(read_u16_be "$hex" 0) + 2)) -eq "$(hex_byte_length "$hex")" ] || fail "$1: TPM2B_PUBLIC size mismatch"
    printf '%s' "${hex:4}"
}

# Check the supported H-1/H-2/H-3 public parameters. The TPM replaces the
# template's unique string with the generated public key, so only the parameter
# prefix is checked here; setup-tpm.sh supplies the required unique input.
validate_key_public_parameters() {
    local label=$1 role=$2 pub=$3 name_alg=$4 offset=$5 type expected
    type=$(hex_slice "$pub" 0 2)
    case "$type:$name_alg:$role" in
    0001:000b:idevid) expected=00100010080000000000 ;; # NULL symmetric/scheme, RSA2048, exponent 0
    0001:000b:iak) expected=00100016000b080000000000 ;; # NULL symmetric, PSS-SHA256, RSA2048
    0023:000b:*) expected=00100018000b00030010 ;; # NULL symmetric, ECDSA-SHA256, P256, NULL KDF
    0023:000c:*) expected=00100018000c00040010 ;; # NULL symmetric, ECDSA-SHA384, P384, NULL KDF
    *) fail "$label does not use a supported TCG template (H-1, H-2 or H-3)" ;;
    esac
    [ "$(hex_slice "$pub" "$offset" "$(hex_byte_length "$expected")")" = "$expected" ] ||
        fail "$label public parameters do not match the TCG template"
}

# Check all H-0 attributes and PolicyIDevIDKey, then the algorithm-specific
# parameters. Print the Name of the checked public area for the Certify proof.
validate_key_template() {
    local label=$1 role=$2 pub=$3 name_alg hash attributes policy_size auth_policy required
    name_alg=$(hex_slice "$pub" 2 2)
    hash=$(get_tpm_hash_algorithm_name "$name_alg")
    attributes=$(read_u32_be "$pub" 4)
    policy_size=$(read_u16_be "$pub" 8)
    auth_policy=$(hex_slice "$pub" 10 "$policy_size")
    required=$((FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | ADMIN_WITH_POLICY | SIGN))
    if [ "$role" = iak ]; then
        required=$((required | RESTRICTED))
    fi
    [ "$attributes" -eq "$required" ] ||
        fail "$label attributes $(printf '0x%08x' "$attributes") do not match template H-0"
    compute_key_policy_digests "$role" "$hash"
    [ "$auth_policy" = "$P_KEY" ] || fail "$label authPolicy is not PolicyIDevIDKey"
    validate_key_public_parameters "$label" "$role" "$pub" "$name_alg" $((10 + policy_size))
    printf '%s%s' "$name_alg" "$(hash_hex_data "$hash" "$pub")"
}

# The caller first authenticates the IAK Name through EK credential activation
# (setup-tpm.sh does this). This step binds the supplied key to that public area
# and verifies its TPM2_Certify proof for the IDevID.
cmd_verify_enrollment() {
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
    tpm2_print -t TPM2B_PUBLIC "$iak_public" > /dev/null
    tpm2_print -t TPM2B_PUBLIC "$idevid_public" > /dev/null
    iak_area=$(read_tpm_public_area_hex "$iak_public")
    validate_key_template IAK iak "$iak_area" > /dev/null
    # Bind the signature verification key to the public area whose TPM attributes
    # and policy were checked. A separately supplied software key is not an IAK.
    expected_spki=$(tpm2_print -t TPM2B_PUBLIC -f pem "$iak_public" |
        openssl pkey -pubin -outform DER | binary_to_hex)
    supplied_spki=$(openssl pkey -pubin -in "$iak_pem" -outform DER | binary_to_hex)
    [ "$expected_spki" = "$supplied_spki" ] || fail "IAK PEM does not match TPM public area"
    if [ "$(hex_slice "$iak_area" 0 2)" = 0001 ]; then
        verify_options=(-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest)
    fi
    idevid_name=$(validate_key_template IDevID idevid "$(read_tpm_public_area_hex "$idevid_public")")

    # TPMS_ATTEST: magic, type, qualifiedSigner, extraData, clockInfo, firmwareVersion,
    # TPMS_CERTIFY_INFO {name, qualifiedName}
    att=$(read_file_hex "$attest")
    [ "$(read_u32_be "$att" 0)" -eq $TPM_GENERATED_VALUE ] && [ "$(read_u16_be "$att" 4)" -eq $TPM_ST_ATTEST_CERTIFY ] ||
        fail "not a TPM-generated certify attestation"
    off=6
    off=$((off + 2 + $(read_u16_be "$att" $off))) # qualifiedSigner
    off=$((off + 2 + $(read_u16_be "$att" $off))) # extraData
    off=$((off + 8 + 4 + 4 + 1 + 8))           # clockInfo, firmwareVersion
    size=$(read_u16_be "$att" $off)
    certified_name=$(hex_slice "$att" $((off + 2)) "$size")
    off=$((off + 2 + size))
    off=$((off + 2 + $(read_u16_be "$att" $off))) # qualifiedName
    [ $off -eq "$(hex_byte_length "$att")" ] || fail "trailing bytes in TPMS_ATTEST"
    [ "$certified_name" = "$idevid_name" ] || fail "certified Name != Name(IDevID public area)"
    openssl dgst "-$hash" "${verify_options[@]}" -verify "$iak_pem" -signature "$signature" "$attest" > /dev/null 2>&1 ||
        fail "certify signature does not verify with the IAK"
    echo "CA enrollment check passed: IDevID and IAK follow the TCG templates and are in the same TPM"
}

print_usage() {
    sed -n '7,19p' "$0" | sed 's/^# \{0,1\}//'
    echo "usage: $0 {policy|unique|cert|enroll-check} [options]"
}

[ $# -ge 1 ] || { print_usage >&2; exit 1; }
cmd=$1
shift
case $cmd in
policy) cmd_generate_policy "$@" ;;
unique) cmd_generate_unique_field "$@" ;;
cert) cmd_generate_certificate "$@" ;;
enroll-check) cmd_verify_enrollment "$@" ;;
-h | --help) print_usage ;;
*) print_usage >&2; exit 1 ;;
esac
