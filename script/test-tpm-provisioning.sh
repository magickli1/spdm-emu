#!/bin/sh -eu

IAK_KEY=0x81020001
IAK_CERT=0x01C90100
# tpm2_getcap may print 0x01c90100 or 0x1c90100; match either form.
IAK_CERT_GREP='0x0*1[cC]90100'

required_files="iak_cert.der iak_cert.pem root_ca_cert.pem"
for file in ${required_files}; do
    if [ ! -f "${file}" ]; then
        echo "Missing provisioning artifact: ${file}" >&2
        exit 1
    fi
done

if ! tpm2_getcap handles-persistent | grep -qi "${IAK_KEY}"; then
    echo "IAK is not persisted at ${IAK_KEY}" >&2
    exit 1
fi

if ! tpm2_getcap handles-nv-index | grep -Eiq "${IAK_CERT_GREP}"; then
    echo "IAK certificate is not stored at ${IAK_CERT}" >&2
    exit 1
fi

tmp_dir="$(mktemp -d /tmp/spdm-tpm-provisioning.XXXXXXXXXX)"
trap 'rm -rf "${tmp_dir}"' EXIT INT TERM

tpm2_readpublic -c "${IAK_KEY}" -f pem \
    -o "${tmp_dir}/iak-tpm-public.pem" \
    > "${tmp_dir}/iak-public.yaml"

attributes="$(sed -n '/^attributes:/,/^[^ ]/p' \
    "${tmp_dir}/iak-public.yaml")"
for attribute in fixedtpm fixedparent restricted sign; do
    if ! printf '%s\n' "${attributes}" | grep -qi "${attribute}"; then
        echo "IAK is missing required attribute: ${attribute}" >&2
        exit 1
    fi
done
if printf '%s\n' "${attributes}" | grep -qi decrypt; then
    echo "IAK must not have the decrypt attribute" >&2
    exit 1
fi

# Sample provisioning writes leaf-only IAK NV. Responder also accepts a
# TCG-style concatenated chain-except-root; this check keeps the sample path.
tpm2_nvread "${IAK_CERT}" -C o -o "${tmp_dir}/iak-cert-nv.der"
cmp "${tmp_dir}/iak-cert-nv.der" iak_cert.der
openssl x509 -inform DER -in "${tmp_dir}/iak-cert-nv.der" -noout
openssl verify -CAfile root_ca_cert.pem iak_cert.pem

openssl x509 -inform DER -in iak_cert.der -pubkey -noout |
    openssl pkey -pubin -outform DER -out "${tmp_dir}/iak-cert-public.der"
openssl pkey -pubin -in "${tmp_dir}/iak-tpm-public.pem" -outform DER \
    -out "${tmp_dir}/iak-tpm-public.der"
cmp "${tmp_dir}/iak-cert-public.der" "${tmp_dir}/iak-tpm-public.der"

echo "TPM IAK provisioning verification - PASS"
