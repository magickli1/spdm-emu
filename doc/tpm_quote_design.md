# TPM Quote Measurement Evidence Design

## 1. Purpose and Scope

This document is the deep design companion for TPM Quote measurement evidence. For the
primary TPM user guide (flows, build, provisioning, validation, and security
considerations), see [TPM Support](tpm.md).

This design binds TPM attestation evidence to an SPDM `MEASUREMENTS` response. The
responder returns the normal SPDM measurement record and signature, plus a TPM Quote in
the response OpaqueData field. The Quote binds:

- the exact requester-generated SPDM nonce;
- the PCR selection represented by the returned measurement blocks;
- the PCR values contained in those blocks; and
- a separately provisioned Initial Attestation Key (IAK).

The design does not replace normal SPDM authentication. The existing TPM-backed responder
identity key continues to sign `CHALLENGE_AUTH`, `MEASUREMENTS`, and `KEY_EXCHANGE_RSP`
transcripts. The restricted IAK is used only by `TPM2_Quote`.

The implementation spans the `spdm-emu` integration layer and the `libspdm` submodule. The
protocol flow is shown in [tpm-in-flow.png](assets/tpm-in-flow.png); its editable source
is [tpm-in-flow.puml](assets/tpm-in-flow.puml).

## 2. Design Goals

- Preserve the existing libspdm measurement OpaqueData API and ABI.
- Provide a generic extended callback usable by TPM, TEE, DICE, or vendor-defined evidence
  providers.
- Bind evidence to both freshness data and the exact returned measurements.
- Keep the IAK independent from the SPDM identity signing key.
- Support a TPM containing only the IAK leaf certificate.
- Make requester trust configuration independent of TPM NV capacity.
- Fail closed on malformed evidence, certificate mismatch, or binding failure.

## 3. Component Architecture

| Component                                    | Responsibility                                                                                                                                                   |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `libspdm_rsp_measurements.c`                 | Collects measurements, invokes the extended OpaqueData callback, and constructs the signed SPDM response.                                                        |
| `spdm_device_secret_lib_tpm/meas.c`          | Refreshes PCR measurements, creates the Quote, and serializes the TCG OpaqueData element.                                                                        |
| `cryptlib_openssl/tpm/tpm.c`                 | Calls `TPM2_Quote`, marshals TPM structures, and verifies Quote contents and signature.                                                                          |
| `spdm_device_secret_lib_tpm/read_pub_cert.c` | Reads the IAK NV chain except root (leaf only, or intermediates then leaf) and builds `spdm_cert_chain_t` (RootHash from separate root NV + entire IAK NV blob). |
| `spdm_device_secret_lib_tpm/sign.c`          | Signs normal SPDM transcripts with the identity key and explicitly rejects the reserved IAK KeyPairID.                                                           |
| `spdm_responder_spdm.c`                      | Publishes the IAK slot and restricts its advertised key usage.                                                                                                   |
| `spdm_requester_measurement.c`               | Parses evidence, validates IAK trust and slot binding, reconstructs PCR input, and verifies the Quote.                                                           |

## 4. Key and Certificate Model

### 4.1 Key separation

The sample uses the following logical roles:

| Role                   |                                          Default value | Permitted operation                                        |
| ---------------------- | -----------------------------------------------------: | ---------------------------------------------------------- |
| Responder identity key |                   TPM handle `0x81000021`, SPDM slot 0 | SPDM transcript signing and the existing key-exchange path |
| IAK                    | TPM handle `0x81020001`, SPDM slot 1, KeyPairID `0xFE` | `TPM2_Quote` only                                          |

KeyPairID `0xFE` is a reserved sample ID outside the contiguous identity
KeyPairID space so transcript signing can reject the IAK without colliding with
ordinary multi-key slot IDs.

The IAK is provisioned as a restricted signing key. Slot 1 advertises only
`SPDM_KEY_USAGE_BIT_MASK_STANDARDS_KEY_USE`; it omits challenge, measurement,
key-exchange, and endpoint-info signing usages. `libspdm_responder_data_sign()` also
rejects KeyPairID `0xFE`, providing a second enforcement layer.

The responder must use an identity slot, normally slot 0, in the `GET_MEASUREMENTS`
request for the SPDM transcript signature. Slot 1 and slot `0xF` are rejected by the Quote
OpaqueData callback.

### 4.2 Persistent provisioning

The IAK handle follows *TPM 2.0 Keys for Device Identity and Attestation*:

- IAK persistent handle: `0x81020001`
- IAK certificate NV range index 0: `0x01C90100`

`script/setup-tpm.sh` provisions an ECC P-256 restricted IAK, creates its X.509 leaf
certificate, persists the key, and writes the exact DER leaf bytes to NV.

IAK NV may store a TCG-style certificate chain except the root: leaf only, or intermediate
CA(s) then leaf. The sample writes leaf-only to minimize NV use and keep the provisioning
script simple; products may provision the fuller chain-except-root blob. The SPDM
`CERTIFICATE` for the IAK slot is `spdm_cert_chain_t` with RootHash plus that entire NV
blob. The responder reads the IAK root (or an equivalent protected root-hash source) from
a separate NV index to populate `RootHash`. The sample uses
`LIBSPDM_TPM_IAK_ROOT_CERT_INDEX` (`0x01500000`); the root is not stored in IAK NV and is
not sent in the slot certificate portion.

### 4.3 Requester trust policy

The requester always requires `LIBSPDM_TPM_IAK_ROOT_CERT_FILE`. Optional
`LIBSPDM_TPM_IAK_CERT_CHAIN_FILE` (DER concat: root, optional intermediates, leaf)
supplies OOB intermediates when they are absent from the SPDM slot; it is not needed when
the slot chain (root-excluded) already verifies to that root (sample leaf-only path).
Quote verification binds the cached IAK slot leaf to that root (see §4.2 for CertChain
shape). When the OOB chain file is set, the slot chain is not path-validated against that
file: only RootHash vs configured root and leaf byte-match are required.

GET_CERTIFICATE for the IAK slot still runs libspdm's peer integrity check and may warn
with `LIBSPDM_STATUS_VERIF_NO_AUTHORITY` yet cache the buffer (e.g. intermediate-signed
leaf-only NV). Full IAK policy—RootHash match, optional OOB chain validation, slot-chain
or leaf bind, and Quote signature under `LIBSPDM_TPM_IAK_*` algorithms—runs in
`verify_tpm_quote_evidence` (numbered steps in §8). Neither an untrusted external chain
nor an attacker-controlled SPDM IAK slot is sufficient by itself.

Two trust anchors can diverge. Quote policy hashes `LIBSPDM_TPM_IAK_ROOT_CERT_FILE` and
compares it to the SPDM IAK slot `RootHash`. GET_CERTIFICATE peer-authority roots for
`DEVICE=tpm` come from TPM NV (`LIBSPDM_TPM_IAK_ROOT_CERT_INDEX` and related peer-root
loads). If the file root and NV root differ, Quote verification fails with RootHash
mismatch even when NV-backed peer checks succeed.

Quote verification fails closed when the cached IAK `CERTIFICATE` is empty; it does not
re-issue GET_CERTIFICATE. Typical empty-cache triggers include: GET_CERTIFICATE never
completed for the IAK slot; `EXE_CONNECTION_CERT` off; IAK absent from DIGESTS (for
example responder `get_iak_certificate` failed—including root embedded in IAK NV—so the
slot was never loaded); or a hard GET_CERTIFICATE error that left no usable cache. CI
root-in-IAK-NV rejection commonly surfaces as this empty-cache path, not as a Quote
crypto parse failure.

Canonical trust-env example:

```sh
export LIBSPDM_TPM_IAK_ROOT_CERT_FILE=/etc/spdm/iak-root.der
# Optional when the SPDM slot chain verifies to that root:
# export LIBSPDM_TPM_IAK_CERT_CHAIN_FILE=/etc/spdm/iak-chain.der
```

## 5. Generic Extended OpaqueData Interface

`libspdm_measurement_opaque_data()` remains unchanged for existing HAL implementations. A
build may enable the new callback with `LIBSPDM_ENABLE_MEASUREMENT_OPAQUE_DATA_EX`:

```c
bool libspdm_measurement_opaque_data_ex(
    void *spdm_context,
    const uint32_t *session_id,
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_index,
    uint8_t request_attribute,
    const uint8_t *requester_nonce,
    uint8_t slot_id_param,
    size_t request_context_size,
    const void *request_context,
    void *measurements,
    uint8_t measurements_count,
    size_t measurements_size,
    void *opaque_data,
    size_t *opaque_data_size);
```

Compared with the original callback, the extended form receives the requester nonce,
signing slot, and collected measurement record. An implementation may refresh the record
to close the time-of-check/time-of-use window, but it must not change `measurements_count`
or `measurements_size`.

TPM support enables the generic callback by default. Non-TPM platforms may enable it
independently and provide another evidence format.

If the callback fails, the responder resets the measurement transcript and returns
`SPDM_ERROR_CODE_UNSPECIFIED`; it never sends unbound evidence.

## 6. Responder Processing

### 6.1 Eligibility

The OpaqueData callback emits Quote evidence only when all of the following are true:

- SPDM version is 1.2 or later;
- `GenerateSignature` is set;
- a non-NULL requester nonce pointer is present; and
- the operation is `ALL_MEASUREMENTS` or a single PCR-backed index in
  `1..LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER`.

Total-number queries and non-PCR indices return empty OpaqueData. A signed non-PCR block
may still carry the normal SPDM L1 transcript signature. The exact 32-byte nonce length
(`SPDM_NONCE_SIZE`) is enforced inside `libspdm_tpm_quote()` / `libspdm_tpm_verify_quote()`,
not in the OpaqueData eligibility gate above.

### 6.2 Measurement-to-PCR binding

For `ALL_MEASUREMENTS`, the PCR mask selects every configured PCR measurement index. For a
single measurement, it selects `index - 1`.

Before quoting, the implementation recollects the requested measurement record. It
verifies that the block count and serialized size are unchanged. Each selected block must:

- use a valid PCR-backed index;
- contain a digest rather than a raw bit stream;
- have the negotiated measurement hash size; and
- fit in the bounded PCR data buffer.

Selected digests are concatenated in measurement-record order. The Quote `pcrDigest` is
the negotiated PCR-bank hash over this concatenation. Quote creation is retried at most
three times so that PCR changes during collection can converge on a self-consistent record
and Quote.

### 6.3 TPM Quote creation

`libspdm_tpm_quote()`:

1. Maps the negotiated SPDM measurement hash algorithm to the TPM PCR bank.
2. Copies the requester nonce into `TPMS_ATTEST.extraData`.
3. Builds an exact 24-PCR selection from the mask.
4. calls `Esys_Quote()` with the persistent IAK;
5. checks the returned magic, attestation type, nonce, and `pcrDigest`; and
6. marshals the complete `TPM2B_ATTEST` and `TPMT_SIGNATURE`.

The sample IAK signature scheme is ECDSA with SHA-256. PCR-bank selection is not fixed to
SHA-256; the implementation maps SHA-256, SHA-384, SHA-512, SHA3 variants, and SM3-256
when supported by the TPM and crypto backend.

## 7. OpaqueData Wire Format

The evidence is one 4-byte-aligned element in an SPDM general OpaqueData table:

```text
spdm_general_opaque_data_table_header_t
spdm_svh_tcg_header_t
uint16 element_data_size
uint8  version
uint8  iak_slot_id
uint16 attest_size
uint16 signature_size
uint8  tpm2b_attest[attest_size]
uint8  tpmt_signature[signature_size]
uint8  zero_padding[0..3]
```

| Field            | Current value or rule                     |
| ---------------- | ----------------------------------------- |
| `total_elements` | Exactly 1                                 |
| Registry ID      | `SPDM_REGISTRY_ID_TCG`                    |
| Vendor ID        | `LIBSPDM_TPM_VENDOR_ID`, default `0x1014` |
| Evidence version | 1                                         |
| IAK slot         | `LIBSPDM_TPM_IAK_SLOT_ID`, default 1      |
| Attestation      | TSS2-marshaled `TPM2B_ATTEST`             |
| Signature        | TSS2-marshaled `TPMT_SIGNATURE`           |
| Padding          | Zero bytes to a 4-byte boundary           |

The vendor ID is intentionally configured at build time rather than read from
`TPM2_PT_MANUFACTURER`: the system or evidence-provider vendor may differ from the TPM
chip manufacturer, and the same software TPM may be used by multiple vendors.

## 8. Requester Verification

The requester first lets libspdm validate the normal SPDM `MEASUREMENTS` response and
transcript signature. It then performs Quote verification:

1. Require one correctly identified TCG element and the configured vendor ID.
2. Validate all lengths, version, IAK slot, and zero padding.
3. Load the configured IAK trust anchor (required). If an external chain file is set,
   validate that chain against the trust anchor (see §4.3).
4. Use the cached SPDM IAK slot `CERTIFICATE` (see §4.2) and require its `RootHash` to
   match the configured root (`LIBSPDM_TPM_IAK_ROOT_CERT_FILE`). Fail closed if that
   cache is empty; Quote verification does not re-GET_CERTIFICATE. Empty-cache triggers
   and the dual-anchor RootHash note are in §4.3. CI root-in-IAK-NV often fails here
   (slot never advertised / cert not retrieved) rather than at Quote crypto parse.
5. When a chain file is set, require its leaf to byte-match the SPDM leaf (no slot-chain
   path validation against the OOB file); otherwise verify the SPDM slot chain against
   the configured root.
6. Parse the returned DMTF measurement blocks.
7. Require PCR-backed indices to be strictly increasing and digest-sized.
8. Reconstruct the PCR mask and concatenated PCR digest input.
9. Unmarshal the TPM attestation and signature without trailing bytes.
10. Require `TPM2_GENERATED_VALUE` and `TPM2_ST_ATTEST_QUOTE`.
11. Compare `extraData` with the exact requester nonce.
12. Compare the Quote PCR bank and selection with the returned record.
13. Recompute and compare `pcrDigest`.
14. Verify the Quote signature with the SPDM IAK slot leaf public key.

Any failure returns `LIBSPDM_STATUS_VERIF_FAIL`. The IAK root is mandatory; the external
chain file is optional. The implementation does not silently fall back to trusting an
unanchored TPM-provided leaf.

## 9. Build-Time and Runtime Configuration

Important CMake settings are:

| Setting                           |      Default | Meaning                                            |
| --------------------------------- | -----------: | -------------------------------------------------- |
| `LIBSPDM_TPM_SUPPORT`             |        `OFF` | Enables the TPM backend and Quote integration      |
| `LIBSPDM_TPM_IAK_HANDLE`          | `0x81020001` | Persistent IAK handle                              |
| `LIBSPDM_TPM_IAK_SLOT_ID`         |          `1` | SPDM slot exposing the IAK chain except root       |
| `LIBSPDM_TPM_IAK_KEY_PAIR_ID`     |       `0xFE` | Reserved ID rejected by transcript signing         |
| `LIBSPDM_TPM_IAK_ROOT_CERT_INDEX` | `0x01500000` | Root certificate used to construct slot 1 RootHash |
| `LIBSPDM_TPM_VENDOR_ID`           |     `0x1014` | TCG SVH vendor identifier                          |
| `LIBSPDM_TPM_IAK_BASE_ASYM_ALGO`  |  ECDSA P-256 | IAK certificate algorithm                          |
| `LIBSPDM_TPM_IAK_BASE_HASH_ALGO`  |      SHA-256 | IAK certificate hash algorithm                     |

TPM access uses two distinct TCTI environment variables:

- `TPM2TOOLS_TCTI` — TSS2/Esys for `Esys_Quote` / PCR paths and `libspdm_tpm_read_nv`
  (responder IAK and root NV reads). With `DEVICE=tpm`, requester peer-root load from TPM
  NV also uses this TCTI. Provisioning via tpm2-tools uses the same variable.
- `TPM2OPENSSL_TCTI` — OpenSSL TPM provider (provisioning and provider-backed signing).

`libspdm_tpm_verify_quote()` is pure OpenSSL crypto over the returned blob and IAK leaf;
it needs no TCTI. If `TPM2TOOLS_TCTI` is unset, TSS falls back to its default TCTI, which
can split-brain against a separately configured `TPM2OPENSSL_TCTI` (tools/provider hit one
TPM, Esys/NV another). Export both to the same endpoint for emulator runs.

```sh
export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
```

The setup script always provisions the sample IAK as ECC P-256/SHA-256. Changing only the
CMake algorithm settings does not reprovision an existing key or certificate.

## 10. Security Properties and Failure Handling

- **Freshness:** the Quote `extraData` equals the unpredictable requester nonce.
- **Measurement integrity:** the Quote selection and `pcrDigest` must match the
  measurement blocks in the same response.
- **Key provenance:** the Quote verifies with the leaf advertised in the evidence-selected
  SPDM slot.
- **Trust anchoring:** that leaf must also terminate at an independently configured
  requester trust anchor.
- **Key separation:** IAK KeyPairID and usage flags prevent it from becoming an SPDM
  identity-signing key.
- **Strict parsing:** unexpected element counts, IDs, sizes, padding, TPM magic,
  attestation type, algorithms, PCR order, or trailing bytes are rejected.
- **Fail closed:** missing trust configuration, unsupported algorithms, unavailable TPM
  objects, buffer exhaustion, or PCR instability reject evidence. On the responder, a
  failed OpaqueData callback resets the measurement transcript and returns
  `SPDM_ERROR_CODE_UNSPECIFIED`. On the requester, libspdm may already have accepted the
  SPDM `MEASUREMENTS` response; Quote policy failure then returns
  `LIBSPDM_STATUS_VERIF_FAIL` after the fact.

The design binds PCR digest values, not event-log semantics. A relying party that needs
measured-boot interpretation must obtain and replay the appropriate event log separately.

## 11. Test Strategy

`libspdm/unit_test/test_crypt/tpm_quote_verify.c` covers:

- a valid Quote;
- wrong nonce;
- wrong PCR digest;
- invalid TPM magic;
- invalid attestation type;
- wrong signature; and
- overridden bad `pcrDigest` in the ATTEST blob.

`libspdm/unit_test/test_spdm_responder/measurements.c` verifies invocation of the extended
callback and propagation of its inputs.

The TPM CI workflow provisions `swtpm`, validates the persistent handle, restricted
attributes, NV index, DER size, certificate chain, and key match, then runs:

- positive end-to-end Quote generation and verification with an external chain;
- positive verification with root only (no `LIBSPDM_TPM_IAK_CERT_CHAIN_FILE`);
- positive multi-cert IAK NV (`intermediate||leaf`) without an external chain;
- positive OOB intermediates: NV holds an intermediate-signed leaf only, with
  `LIBSPDM_TPM_IAK_CERT_CHAIN_FILE` = `root||intermediate||leaf`;
- rejection when the IAK root is missing;
- rejection when configured root yields an SPDM IAK slot RootHash mismatch;
- rejection when IAK NV embeds the root (`root||leaf`);
- rejection of an untrusted root/chain;
- rejection when the external leaf differs from the SPDM slot leaf; and
- rejection when slot 1 is used for SPDM transcript signing.

The existing identity-key `KEY_EXCHANGE_RSP`, encapsulated requester authentication,
`FINISH`, secured messaging, key update, and session teardown remain outside the IAK path
and are unchanged by this design.

## 12. Current Limitations

- The OpaqueData payload is an implementation-defined version-1 format; peers must
  implement the same schema and configured vendor ID.
- The sample Quote signature hash follows `LIBSPDM_TPM_IAK_BASE_HASH_ALGO` (default
  SHA-256 with a P-256 IAK); the provisioning script creates only an ECC P-256 IAK.
- Only one PCR bank and PCR indices 0 through 23 are represented per Quote.
- At most one Quote evidence element is accepted.
- Certificate revocation and time-policy handling are outside this sample.
- The requester loads trust material from environment-selected files
  (`LIBSPDM_TPM_IAK_ROOT_CERT_FILE`, optional `LIBSPDM_TPM_IAK_CERT_CHAIN_FILE`).
  Those paths are a local trust boundary: whoever can write them controls Quote
  acceptance. Production integrations should bind this policy to protected platform
  configuration rather than an untrusted process environment.
- There is no Endorsement Key (EK) binding or TPM endorsement hierarchy attestation
  in this sample. Quote evidence is bound to the provisioned IAK leaf and configured
  IAK root only; EK-certified IAK provenance is out of scope.
- Quote evidence requires SPDM 1.2 or later and negotiated OpaqueData support.
