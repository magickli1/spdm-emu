/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "tpm_quote_verify.h"
#include "internal/libspdm_lib_config.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP && LIBSPDM_TPM_SUPPORT

#include "library/spdm_crypt_lib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_crypt_ext_lib.h"
#include "library/spdm_tpm_pcr.h"
#include "internal/libspdm_common_lib.h"
#include "hal/library/cryptlib.h"
#include "industry_standard/spdm.h"
#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"
#include <stdlib.h>

#ifdef LIBSPDM_MAX_CERT_CHAIN_SIZE
#define SPDM_TPM_PEER_CERT_CHAIN_MAX_SIZE LIBSPDM_MAX_CERT_CHAIN_SIZE
#else
#define SPDM_TPM_PEER_CERT_CHAIN_MAX_SIZE SPDM_MAX_CERTIFICATE_CHAIN_SIZE
#endif

/* TPM identity of each peer slot leaf certificate, recorded from GET_CERTIFICATE: the
 * SubjectAltName hardwareModuleName (identifies the TPM, TCG DevID sec. 8.1) and whether the
 * certificate asserts tcg-cap-verifiedTPMRestricted. The CA verified at enrollment that the
 * IDevID and the IAK are in that TPM; the requester trusts the CA. */
typedef struct {
    bool valid;
    uint8_t hw_module_name[LIBSPDM_TPM_HW_MODULE_NAME_MAX_SIZE];
    size_t hw_module_name_size;
    bool verified_tpm_restricted;
} spdm_tpm_peer_identity_t;

static spdm_tpm_peer_identity_t m_spdm_tpm_peer_identity[SPDM_MAX_SLOT_COUNT];

static bool spdm_get_leaf_tpm_identity(uint32_t base_hash_algo, const uint8_t *cert_chain,
                                       size_t cert_chain_size,
                                       spdm_tpm_peer_identity_t *identity)
{
    size_t header_size;
    const uint8_t *leaf_cert;
    size_t leaf_cert_size;

    header_size = sizeof(spdm_cert_chain_t) + libspdm_get_hash_size(base_hash_algo);
    if (cert_chain_size <= header_size) {
        return false;
    }
    if (!libspdm_x509_get_cert_from_cert_chain(cert_chain + header_size,
                                               cert_chain_size - header_size, -1,
                                               &leaf_cert, &leaf_cert_size)) {
        return false;
    }
    identity->hw_module_name_size = sizeof(identity->hw_module_name);
    return libspdm_tpm_get_cert_device_identity(leaf_cert, leaf_cert_size,
                                                identity->hw_module_name,
                                                &identity->hw_module_name_size,
                                                &identity->verified_tpm_restricted);
}

static bool spdm_fetch_peer_identity(void *spdm_context, const uint32_t *session_id,
                                     uint8_t slot_id, uint32_t base_hash_algo)
{
    libspdm_return_t status;
    uint8_t *cert_chain;
    size_t cert_chain_size;
    spdm_tpm_peer_identity_t *identity;
    bool result;

    if (slot_id >= SPDM_MAX_SLOT_COUNT) {
        return false;
    }
    identity = &m_spdm_tpm_peer_identity[slot_id];
    if (identity->valid) {
        return true;
    }

    cert_chain = malloc(SPDM_TPM_PEER_CERT_CHAIN_MAX_SIZE);
    if (cert_chain == NULL) {
        return false;
    }
    cert_chain_size = SPDM_TPM_PEER_CERT_CHAIN_MAX_SIZE;
    status = libspdm_get_certificate(spdm_context, session_id, slot_id, &cert_chain_size,
                                     cert_chain);
    /* The identity binding trusts the CA that issued the IDevID and IAK certificates, so the
     * chain must also verify against a provisioned root. libspdm reports a chain that is
     * well formed but not issued by a trusted root as LIBSPDM_STATUS_VERIF_NO_AUTHORITY,
     * which is only a warning; reject it here. */
    result = LIBSPDM_STATUS_IS_SUCCESS(status);
    if (status == LIBSPDM_STATUS_VERIF_NO_AUTHORITY) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "slot %d certificate chain is not issued by a trusted root\n", slot_id));
    } else if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "GET_CERTIFICATE slot %d failed - 0x%x\n",
                       slot_id, (uint32_t)status));
    } else {
        result = spdm_get_leaf_tpm_identity(base_hash_algo, cert_chain, cert_chain_size,
                                            identity);
        if (!result) {
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                           "slot %d leaf certificate has no TPM 2.0 hardwareModuleName\n",
                           slot_id));
        }
        identity->valid = result;
    }
    free(cert_chain);
    return result;
}

bool spdm_tpm_quote_prepare_peer_identity(void *spdm_context, const uint32_t *session_id,
                                          uint8_t signing_slot_id)
{
    libspdm_data_parameter_t parameter;
    libspdm_return_t status;
    uint32_t base_hash_algo;
    size_t data_size;

    if ((signing_slot_id >= SPDM_MAX_SLOT_COUNT) ||
        (signing_slot_id == SPDM_TPM_IAK_CERT_SLOT_ID)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "TPM Quote needs a certificate signing slot other than IAK slot %d\n",
                       SPDM_TPM_IAK_CERT_SLOT_ID));
        return false;
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(base_hash_algo);
    base_hash_algo = 0;
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                              &base_hash_algo, &data_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    if (!spdm_fetch_peer_identity(spdm_context, session_id, SPDM_TPM_IAK_CERT_SLOT_ID,
                                  base_hash_algo)) {
        return false;
    }
    return spdm_fetch_peer_identity(spdm_context, session_id, signing_slot_id, base_hash_algo);
}

void spdm_tpm_quote_reset_peer_identity(void)
{
    libspdm_zero_mem(m_spdm_tpm_peer_identity, sizeof(m_spdm_tpm_peer_identity));
}

static bool spdm_verify_iak_identity_binding(uint8_t signing_slot_id)
{
    const spdm_tpm_peer_identity_t *device_identity;
    const spdm_tpm_peer_identity_t *iak_identity;

    if (signing_slot_id >= SPDM_MAX_SLOT_COUNT) {
        return false;
    }
    device_identity = &m_spdm_tpm_peer_identity[signing_slot_id];
    iak_identity = &m_spdm_tpm_peer_identity[SPDM_TPM_IAK_CERT_SLOT_ID];
    if (!device_identity->valid || !iak_identity->valid) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "IAK / device identity not recorded\n"));
        return false;
    }
    /* TCG DevID sec. 8.2: a relying party evaluating TPM internal data MUST check for
     * tcg-cap-verifiedTPMRestricted in the IAK certificate. */
    if (!iak_identity->verified_tpm_restricted) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "IAK certificate lacks tcg-cap-verifiedTPMRestricted\n"));
        return false;
    }
    /* Same hardwareModuleName: the IDevID that signs MEASUREMENTS and the IAK that signs
     * the Quote belong to the same TPM. */
    if ((device_identity->hw_module_name_size != iak_identity->hw_module_name_size) ||
        !libspdm_consttime_is_mem_equal(device_identity->hw_module_name,
                                        iak_identity->hw_module_name,
                                        iak_identity->hw_module_name_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "IAK hardwareModuleName != slot %d device hardwareModuleName\n",
                       signing_slot_id));
        return false;
    }
    return true;
}

static void *spdm_get_iak_public_key(void *spdm_context, uint32_t base_hash_algo,
                                     uint32_t base_asym_algo, bool *owned)
{
    void *iak_public_key;

    *owned = false;
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    {
        const uint8_t *iak_cert_chain;
        size_t iak_cert_chain_size;

        libspdm_get_peer_cert_chain_buffer(spdm_context, SPDM_TPM_IAK_CERT_SLOT_ID,
                                           (const void **)&iak_cert_chain,
                                           &iak_cert_chain_size);
        if (iak_cert_chain_size == 0) {
            return NULL;
        }
        if (!libspdm_get_leaf_cert_public_key_from_cert_chain(base_hash_algo, base_asym_algo,
                                                              (uint8_t *)iak_cert_chain,
                                                              iak_cert_chain_size,
                                                              &iak_public_key)) {
            return NULL;
        }
        *owned = true;
        return iak_public_key;
    }
#else
    libspdm_context_t *context;

    (void)base_hash_algo;
    (void)base_asym_algo;
    context = (libspdm_context_t *)spdm_context;
    iak_public_key =
        context->connection_info.peer_used_cert_chain[SPDM_TPM_IAK_CERT_SLOT_ID]
        .leaf_cert_public_key;
    return iak_public_key;
#endif
}

bool spdm_verify_tpm_quote_measurement(
    void *spdm_context,
    uint8_t signing_slot_id,
    uint32_t measurement_hash_algo,
    uint32_t base_hash_algo,
    uint32_t base_asym_algo,
    const uint8_t *measurement_record,
    uint32_t measurement_record_length,
    const uint8_t *request_nonce,
    const uint8_t *opaque_data,
    size_t opaque_data_size)
{
    uint8_t iak_slot_id;
    const void *quote;
    size_t quote_size;
    void *iak_public_key;
    bool iak_public_key_owned;
    bool result;

    if (opaque_data_size == 0) {
        libspdm_data_parameter_t parameter;
        uint8_t slot_mask;
        size_t data_size;
        size_t offset;
        size_t block_size;

        /* Unsigned measurements and peers outside the TPM IAK profile need no Quote. */
        if (request_nonce == NULL) {
            return true;
        }
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
        data_size = sizeof(slot_mask);
        if ((spdm_context == NULL) ||
            !LIBSPDM_STATUS_IS_SUCCESS(libspdm_get_data(
                                           spdm_context, LIBSPDM_DATA_PEER_PROVISIONED_SLOT_MASK,
                                           &parameter,
                                           &slot_mask, &data_size))) {
            return false;
        }
        if ((slot_mask & (1u << SPDM_TPM_IAK_CERT_SLOT_ID)) == 0) {
            return true;
        }
        /* An empty record contains no PCR blocks requiring a Quote. */
        if (measurement_record_length == 0) {
            return true;
        }
        if (measurement_record == NULL) {
            return false;
        }
        /* Parse SPDM block boundaries only; TPM evidence parsing stays in libspdm. */
        for (offset = 0; offset < measurement_record_length; offset += block_size) {
            if (measurement_record_length - offset <
                sizeof(spdm_measurement_block_common_header_t)) {
                return false;
            }
            block_size = sizeof(spdm_measurement_block_common_header_t) +
                         libspdm_read_uint16(measurement_record + offset + 2);
            if (block_size > measurement_record_length - offset) {
                return false;
            }
            if (libspdm_tpm_measurement_pcr_index(measurement_record[offset]) <
                LIBSPDM_TPM_PCR_COUNT) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "signed PCR measurement has no TPM Quote\n"));
                return false;
            }
        }
        return true;
    }
    if (opaque_data == NULL) {
        return false;
    }
    if (!libspdm_tpm_quote_opaque_decode(opaque_data, opaque_data_size, &iak_slot_id,
                                         &quote, &quote_size)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "malformed TPM Quote opaque element\n"));
        return false;
    }

    /* The Quote names its IAK slot; it must be the configured IAK slot, which is never the
     * slot that signed MEASUREMENTS. */
    if ((iak_slot_id != SPDM_TPM_IAK_CERT_SLOT_ID) || (iak_slot_id == signing_slot_id)) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "TPM Quote iak_slot_id %d invalid (IAK slot %d, signing slot %d)\n",
                       iak_slot_id, SPDM_TPM_IAK_CERT_SLOT_ID, signing_slot_id));
        return false;
    }
    if (request_nonce == NULL) {
        return false;
    }

    if (!spdm_verify_iak_identity_binding(signing_slot_id)) {
        return false;
    }

    iak_public_key = spdm_get_iak_public_key(spdm_context, base_hash_algo, base_asym_algo,
                                             &iak_public_key_owned);
    if (iak_public_key == NULL) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR, "IAK public key (slot %d) not provisioned\n",
                       SPDM_TPM_IAK_CERT_SLOT_ID));
        return false;
    }
    /* The Quote must attest exactly the PCRs reported in measurement_record. */
    result = libspdm_tpm_verify_quote_measurement_record(
        iak_public_key, quote, quote_size, request_nonce, SPDM_NONCE_SIZE,
        measurement_hash_algo, measurement_record, measurement_record_length);
    if (iak_public_key_owned) {
        libspdm_asym_free(base_asym_algo, iak_public_key);
    }
    if (!result) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
                       "TPM Quote does not attest the measurement record PCRs\n"));
    }
    return result;
}

libspdm_return_t spdm_tpm_verify_signed_measurement(
    void *spdm_context, const uint32_t *session_id, uint8_t signing_slot_id,
    const uint8_t *measurement_record, uint32_t measurement_record_length,
    const uint8_t *request_nonce, const uint8_t *opaque_data, size_t opaque_data_size)
{
    libspdm_data_parameter_t parameter;
    libspdm_return_t status;
    uint32_t measurement_hash_algo;
    uint32_t base_hash_algo;
    uint32_t base_asym_algo;
    size_t data_size;

    if ((opaque_data_size != 0) &&
        !spdm_tpm_quote_prepare_peer_identity(spdm_context, session_id, signing_slot_id)) {
        return LIBSPDM_STATUS_INVALID_STATE_PEER;
    }
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(measurement_hash_algo);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                              &measurement_hash_algo, &data_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    data_size = sizeof(base_hash_algo);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                              &base_hash_algo, &data_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    data_size = sizeof(base_asym_algo);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                              &base_asym_algo, &data_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    if (!spdm_verify_tpm_quote_measurement(spdm_context, signing_slot_id,
                                           measurement_hash_algo, base_hash_algo, base_asym_algo,
                                           measurement_record, measurement_record_length,
                                           request_nonce, opaque_data, opaque_data_size)) {
        return LIBSPDM_STATUS_INVALID_STATE_PEER;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP && LIBSPDM_TPM_SUPPORT */
