/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_requester_emu.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP

extern void *m_spdm_context;

#define LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE 0x1000

#if LIBSPDM_TPM_SUPPORT
#define SPDM_TPM_QUOTE_VERSION 1
#define SPDM_TPM_QUOTE_HEADER_SIZE 6

uint8_t m_tpm_iak_cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
size_t m_tpm_iak_cert_chain_size;

static bool verify_tpm_quote_evidence(void *spdm_context,
                                      const uint8_t *requester_nonce,
                                      const uint8_t *measurement_record,
                                      size_t measurement_record_size,
                                      uint8_t number_of_blocks,
                                      const uint8_t *opaque_data,
                                      size_t opaque_data_size)
{
    const spdm_general_opaque_data_table_header_t *table_header;
    const spdm_svh_tcg_header_t *element_header;
    const uint8_t *element_data;
    uint16_t element_data_size;
    uint16_t attest_size;
    uint16_t signature_size;
    size_t unpadded_opaque_size;
    size_t padding_size;
    uint8_t iak_slot_id;
    const char *iak_root_cert_file;
    const char *iak_cert_chain_file;
    void *iak_root_cert;
    size_t iak_root_cert_size;
    void *iak_cert_chain;
    size_t iak_cert_chain_size;
    const uint8_t *chain_root_cert;
    size_t chain_root_cert_size;
    const uint8_t *env_leaf_cert;
    size_t env_leaf_cert_size;
    const uint8_t *received_spdm_cert_chain;
    size_t received_spdm_cert_chain_size;
    const uint8_t *spdm_cert_chain_data;
    size_t spdm_cert_chain_data_size;
    const uint8_t *spdm_leaf_cert;
    size_t spdm_leaf_cert_size;
    const spdm_measurement_block_dmtf_t *measurement_block;
    size_t measurement_block_size;
    size_t record_offset;
    size_t hash_size;
    size_t base_hash_size;
    uint8_t pcr_data[LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                     LIBSPDM_MAX_HASH_SIZE];
    size_t pcr_data_size;
    uint32_t pcr_mask;
    uint8_t block_index;
    uint8_t last_pcr_index;
    libspdm_data_parameter_t parameter;
    uint32_t measurement_hash_algo;
    uint32_t base_hash_algo;
    uint8_t expected_root_hash[LIBSPDM_MAX_HASH_SIZE];
    size_t data_size;
    bool verified;

    EMU_LOG("TPM Quote evidence: opaque=%zu, measurement=%zu, blocks=%u\n",
            opaque_data_size, measurement_record_size, number_of_blocks);
    {
        uint8_t zero_nonce[SPDM_NONCE_SIZE];

        libspdm_zero_mem(zero_nonce, sizeof(zero_nonce));
        if ((requester_nonce == NULL) ||
            libspdm_consttime_is_mem_equal(requester_nonce, zero_nonce,
                                            SPDM_NONCE_SIZE)) {
            EMU_ERR(
                "TPM Quote verification failed: requester nonce missing or all-zero\n");
            return false;
        }
    }
    if (opaque_data_size < (sizeof(*table_header) + sizeof(*element_header) +
                            sizeof(uint16_t) + SPDM_TPM_QUOTE_HEADER_SIZE)) {
        EMU_ERR("TPM Quote verification failed: opaque data too small\n");
        return false;
    }
    table_header = (const void *)opaque_data;
    element_header = (const void *)(table_header + 1);
    if ((table_header->total_elements != 1) ||
        (element_header->header.id != SPDM_REGISTRY_ID_TCG) ||
        (element_header->header.vendor_id_len != sizeof(element_header->vendor_id)) ||
        (element_header->vendor_id != LIBSPDM_TPM_VENDOR_ID)) {
        EMU_ERR("TPM Quote verification failed: unexpected opaque element header\n");
        return false;
    }

    element_data = (const uint8_t *)(element_header + 1);
    /* SPDM opaque element: uint16 LE length prefix, then payload. */
    element_data_size = (uint16_t)(element_data[0] |
                                   ((uint16_t)element_data[1] << 8));
    element_data += sizeof(uint16_t);
    unpadded_opaque_size = sizeof(*table_header) + sizeof(*element_header) +
                           sizeof(uint16_t) + element_data_size;
    /*
     * Validate SPDM opaque padding and element version:
     *   - total size must be 4-byte aligned (SPDM requirement)
     *   - payload must fit within opaque buffer
     *   - 0-3 trailing zero-padding bytes (no non-zero padding)
     *   - payload must hold at least the Quote header
     *   - first payload byte is the evidence version (must be 1)
     */
    if (((opaque_data_size % 4) != 0) ||
        (unpadded_opaque_size > opaque_data_size) ||
        ((padding_size = opaque_data_size - unpadded_opaque_size) >= 4) ||
        ((padding_size > 0) && (opaque_data[unpadded_opaque_size] != 0)) ||
        ((padding_size > 1) && (opaque_data[unpadded_opaque_size + 1] != 0)) ||
        ((padding_size > 2) && (opaque_data[unpadded_opaque_size + 2] != 0)) ||
        (element_data_size < SPDM_TPM_QUOTE_HEADER_SIZE) ||
        (element_data[0] != SPDM_TPM_QUOTE_VERSION)) {
        EMU_ERR("TPM Quote verification failed: opaque layout/version invalid\n");
        return false;
    }

    /* Quote header: slot_id(u8) | attest_len(u16 LE) | sig_len(u16 LE) */
    iak_slot_id = element_data[1];
    attest_size = (uint16_t)(element_data[2] |
                             ((uint16_t)element_data[3] << 8));
    signature_size = (uint16_t)(element_data[4] |
                                ((uint16_t)element_data[5] << 8));
    if ((iak_slot_id != LIBSPDM_TPM_IAK_SLOT_ID) ||
        (iak_slot_id == 0xF) ||
        ((size_t)SPDM_TPM_QUOTE_HEADER_SIZE + attest_size + signature_size !=
         element_data_size)) {
        EMU_ERR("TPM Quote verification failed: slot or evidence sizes invalid\n");
        return false;
    }
    EMU_LOG("TPM Quote evidence header: slot=%u, attest=%u, signature=%u\n",
            iak_slot_id, attest_size, signature_size);

    iak_root_cert = NULL;
    iak_cert_chain = NULL;
    env_leaf_cert = NULL;
    env_leaf_cert_size = 0;
    verified = false;
    iak_root_cert_file = getenv("LIBSPDM_TPM_IAK_ROOT_CERT_FILE");
    iak_cert_chain_file = getenv("LIBSPDM_TPM_IAK_CERT_CHAIN_FILE");

    /*
     * Root is always required. The external chain is optional: when set it is
     * validated against the root and its leaf must byte-match the SPDM IAK
     * slot leaf; when unset the SPDM slot chain (root-excluded: intermediates
     * then leaf, or leaf only) must verify against the configured root.
     */
    if ((iak_root_cert_file == NULL) || (iak_root_cert_file[0] == '\0') ||
        !libspdm_read_input_file(iak_root_cert_file, &iak_root_cert,
                                 &iak_root_cert_size)) {
        free(iak_root_cert);
        EMU_ERR("TPM Quote verification requires configured IAK root certificate\n");
        return false;
    }
    if ((iak_cert_chain_file != NULL) && (iak_cert_chain_file[0] != '\0')) {
        if (!libspdm_read_input_file(iak_cert_chain_file, &iak_cert_chain,
                                     &iak_cert_chain_size)) {
            free(iak_root_cert);
            free(iak_cert_chain);
            EMU_ERR("TPM Quote verification failed: unable to read IAK certificate chain\n");
            return false;
        }

        /* External root/chain is verifier trust policy for the IAK. */
        if (!libspdm_verify_cert_chain_data(
                SPDM_MESSAGE_VERSION_12, iak_cert_chain, iak_cert_chain_size,
                LIBSPDM_TPM_IAK_BASE_ASYM_ALGO, 0,
                LIBSPDM_TPM_IAK_BASE_HASH_ALGO, false,
                SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT) ||
            !libspdm_x509_get_cert_from_cert_chain(
                iak_cert_chain, iak_cert_chain_size, 0,
                &chain_root_cert, &chain_root_cert_size) ||
            (chain_root_cert_size != iak_root_cert_size) ||
            !libspdm_consttime_is_mem_equal(chain_root_cert, iak_root_cert,
                                            iak_root_cert_size) ||
            !libspdm_x509_get_cert_from_cert_chain(
                iak_cert_chain, iak_cert_chain_size, -1,
                &env_leaf_cert, &env_leaf_cert_size)) {
            EMU_ERR("TPM Quote verification failed: untrusted IAK certificate chain\n");
            goto verification_done;
        }
    }

    /*
     * The Quote signing leaf must be the SPDM certificate for iak_slot_id.
     * Use the IAK CERTIFICATE cached during authentication; fail closed if
     * that cache is empty (Quote verification does not re-GET_CERTIFICATE).
     */
    received_spdm_cert_chain = m_tpm_iak_cert_chain;
    received_spdm_cert_chain_size = m_tpm_iak_cert_chain_size;
    if (received_spdm_cert_chain_size == 0) {
        EMU_ERR("TPM Quote verification failed: SPDM IAK slot certificate was not retrieved during authentication\n");
        goto verification_done;
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(base_hash_algo);
    if (LIBSPDM_STATUS_IS_ERROR(
            libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO,
                             &parameter, &base_hash_algo, &data_size))) {
        EMU_ERR("TPM Quote verification failed: unable to get base hash algorithm\n");
        goto verification_done;
    }
    base_hash_size = libspdm_get_hash_size(base_hash_algo);
    if ((received_spdm_cert_chain_size <=
        sizeof(spdm_cert_chain_t) + base_hash_size) ||
        (((const spdm_cert_chain_t *)received_spdm_cert_chain)->length !=
         received_spdm_cert_chain_size) ||
        !libspdm_hash_all(base_hash_algo, iak_root_cert, iak_root_cert_size,
                          expected_root_hash) ||
        !libspdm_consttime_is_mem_equal(
            received_spdm_cert_chain + sizeof(spdm_cert_chain_t),
            expected_root_hash, base_hash_size)) {
        EMU_ERR("TPM Quote verification failed: SPDM IAK slot RootHash mismatch\n");
        goto verification_done;
    }
    EMU_INFO("SPDM IAK slot RootHash match - PASS\n");
    spdm_cert_chain_data =
        received_spdm_cert_chain + sizeof(spdm_cert_chain_t) + base_hash_size;
    spdm_cert_chain_data_size =
        received_spdm_cert_chain_size - sizeof(spdm_cert_chain_t) - base_hash_size;
    if (!libspdm_x509_get_cert_from_cert_chain(
            spdm_cert_chain_data, spdm_cert_chain_data_size, -1,
            &spdm_leaf_cert, &spdm_leaf_cert_size)) {
        EMU_ERR("TPM Quote verification failed: SPDM IAK slot certificate chain invalid\n");
        goto verification_done;
    }
    if (iak_cert_chain != NULL) {
        if ((spdm_leaf_cert_size != env_leaf_cert_size) ||
            !libspdm_consttime_is_mem_equal(spdm_leaf_cert, env_leaf_cert,
                                            spdm_leaf_cert_size)) {
            EMU_ERR("TPM Quote verification failed: IAK leaf does not match SPDM slot certificate\n");
            goto verification_done;
        }
    } else if (!libspdm_x509_verify_cert_chain(
                   iak_root_cert, iak_root_cert_size,
                   spdm_cert_chain_data, spdm_cert_chain_data_size) ||
               !libspdm_x509_certificate_check(
                   SPDM_MESSAGE_VERSION_12,
                   spdm_leaf_cert, spdm_leaf_cert_size,
                   LIBSPDM_TPM_IAK_BASE_ASYM_ALGO, 0,
                   LIBSPDM_TPM_IAK_BASE_HASH_ALGO, false,
                   SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT)) {
        EMU_ERR("TPM Quote verification failed: IAK certificate chain does not verify to configured root\n");
        goto verification_done;
    }

    data_size = sizeof(measurement_hash_algo);
    if (LIBSPDM_STATUS_IS_ERROR(
            libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
                             &parameter, &measurement_hash_algo, &data_size))) {
        EMU_ERR("TPM Quote verification failed: unable to get measurement hash algorithm\n");
        goto verification_done;
    }
    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);
    if (hash_size == 0) {
        EMU_ERR("TPM Quote verification failed: unsupported measurement hash size\n");
        goto verification_done;
    }

    pcr_data_size = 0;
    pcr_mask = 0;
    last_pcr_index = 0;
    record_offset = 0;
    measurement_block = (const void *)measurement_record;
    for (block_index = 0; block_index < number_of_blocks; block_index++) {
        if (record_offset + sizeof(*measurement_block) > measurement_record_size) {
            EMU_ERR("TPM Quote verification failed: truncated measurement record\n");
            goto verification_done;
        }
        measurement_block_size =
            sizeof(*measurement_block) +
            measurement_block->measurement_block_dmtf_header
            .dmtf_spec_measurement_value_size;
        if (record_offset + measurement_block_size > measurement_record_size) {
            EMU_ERR("TPM Quote verification failed: truncated measurement block\n");
            goto verification_done;
        }
        if ((measurement_block->measurement_block_common_header.index >= 1) &&
            (measurement_block->measurement_block_common_header.index <=
             LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER)) {
            if ((measurement_block->measurement_block_dmtf_header
                 .dmtf_spec_measurement_value_type &
                 SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM) != 0) {
                EMU_ERR("TPM Quote verification failed: PCR block must not be raw bitstream\n");
                goto verification_done;
            }
            if ((measurement_block->measurement_block_dmtf_header
                .dmtf_spec_measurement_value_size != hash_size) ||
                (measurement_block->measurement_block_common_header.index <=
                 last_pcr_index) ||
                (pcr_data_size + hash_size > sizeof(pcr_data))) {
                EMU_ERR("TPM Quote verification failed: invalid PCR measurement block\n");
                goto verification_done;
            }
            last_pcr_index =
                measurement_block->measurement_block_common_header.index;
            pcr_mask |=
                1u << (measurement_block->measurement_block_common_header.index - 1);
            /* Copy hash value immediately after the packed block header. */
            libspdm_copy_mem(&pcr_data[pcr_data_size],
                             sizeof(pcr_data) - pcr_data_size,
                             measurement_block + 1, hash_size);
            pcr_data_size += hash_size;
        }
        record_offset += measurement_block_size;
        measurement_block =
            (const void *)((const uint8_t *)measurement_block +
                           measurement_block_size);
    }
    if ((record_offset != measurement_record_size) || (pcr_data_size == 0)) {
        EMU_ERR("TPM Quote verification failed: no PCR digests in measurement record\n");
        goto verification_done;
    }

    verified = libspdm_tpm_verify_quote(
        spdm_leaf_cert, spdm_leaf_cert_size, measurement_hash_algo, pcr_mask,
        requester_nonce, SPDM_NONCE_SIZE,
        pcr_data, pcr_data_size,
        &element_data[SPDM_TPM_QUOTE_HEADER_SIZE], attest_size,
        &element_data[SPDM_TPM_QUOTE_HEADER_SIZE + attest_size], signature_size);
    if (!verified) {
        EMU_ERR("TPM Quote verification failed: quote signature or binding invalid\n");
    }

verification_done:
    free(iak_root_cert);
    free(iak_cert_chain);
    return verified;
}
#endif /* LIBSPDM_TPM_SUPPORT */

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t spdm_send_receive_get_measurement(void *spdm_context,
                                                   const uint32_t *session_id)
{
    libspdm_return_t status;
    uint8_t number_of_blocks;
    uint8_t number_of_block;
    uint8_t received_number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t index;
    uint8_t request_attribute;
    uint32_t data32;
    size_t data_size;
    bool need_sig;
    libspdm_data_parameter_t parameter;
    uint8_t requester_context[SPDM_REQ_CONTEXT_SIZE] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00};
    bool measurement_exist_list[SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS] = {false};
#if LIBSPDM_TPM_SUPPORT
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t opaque_data_size;
    libspdm_zero_mem(requester_nonce, sizeof(requester_nonce));
#endif

    /*get requester_capabilities_flag*/
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(data32);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, &data_size);
    if ((data32 & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG) != 0) {
        need_sig = false;
    } else {
        need_sig = true;
    }

    if (m_use_measurement_operation ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {

        /* Request all at one time. TPM Quote opaque is generated/verified
         * for signed ALL_MEASUREMENTS (--meas_op ALL). */
        requester_context[SPDM_REQ_CONTEXT_SIZE - 1] =
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
        if (need_sig) {
            request_attribute =
                SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        } else {
            request_attribute = 0;
        }
        measurement_record_length = sizeof(measurement_record);
#if LIBSPDM_TPM_SUPPORT
        opaque_data_size = sizeof(opaque_data);
#endif
        status = libspdm_get_measurement_ex2(
            spdm_context, session_id, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
            m_use_slot_id & 0xF, requester_context, NULL, &number_of_block,
            &measurement_record_length, measurement_record,
            NULL,
#if LIBSPDM_TPM_SUPPORT
            requester_nonce, NULL, opaque_data, &opaque_data_size
#else
            NULL, NULL, NULL, NULL
#endif
            );
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
#if LIBSPDM_TPM_SUPPORT
        /*
         * Signed ALL_MEASUREMENTS with TPM support must carry Quote opaque.
         * Unsigned MEAS_CAP_NO_SIG (need_sig=false) may skip Quote.
         */
        if (need_sig) {
            if ((opaque_data_size == 0) ||
                !verify_tpm_quote_evidence(spdm_context, requester_nonce,
                                           measurement_record,
                                           measurement_record_length,
                                           number_of_block, opaque_data,
                                           opaque_data_size)) {
                if (opaque_data_size == 0) {
                    EMU_ERR(
                        "TPM Quote verification failed: signed ALL measurements missing Quote opaque\n");
                }
                return LIBSPDM_STATUS_VERIF_FAIL;
            }
            EMU_INFO("TPM Quote verification - PASS\n");
        }
#endif
    } else {
        request_attribute = m_use_measurement_attribute;

        /* 1. query the total number of measurements available.*/
        requester_context[SPDM_REQ_CONTEXT_SIZE - 1] =
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS;
        status = libspdm_get_measurement_ex2(
            spdm_context, session_id, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
            m_use_slot_id & 0xF, requester_context, NULL, &number_of_blocks, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return status;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "number_of_blocks - 0x%x\n",
                       number_of_blocks));

        /* 2. get the existing measurement list*/
        received_number_of_block = 0;
        for (index = 1; index < SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS; index++) {
            if (received_number_of_block == number_of_blocks) {
                break;
            }
            LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "index - 0x%x\n", index));

            requester_context[SPDM_REQ_CONTEXT_SIZE - 1] = index;
            /* Discovery only: do not request signatures here. */
            request_attribute = m_use_measurement_attribute;
            measurement_record_length = sizeof(measurement_record);
            status = libspdm_get_measurement_ex2(
                spdm_context, session_id, request_attribute,
                index, m_use_slot_id & 0xF, requester_context, NULL, &number_of_block,
                &measurement_record_length, measurement_record,
                NULL, NULL, NULL, NULL, NULL);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                continue;
            }
            received_number_of_block++;
            measurement_exist_list[index] = true;
        }
        if (received_number_of_block != number_of_blocks) {
            return LIBSPDM_STATUS_INVALID_STATE_PEER;
        }

        /** 3. query measurement one by one
         *
         * In SPDM 1.2 spec, the L1/L2 will be reset in case of MEASUREMENT error. That impacts 1-by-1 calculation.
         * For example, if a device supports Measurement 1 and Measurement 3,
         * then our current mechanism will cause Measurement 1 NOT included in final transcript,
         * because Measurement 2 is missing.
         *
         * The solution is: get the existing measurement list, then query measurement one by one.
         *
         * With TPM support, signed PCR hash indices also carry Quote opaque
         * evidence; verify each such response. Non-PCR indices keep the
         * signature-on-last-message L1 behavior (empty Quote opaque).
         **/
        received_number_of_block = 0;
        for (index = 1; index < SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS; index++) {
            if (received_number_of_block == number_of_blocks) {
                break;
            }

            if (measurement_exist_list[index]) {
                LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "exist measurement index - 0x%x\n", index));

                requester_context[SPDM_REQ_CONTEXT_SIZE - 1] = index;
                request_attribute = m_use_measurement_attribute;
                if (need_sig) {
                    if ((index >= 1) &&
                        (index <= LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER)) {
                        /* Signed PCR index: generate and verify Quote. */
                        request_attribute |=
                            SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
                    } else if (received_number_of_block == number_of_blocks - 1) {
                        /* Last non-PCR block: SPDM L1 signature only. */
                        request_attribute |=
                            SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
                    }
                }
                measurement_record_length = sizeof(measurement_record);
#if LIBSPDM_TPM_SUPPORT
                opaque_data_size = 0;
                if ((request_attribute &
                     SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
                    opaque_data_size = sizeof(opaque_data);
                }
#endif
                status = libspdm_get_measurement_ex2(
                    spdm_context, session_id, request_attribute,
                    index, m_use_slot_id & 0xF, requester_context, NULL, &number_of_block,
                    &measurement_record_length, measurement_record,
                    NULL,
#if LIBSPDM_TPM_SUPPORT
                    (opaque_data_size != 0) ? requester_nonce : NULL,
                    NULL,
                    (opaque_data_size != 0) ? opaque_data : NULL,
                    (opaque_data_size != 0) ? &opaque_data_size : NULL
#else
                    NULL, NULL, NULL, NULL
#endif
                    );
                if (LIBSPDM_STATUS_IS_ERROR(status)) {
                    return LIBSPDM_STATUS_ERROR_PEER;
                }
#if LIBSPDM_TPM_SUPPORT
                if (need_sig && (index >= 1) &&
                    (index <= LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER)) {
                    /* Signed PCR measurement must carry Quote opaque. */
                    if ((opaque_data_size == 0) ||
                        !verify_tpm_quote_evidence(spdm_context, requester_nonce,
                                                   measurement_record,
                                                   measurement_record_length,
                                                   number_of_block, opaque_data,
                                                   opaque_data_size)) {
                        if (opaque_data_size == 0) {
                            EMU_ERR(
                                "TPM Quote verification failed: signed PCR measurement missing Quote opaque\n");
                        }
                        return LIBSPDM_STATUS_VERIF_FAIL;
                    }
                    EMU_INFO("TPM Quote verification - PASS (index 0x%x)\n",
                             index);
                }
#endif
                received_number_of_block++;
            }
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_measurement_via_spdm(const uint32_t *session_id)
{
    libspdm_return_t status;
    void *spdm_context;

    spdm_context = m_spdm_context;

    status = spdm_send_receive_get_measurement(spdm_context, session_id);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

#if LIBSPDM_ENABLE_CAPABILITY_MEL_CAP
/**
 * This function executes SPDM measurement MEL.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t do_measurement_mel_via_spdm(const uint32_t *session_id)
{
    libspdm_return_t status;
    void *spdm_context;
    size_t spdm_mel_size;
    uint8_t spdm_mel[LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE];
    libspdm_data_parameter_t parameter;
    uint32_t measurement_hash_algo;
    size_t data_size;

    spdm_context = m_spdm_context;
    spdm_mel_size = sizeof(spdm_mel);
    libspdm_zero_mem(spdm_mel, sizeof(spdm_mel));

    /* get setting from connection*/
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

    data_size = sizeof(measurement_hash_algo);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                     &measurement_hash_algo, &data_size);

    status = libspdm_get_measurement_extension_log(spdm_context, session_id, &spdm_mel_size,
                                                   spdm_mel);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    return LIBSPDM_STATUS_SUCCESS;
}
#endif /*LIBSPDM_ENABLE_CAPABILITY_MEL_CAP*/

#endif /*LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP*/
