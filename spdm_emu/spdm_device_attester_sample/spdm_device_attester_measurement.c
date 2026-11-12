/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_device_attester_sample.h"
#include "tpm_quote_verify.h"
#if LIBSPDM_TPM_SUPPORT
#include "library/spdm_tpm_pcr.h"
#endif

/**
 * This function executes SPDM measurement and extend to TPM.
 *
 * @param[in]  spdm_context            The SPDM context for the device.
 **/
libspdm_return_t spdm_send_receive_get_measurement(void *spdm_context,
                                                   const uint32_t *session_id,
                                                   uint8_t slot_id,
                                                   uint8_t *measurement_record,
                                                   uint32_t *measurement_record_length
                                                   )
{
    libspdm_return_t status;
    uint8_t number_of_blocks;
    uint8_t number_of_block;
    uint8_t received_number_of_block;
    uint32_t one_measurement_record_length;
    uint8_t one_measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t index;
    uint8_t request_attribute;
    uint32_t measurement_record_offset;
    uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
    size_t opaque_data_size;
    uint8_t requester_nonce[SPDM_NONCE_SIZE];
    uint8_t responder_nonce[SPDM_NONCE_SIZE];
#if LIBSPDM_TPM_SUPPORT
    libspdm_data_parameter_t parameter;
    uint8_t peer_slot_mask;
    size_t data_size;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(peer_slot_mask);
    status = libspdm_get_data(spdm_context, LIBSPDM_DATA_PEER_PROVISIONED_SLOT_MASK,
                              &parameter, &peer_slot_mask, &data_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
#endif

    /* request all at one time.*/

    request_attribute =
        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    opaque_data_size = sizeof(opaque_data);
    status = libspdm_get_measurement_ex2(
        spdm_context, session_id, request_attribute,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
        slot_id, NULL, NULL, &number_of_block,
        measurement_record_length, measurement_record,
        NULL, requester_nonce, responder_nonce, opaque_data, &opaque_data_size);
    if (status == LIBSPDM_STATUS_SUCCESS) {
#if LIBSPDM_TPM_SUPPORT
        return spdm_tpm_verify_signed_measurement(spdm_context, session_id, slot_id,
                                                  measurement_record, *measurement_record_length,
                                                  requester_nonce, opaque_data, opaque_data_size);
#endif
        return status;
    }

    /* use one by one */
    measurement_record_offset = 0;
    request_attribute = m_use_measurement_attribute;

    /* 1. query the total number of measurements available.*/

    status = libspdm_get_measurement(
        spdm_context, session_id, request_attribute,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
        slot_id, NULL, &number_of_blocks, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }
    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "number_of_blocks - 0x%x\n",
                   number_of_blocks));
    received_number_of_block = 0;
    for (index = 1; index <= 0xFE; index++) {
        if (received_number_of_block == number_of_blocks) {
            break;
        }
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "index - 0x%x\n", index));

        /* 2. query measurement one by one
         * get signature in last message only.*/

        if (received_number_of_block == number_of_blocks - 1) {
            request_attribute = m_use_measurement_attribute |
                                SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        }
#if LIBSPDM_TPM_SUPPORT
        if (((peer_slot_mask & (1u << SPDM_TPM_IAK_CERT_SLOT_ID)) != 0) &&
            (libspdm_tpm_measurement_pcr_index(index) < LIBSPDM_TPM_PCR_COUNT)) {
            request_attribute |= SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        }
#endif
        one_measurement_record_length = sizeof(one_measurement_record);
        opaque_data_size = sizeof(opaque_data);
        status = libspdm_get_measurement_ex2(
            spdm_context, session_id, request_attribute,
            index, slot_id, NULL, NULL, &number_of_block,
            &one_measurement_record_length, one_measurement_record,
            NULL, requester_nonce, responder_nonce, opaque_data, &opaque_data_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            continue;
        }
#if LIBSPDM_TPM_SUPPORT
        if ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
            0) {
            status = spdm_tpm_verify_signed_measurement(
                spdm_context, session_id, slot_id, one_measurement_record,
                one_measurement_record_length, requester_nonce, opaque_data, opaque_data_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                return status;
            }
        }
#endif
        received_number_of_block += 1;

        LIBSPDM_ASSERT (*measurement_record_length >= measurement_record_offset);

        if (one_measurement_record_length <
            *measurement_record_length - measurement_record_offset) {
            libspdm_copy_mem (measurement_record + measurement_record_offset,
                              *measurement_record_length - measurement_record_offset,
                              one_measurement_record,
                              one_measurement_record_length);
            measurement_record_offset += one_measurement_record_length;
        } else {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }
    }
    if (received_number_of_block != number_of_blocks) {
        return LIBSPDM_STATUS_INVALID_STATE_PEER;
    }

    *measurement_record_length = measurement_record_offset;

    return LIBSPDM_STATUS_SUCCESS;
}
