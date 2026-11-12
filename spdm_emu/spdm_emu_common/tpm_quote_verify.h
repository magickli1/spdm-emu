/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#ifndef TPM_QUOTE_VERIFY_H
#define TPM_QUOTE_VERIFY_H

#include "hal/base.h"
#include "library/spdm_return_status.h"
#include "internal/libspdm_lib_config.h"
#if LIBSPDM_TPM_SUPPORT
#include "library/spdm_tpm_quote_opaque.h"

/* SPDM slot that carries the responder TPM IAK certificate chain. */
#define SPDM_TPM_IAK_CERT_SLOT_ID LIBSPDM_TPM_IAK_SLOT_ID
#endif

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP && LIBSPDM_TPM_SUPPORT

/**
 * Verify TPM Quote in MEASUREMENTS opaque_data (OpaqueDataFmt1 + TCG element).
 *
 * Checks:
 * - the opaque data is a well-formed Quote element (libspdm_tpm_quote_opaque_decode()), and
 *   its iak_slot_id == SPDM_TPM_IAK_CERT_SLOT_ID != signing_slot_id;
 * - libspdm_tpm_verify_quote_measurement_record() with the IAK leaf public key (IAK slot
 *   cert chain): the Quote signature, extraData == request nonce (freshness), and that the
 *   Quote selects and attests exactly the PCR measurement blocks of measurement_record;
 * - the IAK certificate asserts tcg-cap-verifiedTPMRestricted, and it carries the same TCG
 *   hardwareModuleName (SubjectAltName, identifies the TPM) as the signing slot IDevID
 *   certificate, so a Quote from another TPM is rejected.
 *
 * @param signing_slot_id  Slot used for the MEASUREMENTS signature (device identity).
 *
 * @retval true   Quote verified, or no Quote required (unsigned/non-PCR measurement,
 *                or a peer that does not advertise the TPM IAK slot).
 * @retval false  Verification failed.
 */
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
    size_t opaque_data_size);

/* Verify a signed measurement response using the negotiated algorithms and fetch
 * the IAK/device certificate chains over the same session when evidence is present. */
libspdm_return_t spdm_tpm_verify_signed_measurement(
    void *spdm_context, const uint32_t *session_id, uint8_t signing_slot_id,
    const uint8_t *measurement_record, uint32_t measurement_record_length,
    const uint8_t *request_nonce, const uint8_t *opaque_data, size_t opaque_data_size);

/**
 * Fetch (GET_CERTIFICATE) the IAK slot and signing slot certificate chains if needed and record
 * the TCG hardwareModuleName and the verifiedTPMRestricted policy of each leaf, for the
 * IAK / IDevID same-TPM binding check. Each chain must verify against a provisioned root
 * (LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT): a chain libspdm reports as
 * LIBSPDM_STATUS_VERIF_NO_AUTHORITY is rejected.
 *
 * @retval true   Both identities recorded.
 * @retval false  A chain could not be fetched, is not issued by a trusted root, has no TPM 2.0
 *                hardwareModuleName, or signing_slot_id is not a certificate slot distinct
 *                from the IAK slot.
 */
bool spdm_tpm_quote_prepare_peer_identity(void *spdm_context, const uint32_t *session_id,
                                          uint8_t signing_slot_id);

/* Forget recorded peer identities, e.g. on a new connection. */
void spdm_tpm_quote_reset_peer_identity(void);

#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP && LIBSPDM_TPM_SUPPORT */

#endif /* TPM_QUOTE_VERIFY_H */
