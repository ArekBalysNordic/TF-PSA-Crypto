/**
 * \file tf-psa-crypto/psa_crypto_client_local_wrappers.h
 *
 * \brief Minimal PSA driver wrappers for client + builtin PAKE mode
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PSA_CRYPTO_CLIENT_LOCAL_WRAPPERS_H
#define TF_PSA_CRYPTO_PSA_CRYPTO_CLIENT_LOCAL_WRAPPERS_H

#include "tf_psa_crypto_common.h"
#include "psa_crypto_core.h"
#include "psa_crypto_pake.h"

#if defined(MBEDTLS_PSA_CRYPTO_CLIENT_BUILTIN_PAKE) && !defined(MBEDTLS_PSA_CRYPTO_C)

enum {
    PSA_CRYPTO_MBED_TLS_DRIVER_ID = 1,
};

static inline psa_status_t psa_driver_wrapper_init(void)
{
    return PSA_SUCCESS;
}

static inline void psa_driver_wrapper_free(void)
{
}

static inline psa_status_t psa_driver_wrapper_get_key_buffer_size_from_key_data(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *buffer_size)
{
    (void) attributes;
    (void) data;
    (void) data_length;
    (void) buffer_size;
    return PSA_ERROR_NOT_SUPPORTED;
}

static inline psa_status_t psa_driver_wrapper_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits)
{
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(
        psa_get_key_lifetime(attributes));

    switch (location) {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            return psa_import_key_into_slot(attributes,
                                            data, data_length,
                                            key_buffer, key_buffer_size,
                                            key_buffer_length, bits);
        default:
            (void) data;
            (void) data_length;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) key_buffer_length;
            (void) bits;
            return PSA_ERROR_INVALID_ARGUMENT;
    }
}

static inline psa_status_t psa_driver_wrapper_pake_setup(
    psa_pake_operation_t *operation,
    const psa_crypto_driver_pake_inputs_t *inputs)
{
    psa_status_t status;

#if defined(MBEDTLS_PSA_BUILTIN_PAKE)
    status = mbedtls_psa_pake_setup(&operation->data.ctx.mbedtls_ctx, inputs);
    if (status == PSA_SUCCESS) {
        operation->id = PSA_CRYPTO_MBED_TLS_DRIVER_ID;
    }
    return status;
#else
    (void) operation;
    (void) inputs;
    return PSA_ERROR_NOT_SUPPORTED;
#endif
}

static inline psa_status_t psa_driver_wrapper_pake_output(
    psa_pake_operation_t *operation,
    psa_crypto_driver_pake_step_t step,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
#if defined(MBEDTLS_PSA_BUILTIN_PAKE)
    if (operation->id == PSA_CRYPTO_MBED_TLS_DRIVER_ID) {
        return mbedtls_psa_pake_output(&operation->data.ctx.mbedtls_ctx, step,
                                       output, output_size, output_length);
    }
#endif
    (void) step;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_INVALID_ARGUMENT;
}

static inline psa_status_t psa_driver_wrapper_pake_input(
    psa_pake_operation_t *operation,
    psa_crypto_driver_pake_step_t step,
    const uint8_t *input,
    size_t input_length)
{
#if defined(MBEDTLS_PSA_BUILTIN_PAKE)
    if (operation->id == PSA_CRYPTO_MBED_TLS_DRIVER_ID) {
        return mbedtls_psa_pake_input(&operation->data.ctx.mbedtls_ctx, step,
                                      input, input_length);
    }
#endif
    (void) step;
    (void) input;
    (void) input_length;
    return PSA_ERROR_INVALID_ARGUMENT;
}

static inline psa_status_t psa_driver_wrapper_pake_get_shared_key(
    psa_pake_operation_t *operation,
    uint8_t *output, size_t output_size,
    size_t *output_length)
{
#if defined(MBEDTLS_PSA_BUILTIN_PAKE)
    if (operation->id == PSA_CRYPTO_MBED_TLS_DRIVER_ID) {
        return mbedtls_psa_pake_get_implicit_key(&operation->data.ctx.mbedtls_ctx,
                                                 output, output_size,
                                                 output_length);
    }
#endif
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_INVALID_ARGUMENT;
}

static inline psa_status_t psa_driver_wrapper_pake_abort(
    psa_pake_operation_t *operation)
{
#if defined(MBEDTLS_PSA_BUILTIN_PAKE)
    if (operation->id == PSA_CRYPTO_MBED_TLS_DRIVER_ID) {
        return mbedtls_psa_pake_abort(&operation->data.ctx.mbedtls_ctx);
    }
#endif
    return PSA_ERROR_INVALID_ARGUMENT;
}

#endif /* MBEDTLS_PSA_CRYPTO_CLIENT_BUILTIN_PAKE && !MBEDTLS_PSA_CRYPTO_C */

#endif /* TF_PSA_CRYPTO_PSA_CRYPTO_CLIENT_LOCAL_WRAPPERS_H */
