/**
 * \file tf-psa-crypto/psa_crypto_client_builtin_pake.h
 *
 * \brief Local builtin PAKE support in PSA crypto client mode
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PSA_CRYPTO_CLIENT_BUILTIN_PAKE_H
#define TF_PSA_CRYPTO_PSA_CRYPTO_CLIENT_BUILTIN_PAKE_H

#include "psa/crypto.h"

#if defined(MBEDTLS_PSA_CRYPTO_CLIENT_BUILTIN_PAKE) && !defined(MBEDTLS_PSA_CRYPTO_C)

psa_status_t psa_crypto_client_builtin_pake_ensure_initialized(void);

psa_status_t psa_crypto_local_import_key(const psa_key_attributes_t *attributes,
                                           const uint8_t *data,
                                           size_t data_length,
                                           mbedtls_svc_key_id_t *key);

#endif

#endif /* TF_PSA_CRYPTO_PSA_CRYPTO_CLIENT_BUILTIN_PAKE_H */
