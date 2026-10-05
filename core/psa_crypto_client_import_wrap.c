/*
 *  PSA import_key wrapper for client-side builtin PAKE
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_CLIENT_BUILTIN_PAKE) && !defined(MBEDTLS_PSA_CRYPTO_C)

#include "psa/crypto.h"
#include "psa/crypto_values.h"
#include "tf-psa-crypto/psa_crypto_client_builtin_pake.h"

psa_status_t __real_psa_import_key(const psa_key_attributes_t *attributes,
                                   const uint8_t *data,
                                   size_t data_length,
                                   mbedtls_svc_key_id_t *key);

psa_status_t __wrap_psa_import_key(const psa_key_attributes_t *attributes,
                                   const uint8_t *data,
                                   size_t data_length,
                                   mbedtls_svc_key_id_t *key);

psa_status_t __wrap_psa_import_key(const psa_key_attributes_t *attributes,
                                   const uint8_t *data,
                                   size_t data_length,
                                   mbedtls_svc_key_id_t *key)
{
    psa_key_type_t type = psa_get_key_type(attributes);

    if (type == PSA_KEY_TYPE_PASSWORD ||
        type == PSA_KEY_TYPE_PASSWORD_HASH) {
        return psa_crypto_local_import_key(attributes, data, data_length, key);
    }

    return __real_psa_import_key(attributes, data, data_length, key);
}

#endif /* MBEDTLS_PSA_CRYPTO_CLIENT_BUILTIN_PAKE && !MBEDTLS_PSA_CRYPTO_C */
