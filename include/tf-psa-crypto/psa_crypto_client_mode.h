/**
 * \file tf-psa-crypto/psa_crypto_client_mode.h
 *
 * \brief PSA crypto client vs local implementation mode macros
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PSA_CRYPTO_CLIENT_MODE_H
#define TF_PSA_CRYPTO_PSA_CRYPTO_CLIENT_MODE_H

#if defined(MBEDTLS_PSA_CRYPTO_C) || defined(MBEDTLS_PSA_CRYPTO_CLIENT_BUILTIN_PAKE)
#define MBEDTLS_PSA_CRYPTO_HAVE_LOCAL_PSA 1
#else
#define MBEDTLS_PSA_CRYPTO_HAVE_LOCAL_PSA 0
#endif

#if defined(MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(MBEDTLS_PSA_CRYPTO_C) && \
    !defined(MBEDTLS_PSA_CRYPTO_CLIENT_BUILTIN_PAKE)
#define MBEDTLS_PSA_CRYPTO_PSA_CLIENT_REMOTE 1
#else
#define MBEDTLS_PSA_CRYPTO_PSA_CLIENT_REMOTE 0
#endif

#endif /* TF_PSA_CRYPTO_PSA_CRYPTO_CLIENT_MODE_H */
