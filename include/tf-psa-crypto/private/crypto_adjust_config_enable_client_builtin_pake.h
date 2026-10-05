/**
 * \file tf-psa-crypto/private/crypto_adjust_config_enable_client_builtin_pake.h
 * \brief Built-in implementations for PSA client + builtin PAKE mode
 *
 * This is an internal header. Do not include it directly.
 *
 * When PSA crypto runs as a remote client but J-PAKE (and local password
 * import) are handled in-process, enable only the builtin modules those
 * code paths need. The full crypto_adjust_config_enable_builtins.h must not
 * be used here: it would enable unrelated mechanisms (for example CMAC)
 * that the client delegates to the secure PSA implementation.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TF_PSA_CRYPTO_PRIVATE_CRYPTO_ADJUST_CONFIG_ENABLE_CLIENT_BUILTIN_PAKE_H
#define TF_PSA_CRYPTO_PRIVATE_CRYPTO_ADJUST_CONFIG_ENABLE_CLIENT_BUILTIN_PAKE_H

#if defined(PSA_WANT_ALG_JPAKE)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_JPAKE) || \
    !defined(MBEDTLS_PSA_ACCEL_ECC_SECP_R1_256) || \
    defined(MBEDTLS_PSA_ECC_ACCEL_INCOMPLETE_KEY_TYPES_BASIC)
#define MBEDTLS_PSA_BUILTIN_PAKE 1
#define MBEDTLS_PSA_BUILTIN_ALG_JPAKE 1
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECJPAKE_C
#endif /* missing accel */
#endif /* PSA_WANT_ALG_JPAKE */

#endif /* TF_PSA_CRYPTO_PRIVATE_CRYPTO_ADJUST_CONFIG_ENABLE_CLIENT_BUILTIN_PAKE_H */
