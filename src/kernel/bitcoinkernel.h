// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_H
#define BITCOIN_KERNEL_BITCOINKERNEL_H

#ifndef __cplusplus
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#else
#include <cstddef>
#include <cstdint>
#endif // __cplusplus


#if !defined(BITCOINKERNEL_GNUC_PREREQ)
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define BITCOINKERNEL_GNUC_PREREQ(_maj, _min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((_maj) << 16) + (_min))
#else
#define BITCOINKERNEL_GNUC_PREREQ(_maj, _min) 0
#endif
#endif

/* Warning attributes */
#if defined(__GNUC__) && BITCOINKERNEL_GNUC_PREREQ(3, 4)
#define BITCOINKERNEL_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
#define BITCOINKERNEL_WARN_UNUSED_RESULT
#endif
#if !defined(BITCOINKERNEL_BUILD) && defined(__GNUC__) && BITCOINKERNEL_GNUC_PREREQ(3, 4)
#define BITCOINKERNEL_ARG_NONNULL(_x) __attribute__((__nonnull__(_x)))
#else
#define BITCOINKERNEL_ARG_NONNULL(_x)
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * ------ Context ------
 *
 * The library provides a built-in constant kernel context. This context offers
 * only limited functionality. It detects and self-checks the correct sha256
 * implementation, initializes the random number generator and self-checks the
 * secp256k1 static context. It is used internally for otherwise "context-free"
 * operations.
 *
 * ------ Error handling ------
 *
 * When passing the kernel_Error argument to a function it may either be null or
 * initialized to an initial value. It is recommended to set kernel_ERROR_OK
 * before passing it to a function.
 */

/**
 * A collection of error codes that may be issued by the kernel library.
 */
typedef enum {
    kernel_ERROR_OK = 0,
    kernel_ERROR_TX_INDEX,
    kernel_ERROR_TX_SIZE_MISMATCH,
    kernel_ERROR_TX_DESERIALIZE,
    kernel_ERROR_INVALID_FLAGS,
    kernel_ERROR_INVALID_FLAGS_COMBINATION,
    kernel_ERROR_SPENT_OUTPUTS_REQUIRED,
    kernel_ERROR_SPENT_OUTPUTS_MISMATCH,
} kernel_ErrorCode;

/**
 * Contains an error code and a pre-defined buffer for containing a string
 * describing a possible error.
 */
typedef struct {
    kernel_ErrorCode code;
    char message[256];
} kernel_Error;

/**
 * Script verification flags that may be composed with each other.
 */
typedef enum
{
    kernel_SCRIPT_FLAGS_VERIFY_NONE                = 0,
    kernel_SCRIPT_FLAGS_VERIFY_P2SH                = (1U << 0), //!< evaluate P2SH (BIP16) subscripts
    kernel_SCRIPT_FLAGS_VERIFY_DERSIG              = (1U << 2), //!< enforce strict DER (BIP66) compliance
    kernel_SCRIPT_FLAGS_VERIFY_NULLDUMMY           = (1U << 4), //!< enforce NULLDUMMY (BIP147)
    kernel_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9), //!< enable CHECKLOCKTIMEVERIFY (BIP65)
    kernel_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10), //!< enable CHECKSEQUENCEVERIFY (BIP112)
    kernel_SCRIPT_FLAGS_VERIFY_WITNESS             = (1U << 11), //!< enable WITNESS (BIP141)

    kernel_SCRIPT_FLAGS_VERIFY_TAPROOT             = (1U << 17), //!< enable TAPROOT (BIPs 341 & 342)
    kernel_SCRIPT_FLAGS_VERIFY_ALL                 = kernel_SCRIPT_FLAGS_VERIFY_P2SH |
                                                     kernel_SCRIPT_FLAGS_VERIFY_DERSIG |
                                                     kernel_SCRIPT_FLAGS_VERIFY_NULLDUMMY |
                                                     kernel_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                                     kernel_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY |
                                                     kernel_SCRIPT_FLAGS_VERIFY_WITNESS |
                                                     kernel_SCRIPT_FLAGS_VERIFY_TAPROOT
} kernel_ScriptFlags;

/**
 * A helper struct for a single transaction output.
 */
typedef struct {
    int64_t value;
    const unsigned char* script_pubkey;
    size_t script_pubkey_len;
} kernel_TransactionOutput;

/**
 * @brief Verify if the input at input_index of tx_to spends the script pubkey
 * under the constraints specified by flags. If the witness flag is set the
 * amount parameter is used. Additionally, if the spent outputs parameter is
 * used to validate taproot transactions if the taproot flag is set.
 *
 * @param[in] script_pubkey     Non-null, serialized script pubkey to be spent.
 * @param[in] script_pubkey_len Length of the script pubkey to be spent.
 * @param[in] amount            Amount of the script pubkey's associated output. May be zero if
 *                              the witness flag is not set.
 * @param[in] tx_to             Non-null, serialized transaction spending the script_pubkey.
 * @param[in] tx_to_len         Length of the serialized transaction spending the script_pubkey.
 * @param[in] spent_outputs     Nullable if the taproot flag is not set. Points to an array of
 *                              outputs spent by the transaction.
 * @param[in] spent_outputs_len Length of the spent_outputs array.
 * @param[in] input_index       Index of the input in tx_to spending the script_pubkey.
 * @param[in] flags             Bitfield of kernel_ScriptFlags controlling validation constraints.
 * @param[out] error            Nullable, will contain an error/success code for the operation.
 * @return                      1 if the script is valid.
 */
int BITCOINKERNEL_WARN_UNUSED_RESULT kernel_verify_script(
    const unsigned char* script_pubkey, size_t script_pubkey_len,
    int64_t amount,
    const unsigned char* tx_to, size_t tx_to_len,
    const kernel_TransactionOutput* spent_outputs, size_t spent_outputs_len,
    unsigned int input_index,
    unsigned int flags,
    kernel_Error* error
) BITCOINKERNEL_ARG_NONNULL(1) BITCOINKERNEL_ARG_NONNULL(4) BITCOINKERNEL_ARG_NONNULL(6);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // BITCOIN_KERNEL_BITCOINKERNEL_H