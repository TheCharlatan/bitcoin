// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_H
#define BITCOIN_KERNEL_BITCOINKERNEL_H

#ifndef __cplusplus
#include <stddef.h>
#include <stdint.h>
#else
#include <cstddef>
#include <cstdint>
#endif // __cplusplus

#ifndef BITCOINKERNEL_API
    #ifdef BITCOINKERNEL_BUILD
        #if defined(_WIN32)
            #define BITCOINKERNEL_API __declspec(dllexport)
        #elif !defined(_WIN32) && defined(__GNUC__)
            #define BITCOINKERNEL_API __attribute__((visibility("default")))
        #else
            #define BITCOINKERNEL_API
        #endif
    #else
        #if defined(_WIN32) && !defined(BITCOINKERNEL_STATIC)
            #define BITCOINKERNEL_API __declspec(dllimport)
        #else
            #define BITCOINKERNEL_API
        #endif
    #endif
#endif

/* Warning attributes */
#if defined(__GNUC__)
    #define BITCOINKERNEL_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
    #define BITCOINKERNEL_WARN_UNUSED_RESULT
#endif
#if !defined(BITCOINKERNEL_BUILD) && defined(__GNUC__)
    #define BITCOINKERNEL_ARG_NONNULL(...) __attribute__((__nonnull__(__VA_ARGS__)))
#else
    #define BITCOINKERNEL_ARG_NONNULL(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @page remarks Remarks
 *
 * @section context Context
 *
 * The library provides a built-in static constant kernel context. This static
 * context offers only limited functionality. It detects and self-checks the
 * correct sha256 implementation, initializes the random number generator and
 * self-checks the secp256k1 static context. It is used internally for
 * otherwise "context-free" operations. This means that the user is not
 * required to initialize their own context before using the library.
 *
 * @section error Error handling
 *
 * Functions communicate an error through their return types, usually returning
 * a nullptr, 0, or false if an error is encountered. Additionally, verification
 * functions, e.g. for scripts, may communicate more detailed error information
 * through status code out parameters.
 *
 * @section pointer Pointer and argument conventions
 *
 * The user is responsible for de-allocating the memory owned by pointers
 * returned by functions. Typically pointers returned by *_create(...) functions
 * can be de-allocated by corresponding *_destroy(...) functions.
 *
 * A function that takes pointer arguments makes no assumptions on their
 * lifetime. Once the function returns the user can safely de-allocate the
 * passed in arguments.
 *
 * Pointers passed by callbacks are not owned by the user and are only valid
 * for the duration of the callback. They are always marked as `const` and must
 * not be de-allocated by the user.
 *
 * Array lengths follow the pointer argument they describe.
 */

/**
 * Opaque data structure for holding a transaction.
 */
typedef struct btck_Transaction btck_Transaction;

/**
 * Opaque data structure for holding a script pubkey.
 */
typedef struct btck_ScriptPubkey btck_ScriptPubkey;

/**
 * Opaque data structure for holding a transaction output.
 */
typedef struct btck_TransactionOutput btck_TransactionOutput;

/**
 * A collection of status codes that may be issued by the script verify function.
 */
typedef uint8_t btck_ScriptVerifyStatus;
#define btck_ScriptVerifyStatus_SCRIPT_VERIFY_OK ((btck_ScriptVerifyStatus)(0))
#define btck_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION ((btck_ScriptVerifyStatus)(2)) //!< The flags very combined in an invalid way.
#define btck_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED ((btck_ScriptVerifyStatus)(3))    //!< The taproot flag was set, so valid spent_outputs have to be provided.

/**
 * Script verification flags that may be composed with each other.
 */
typedef uint32_t btck_ScriptVerificationFlags;
#define btck_ScriptVerificationFlags_NONE ((btck_ScriptVerificationFlags)(0))
#define btck_ScriptVerificationFlags_P2SH ((btck_ScriptVerificationFlags)(1U << 0)) //!< evaluate P2SH (BIP16) subscripts
#define btck_ScriptVerificationFlags_DERSIG ((btck_ScriptVerificationFlags)(1U << 2)) //!< enforce strict DER (BIP66) compliance
#define btck_ScriptVerificationFlags_NULLDUMMY ((btck_ScriptVerificationFlags)(1U << 4)) //!< enforce NULLDUMMY (BIP147)
#define btck_ScriptVerificationFlags_CHECKLOCKTIMEVERIFY ((btck_ScriptVerificationFlags)(1U << 9)) //!< enable CHECKLOCKTIMEVERIFY (BIP65)
#define btck_ScriptVerificationFlags_CHECKSEQUENCEVERIFY ((btck_ScriptVerificationFlags)(1U << 10)) //!< enable CHECKSEQUENCEVERIFY (BIP112)
#define btck_ScriptVerificationFlags_WITNESS ((btck_ScriptVerificationFlags)(1U << 11)) //!< enable WITNESS (BIP141)
#define btck_ScriptVerificationFlags_TAPROOT ((btck_ScriptVerificationFlags)(1U << 17)) //!< enable TAPROOT (BIPs 341 & 342)
#define btck_ScriptVerificationFlags_ALL ((btck_ScriptVerificationFlags)(                              \
                                                    btck_ScriptVerificationFlags_P2SH |                \
                                                    btck_ScriptVerificationFlags_DERSIG |              \
                                                    btck_ScriptVerificationFlags_NULLDUMMY |           \
                                                    btck_ScriptVerificationFlags_CHECKLOCKTIMEVERIFY | \
                                                    btck_ScriptVerificationFlags_CHECKSEQUENCEVERIFY | \
                                                    btck_ScriptVerificationFlags_WITNESS |             \
                                                    btck_ScriptVerificationFlags_TAPROOT))

/**
 * Function signature for serializing data.
 */
typedef int (*btck_WriteBytes)(const void* bytes, size_t size, void* userdata);

/** @name Transaction
 * Functions for working with transactions.
 */
///@{

/**
 * @brief Create a new transaction from the serialized data.
 *
 * @param[in] raw_transaction     Non-null.
 * @param[in] raw_transaction_len Length of the serialized transaction.
 * @return                        The transaction, or null on error.
 */
BITCOINKERNEL_API btck_Transaction* BITCOINKERNEL_WARN_UNUSED_RESULT btck_transaction_create(
    const void* raw_transaction, size_t raw_transaction_len
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * @brief Copy a transaction. Transactions are reference counted, so this just
 * increments the reference count.
 *
 * @param[in] transaction Non-null.
 * @return                The copied transaction.
 */
BITCOINKERNEL_API btck_Transaction* BITCOINKERNEL_WARN_UNUSED_RESULT btck_transaction_copy(
    const btck_Transaction* transaction
) BITCOINKERNEL_ARG_NONNULL(1);

/*
 * @brief Serializes the transaction through the passed in callback to bytes.
 * This is consensus serialization that is also used for the p2p network.
 *
 * @param[in] transaction Non-null.
 * @param[in] writer      Non-null, callback to a write bytes function.
 * @param[in] user_data   Holds a user-defined opaque structure that will be
 *                        passed back through the writer callback.
 * @return                0 on success.
 */
BITCOINKERNEL_API int btck_transaction_to_bytes(
    const btck_Transaction* transaction,
    btck_WriteBytes writer,
    void* user_data
) BITCOINKERNEL_ARG_NONNULL(1, 2);

/**
 * @brief Get the number of outputs of a transaction.
 *
 * @param[in] transaction Non-null.
 * @return                The number of outputs.
 */
BITCOINKERNEL_API uint64_t BITCOINKERNEL_WARN_UNUSED_RESULT btck_transaction_count_outputs(
    const btck_Transaction* transaction
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the transaction outputs at the provided index. The returned
 * transaction output is not owned and depends on the lifetime of the
 * transaction.
 *
 * @param[in] transaction  Non-null.
 * @param[in] output_index The index of the transaction to be retrieved.
 * @return                 The transaction output
 */
BITCOINKERNEL_API btck_TransactionOutput* BITCOINKERNEL_WARN_UNUSED_RESULT btck_transaction_get_output_at(
    const btck_Transaction* transaction, uint64_t output_index
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the number of inputs of a transaction.
 *
 * @param[in] transaction Non-null.
 * @return                The number of inputs.
 */
BITCOINKERNEL_API uint64_t BITCOINKERNEL_WARN_UNUSED_RESULT btck_transaction_count_inputs(
    const btck_Transaction* transaction
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * Destroy the transaction.
 */
BITCOINKERNEL_API void btck_transaction_destroy(btck_Transaction* transaction);

///@}

/** @name ScriptPubkey
 * Functions for working with script pubkeys.
 */
///@{

/**
 * @brief Create a script pubkey from serialized data.
 * @param[in] script_pubkey     Non-null.
 * @param[in] script_pubkey_len Length of the script pubkey data.
 * @return                      The script pubkey.
 */
BITCOINKERNEL_API btck_ScriptPubkey* BITCOINKERNEL_WARN_UNUSED_RESULT btck_script_pubkey_create(
    const void* script_pubkey, size_t script_pubkey_len
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * @brief Copy a script pubkey.
 *
 * @param[in] script_pubkey Non-null.
 * @return                  The copied script pubkey.
 */
BITCOINKERNEL_API btck_ScriptPubkey* BITCOINKERNEL_WARN_UNUSED_RESULT btck_script_pubkey_copy(
    const btck_ScriptPubkey* script_pubkey
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * @brief Verify if the input at input_index of tx_to spends the script pubkey
 * under the constraints specified by flags. If the
 * `btck_SCRIPT_FLAGS_VERIFY_WITNESS` flag is set in the flags bitfield, the
 * amount parameter is used. If the taproot flag is set, the spent outputs
 * parameter is used to validate taproot transactions.
 *
 * @param[in] script_pubkey     Non-null, script pubkey to be spent.
 * @param[in] amount            Amount of the script pubkey's associated output. May be zero if
 *                              the witness flag is not set.
 * @param[in] tx_to             Non-null, transaction spending the script_pubkey.
 * @param[in] spent_outputs     Nullable if the taproot flag is not set. Points to an array of
 *                              outputs spent by the transaction.
 * @param[in] spent_outputs_len Length of the spent_outputs array.
 * @param[in] input_index       Index of the input in tx_to spending the script_pubkey.
 * @param[in] flags             Bitfield of btck_ScriptFlags controlling validation constraints.
 * @param[out] status           Nullable, will be set to an error code if the operation fails.
 *                              Should be set to btck_SCRIPT_VERIFY_OK.
 * @return                      1 if the script is valid, 0 otherwise.
 */
BITCOINKERNEL_API int BITCOINKERNEL_WARN_UNUSED_RESULT btck_script_pubkey_verify(
    const btck_ScriptPubkey* script_pubkey,
    int64_t amount,
    const btck_Transaction* tx_to,
    const btck_TransactionOutput** spent_outputs, size_t spent_outputs_len,
    unsigned int input_index,
    unsigned int flags,
    btck_ScriptVerifyStatus* status
) BITCOINKERNEL_ARG_NONNULL(1, 3);

/*
 * @brief Serializes the script pubkey through the passed in callback to bytes.
 *
 * @param[in] script_pubkey Non-null.
 * @param[in] writer        Non-null, callback to a write bytes function.
 * @param[in] user_data     Holds a user-defined opaque structure that will be
 *                          passed back through the writer callback.
 * @return                  0 on success.
 */
BITCOINKERNEL_API int btck_script_pubkey_to_bytes(
    const btck_ScriptPubkey* script_pubkey,
    btck_WriteBytes writer,
    void* user_data
) BITCOINKERNEL_ARG_NONNULL(1, 2);

/**
 * Destroy the script pubkey.
 */
BITCOINKERNEL_API void btck_script_pubkey_destroy(btck_ScriptPubkey* script_pubkey);

///@}

/** @name TransactionOutput
 * Functions for working with transaction outputs.
 */
///@{

/**
 * @brief Create a transaction output from a script pubkey and an amount.
 *
 * @param[in] script_pubkey Non-null.
 * @param[in] amount        The amount associated with the script pubkey for this output.
 * @return                  The transaction output.
 */
BITCOINKERNEL_API btck_TransactionOutput* BITCOINKERNEL_WARN_UNUSED_RESULT btck_transaction_output_create(
    const btck_ScriptPubkey* script_pubkey,
    int64_t amount
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the script pubkey of the output. The returned
 * script pubkey is not owned and depends on the lifetime of the
 * transaction output.
 *
 * @param[in] transaction_output Non-null.
 * @return                       The script pubkey.
 */
BITCOINKERNEL_API btck_ScriptPubkey* BITCOINKERNEL_WARN_UNUSED_RESULT btck_transaction_output_get_script_pubkey(
        const btck_TransactionOutput* transaction_output
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * @brief Get the amount in the output.
 *
 * @param[in] transaction_output Non-null.
 * @return                       The amount.
 */
BITCOINKERNEL_API int64_t BITCOINKERNEL_WARN_UNUSED_RESULT btck_transaction_output_get_amount(
    const btck_TransactionOutput* transaction_output
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 *  @brief Copy a transaction output.
 *
 *  @param[in] transaction_output Non-null.
 *  @return                       The copied transaction output.
 */
BITCOINKERNEL_API btck_TransactionOutput* btck_transaction_output_copy(
    const btck_TransactionOutput* transaction_output
) BITCOINKERNEL_ARG_NONNULL(1);

/**
 * Destroy the transaction output.
 */
BITCOINKERNEL_API void btck_transaction_output_destroy(btck_TransactionOutput* transaction_output);

///@}

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // BITCOIN_KERNEL_BITCOINKERNEL_H
