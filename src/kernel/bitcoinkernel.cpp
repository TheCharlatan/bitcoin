// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <consensus/amount.h>
#include <kernel/context.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context kernel_context_static{};

namespace {

/** A class that deserializes a single CTransaction one time. */
class TxInputStream
{
public:
    TxInputStream(const unsigned char* txTo, size_t txToLen) : m_data(txTo),
                                                               m_remaining(txToLen)
    {
    }

    void read(Span<std::byte> dst)
    {
        if (dst.size() > m_remaining) {
            throw std::ios_base::failure(std::string(__func__) + ": end of data");
        }

        if (dst.data() == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad destination buffer");
        }

        if (m_data == nullptr) {
            throw std::ios_base::failure(std::string(__func__) + ": bad source buffer");
        }

        memcpy(dst.data(), m_data, dst.size());
        m_remaining -= dst.size();
        m_data += dst.size();
    }

    template <typename T>
    TxInputStream& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }

private:
    const unsigned char* m_data;
    size_t m_remaining;
};

void set_error_ok(kernel_Error* error)
{
    if (error) {
        error->code = kernel_ErrorCode::kernel_ERROR_OK;
    }
}

void set_error(kernel_Error* error, kernel_ErrorCode error_code, std::string message)
{
    if (error) {
        error->code = error_code;
        // clamp error message size
        if (message.size() > sizeof(error->message)) {
            message.resize(sizeof(error->message) - 1);
        }
        memcpy(error->message, message.c_str(), message.size() + 1);
    }
}

void set_error_invalid_pointer(kernel_Error* error, std::string message)
{
    set_error(error, kernel_ErrorCode::kernel_ERROR_INVALID_POINTER, message);
}

/** Check that all specified flags are part of the libbitcoinkernel interface. */
static bool verify_flags(unsigned int flags)
{
    return (flags & ~(kernel_SCRIPT_FLAGS_VERIFY_ALL)) == 0;
}

static bool is_valid_flag_combination(unsigned int flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

static int verify_script(const unsigned char* scriptPubKey, size_t scriptPubKeyLen,
                         const CAmount amount,
                         const unsigned char* txTo, size_t txToLen,
                         const kernel_TransactionOutput* spentOutputs, size_t spentOutputsLen,
                         const unsigned int nIn, const unsigned int flags, kernel_Error* error)
{
    if (!verify_flags(flags)) {
        set_error(error, kernel_ERROR_INVALID_FLAGS, "");
        return 0;
    }

    if (!is_valid_flag_combination(flags)) {
        set_error(error, kernel_ERROR_INVALID_FLAGS_COMBINATION, "This combination of flags is not supported.");
        return 0;
    }

    if (flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT && spentOutputs == nullptr) {
        set_error(error, kernel_ERROR_SPENT_OUTPUTS_REQUIRED, "");
        return 0;
    }

    try {
        TxInputStream stream{txTo, txToLen};
        CTransaction tx{deserialize, TX_WITH_WITNESS, stream};

        std::vector<CTxOut> spent_outputs;
        if (spentOutputs != nullptr) {
            if (spentOutputsLen != tx.vin.size()) {
                set_error(error, kernel_ERROR_SPENT_OUTPUTS_MISMATCH, "");
                return 0;
            }
            for (size_t i = 0; i < spentOutputsLen; i++) {
                CScript spk{CScript(spentOutputs[i].script_pubkey, spentOutputs[i].script_pubkey + spentOutputs[i].script_pubkey_len)};
                const CAmount& value{spentOutputs[i].value};
                CTxOut tx_out{CTxOut(value, spk)};
                spent_outputs.push_back(tx_out);
            }
        }

        if (nIn >= tx.vin.size()) {
            set_error(error, kernel_ERROR_TX_INDEX, "");
            return 0;
        }
        if (GetSerializeSize(TX_WITH_WITNESS(tx)) != txToLen) {
            set_error(error, kernel_ERROR_TX_SIZE_MISMATCH, "");
            return 0;
        }

        // Regardless of the verification result, the tx did not error.
        set_error_ok(error);

        PrecomputedTransactionData txdata(tx);

        if (spentOutputs != nullptr && flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT) {
            txdata.Init(tx, std::move(spent_outputs));
        }

        return VerifyScript(tx.vin[nIn].scriptSig, CScript(scriptPubKey, scriptPubKey + scriptPubKeyLen), &tx.vin[nIn].scriptWitness, flags, TransactionSignatureChecker(&tx, nIn, amount, txdata, MissingDataBehavior::FAIL), nullptr);
    } catch (const std::exception&) {
        set_error(error, kernel_ERROR_TX_DESERIALIZE, ""); // Error deserializing
        return 0;
    }
}

} // namespace

int kernel_verify_script_with_spent_outputs(const unsigned char* script_pubkey, size_t script_pubkey_len,
                                            const int64_t amount,
                                            const unsigned char* tx_to, size_t tx_to_len,
                                            const kernel_TransactionOutput* spent_outputs, size_t spent_outputs_len,
                                            const unsigned int nIn, const unsigned int flags, kernel_Error* error)
{
    const CAmount am{amount};

    if (!script_pubkey) {
        set_error_invalid_pointer(error, "Invalid script_pubkey pointer.");
        return 0;
    }
    if (!tx_to) {
        set_error_invalid_pointer(error, "Invalid tx_to pointer.");
        return 0;
    }

    return ::verify_script(script_pubkey, script_pubkey_len, am, tx_to, tx_to_len, spent_outputs, spent_outputs_len, nIn, flags, error);
}

int kernel_verify_script_with_amount(const unsigned char* script_pubkey, size_t script_pubkey_len,
                                     const int64_t amount,
                                     const unsigned char* tx_to, size_t tx_to_len,
                                     const unsigned int nIn, const unsigned int flags, kernel_Error* error)
{
    if (!script_pubkey) {
        set_error_invalid_pointer(error, "Invalid script_pubkey pointer.");
        return 0;
    }
    if (!tx_to) {
        set_error_invalid_pointer(error, "Invalid tx_to pointer.");
        return 0;
    }

    const CAmount am{amount};
    const kernel_TransactionOutput* spentOutputs{nullptr};
    unsigned int spentOutputsLen = 0;
    return ::verify_script(script_pubkey, script_pubkey_len, am, tx_to, tx_to_len, spentOutputs, spentOutputsLen, nIn, flags, error);
}

int kernel_verify_script(const unsigned char* script_pubkey, size_t script_pubkey_len,
                         const unsigned char* tx_to, size_t tx_to_len,
                         const unsigned int nIn, const unsigned int flags, kernel_Error* error)
{
    if (!script_pubkey) {
        set_error_invalid_pointer(error, "Invalid script_pubkey pointer.");
        return 0;
    }
    if (!tx_to) {
        set_error_invalid_pointer(error, "Invalid tx_to pointer.");
        return 0;
    }

    if (flags & kernel_ScriptFlags::kernel_SCRIPT_FLAGS_VERIFY_WITNESS) {
        set_error(error, kernel_ErrorCode::kernel_ERROR_AMOUNT_REQUIRED, "");
        return 0;
    }

    const CAmount am{0};
    const kernel_TransactionOutput* spentOutputs{nullptr};
    unsigned int spentOutputsLen{0};
    return ::verify_script(script_pubkey, script_pubkey_len, am, tx_to, tx_to_len, spentOutputs, spentOutputsLen, nIn, flags, error);
}
