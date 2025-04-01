// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITCOINKERNEL_BUILD

#include <kernel/bitcoinkernel.hpp>

#include <consensus/amount.h>
#include <kernel/context.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>

#include <algorithm>
#include <exception>
#include <functional>
#include <span>
#include <string>
#include <utility>
#include <vector>

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context kernel_context_static{};

namespace kernel_header {

bool is_valid_flag_combination(unsigned int flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

struct ScriptPubkey::ScriptPubkeyImpl {
    CScript m_script_pubkey;

    ScriptPubkeyImpl(std::span<const unsigned char> script_pubkey)
        : m_script_pubkey{script_pubkey.begin(), script_pubkey.end()}
    {
    }
};

ScriptPubkey::ScriptPubkey(std::span<const unsigned char> script_pubkey) noexcept
    : m_impl{std::make_unique<ScriptPubkey::ScriptPubkeyImpl>(script_pubkey)}
{
}

ScriptPubkey::~ScriptPubkey() = default;

struct Transaction::TransactionImpl {
    CTransaction m_transaction;
    TransactionImpl(CTransaction&& tx) : m_transaction{std::move(tx)} {}
};

Transaction::Transaction(std::span<const unsigned char> raw_transaction) noexcept
{
    try {
        DataStream stream{raw_transaction};
        m_impl = std::make_unique<Transaction::TransactionImpl>(CTransaction{deserialize, TX_WITH_WITNESS, stream});
    } catch (std::exception&) {
        m_impl = nullptr;
    }
}

Transaction::~Transaction() = default;

struct TransactionOutput::TransactionOutputImpl {
    CTxOut m_tx_out;

    TransactionOutputImpl(CAmount amount, const ScriptPubkey& script_pubkey)
        : m_tx_out{amount, script_pubkey.m_impl->m_script_pubkey}
    {
    }
};

TransactionOutput::TransactionOutput(const ScriptPubkey& script_pubkey, int64_t amount) noexcept
{
    m_impl = std::make_unique<TransactionOutput::TransactionOutputImpl>(CAmount{amount}, script_pubkey);
}

TransactionOutput::~TransactionOutput() = default;

TransactionOutput::TransactionOutput(TransactionOutput&& other) noexcept = default;
TransactionOutput& TransactionOutput::operator=(TransactionOutput&& other) noexcept = default;


/** Check that all specified flags are part of the libbitcoinkernel interface. */
bool verify_flags(unsigned int flags)
{
    const uint32_t all_valid_flags{((SCRIPT_VERIFY_END_MARKER - 1) << 1) - 1};
    return (flags & all_valid_flags) == flags;
}

int ScriptPubkey::VerifyScript(
    const CAmount amount,
    const Transaction& tx_to,
    std::span<const TransactionOutput> spent_outputs,
    const unsigned int input_index,
    const unsigned int flags) const noexcept
{
    if (!verify_flags(flags)) {
        LogError("Script flags invalid.");
        return false;
    }

    if (!is_valid_flag_combination(flags)) {
        LogError("Invalid script flags combination.");
        return false;
    }

    if (flags & SCRIPT_VERIFY_TAPROOT && spent_outputs.empty()) {
        LogError("Spent outputs required when validating with the SCRIPT_VERIFY_TAPROOT flags set.");
        return false;
    }

    const CTransaction& tx = tx_to.m_impl->m_transaction;
    std::vector<CTxOut> spent_outputs_vec;
    if (!spent_outputs.empty()) {
        if (spent_outputs.size() != tx.vin.size()) {
            LogError("Number of spent outputs does not match number of transaction inputs.");
            return false;
        }
        spent_outputs_vec.reserve(spent_outputs.size());
        for (const auto& spent_output : spent_outputs) {
            spent_outputs_vec.push_back(spent_output.m_impl->m_tx_out);
        }
    }

    if (input_index >= tx.vin.size()) {
        LogError("The transaction input index is out of bounds.");
        return false;
    }
    PrecomputedTransactionData txdata{tx};

    if (!spent_outputs_vec.empty() && flags & SCRIPT_VERIFY_TAPROOT) {
        txdata.Init(tx, std::move(spent_outputs_vec));
    }

    return ::VerifyScript(tx.vin[input_index].scriptSig,
                          m_impl->m_script_pubkey,
                          &tx.vin[input_index].scriptWitness,
                          flags,
                          TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
                          nullptr);
}

} // namespace kernel_header
