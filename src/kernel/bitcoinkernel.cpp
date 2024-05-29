// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <consensus/amount.h>
#include <kernel/context.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <tinyformat.h>

#include <cassert>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <list>
#include <span>
#include <string>
#include <utility>
#include <vector>

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context kernel_context_static{};

namespace {

/** Check that all specified flags are part of the libbitcoinkernel interface. */
bool verify_flags(unsigned int flags)
{
    return (flags & ~(kernel_SCRIPT_FLAGS_VERIFY_ALL)) == 0;
}

bool is_valid_flag_combination(unsigned int flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

std::string log_level_to_string(const kernel_LogLevel level)
{
    switch (level) {
    case kernel_LogLevel::kernel_LOG_INFO: {
        return "info";
    }
    case kernel_LogLevel::kernel_LOG_DEBUG: {
        return "debug";
    }
    case kernel_LogLevel::kernel_LOG_TRACE: {
        return "trace";
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::string log_category_to_string(const kernel_LogCategory category)
{
    switch (category) {
    case kernel_LogCategory::kernel_LOG_BENCH: {
        return "bench";
    }
    case kernel_LogCategory::kernel_LOG_BLOCKSTORAGE: {
        return "blockstorage";
    }
    case kernel_LogCategory::kernel_LOG_COINDB: {
        return "coindb";
    }
    case kernel_LogCategory::kernel_LOG_LEVELDB: {
        return "leveldb";
    }
    case kernel_LogCategory::kernel_LOG_LOCK: {
        return "lock";
    }
    case kernel_LogCategory::kernel_LOG_MEMPOOL: {
        return "mempool";
    }
    case kernel_LogCategory::kernel_LOG_PRUNE: {
        return "prune";
    }
    case kernel_LogCategory::kernel_LOG_RAND: {
        return "rand";
    }
    case kernel_LogCategory::kernel_LOG_REINDEX: {
        return "reindex";
    }
    case kernel_LogCategory::kernel_LOG_VALIDATION: {
        return "validation";
    }
    case kernel_LogCategory::kernel_LOG_KERNEL: {
        return "kernel";
    }
    case kernel_LogCategory::kernel_LOG_ALL: {
        return "all";
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

const CTransaction* cast_transaction(const kernel_Transaction* transaction)
{
    assert(transaction);
    return reinterpret_cast<const CTransaction*>(transaction);
}

const CScript* cast_script_pubkey(const kernel_ScriptPubkey* script_pubkey)
{
    assert(script_pubkey);
    return reinterpret_cast<const CScript*>(script_pubkey);
}

const CTxOut* cast_transaction_output(const kernel_TransactionOutput* transaction_output)
{
    assert(transaction_output);
    return reinterpret_cast<const CTxOut*>(transaction_output);
}
} // namespace

kernel_Transaction* kernel_transaction_create(const unsigned char* raw_transaction, size_t raw_transaction_len)
{
    try {
        DataStream stream{std::span{raw_transaction, raw_transaction_len}};
        auto tx = new CTransaction{deserialize, TX_WITH_WITNESS, stream};
        return reinterpret_cast<kernel_Transaction*>(tx);
    } catch (const std::exception&) {
        return nullptr;
    }
}

void kernel_transaction_destroy(kernel_Transaction* transaction)
{
    if (transaction) {
        delete cast_transaction(transaction);
    }
}

kernel_ScriptPubkey* kernel_script_pubkey_create(const unsigned char* script_pubkey_, size_t script_pubkey_len)
{
    auto script_pubkey = new CScript(script_pubkey_, script_pubkey_ + script_pubkey_len);
    return reinterpret_cast<kernel_ScriptPubkey*>(script_pubkey);
}

void kernel_script_pubkey_destroy(kernel_ScriptPubkey* script_pubkey)
{
    if (script_pubkey) {
        delete cast_script_pubkey(script_pubkey);
    }
}

kernel_TransactionOutput* kernel_transaction_output_create(kernel_ScriptPubkey* script_pubkey_, int64_t amount)
{
    const auto& script_pubkey{*cast_script_pubkey(script_pubkey_)};
    const CAmount& value{amount};
    auto tx_out{new CTxOut(value, script_pubkey)};
    return reinterpret_cast<kernel_TransactionOutput*>(tx_out);
}

void kernel_transaction_output_destroy(kernel_TransactionOutput* output)
{
    if (output) {
        delete cast_transaction_output(output);
    }
}

bool kernel_verify_script(const kernel_ScriptPubkey* script_pubkey_,
                         const int64_t amount_,
                         const kernel_Transaction* tx_to,
                         const kernel_TransactionOutput** spent_outputs_, size_t spent_outputs_len,
                         const unsigned int input_index,
                         const unsigned int flags,
                         kernel_ScriptVerifyStatus* status)
{
    const CAmount amount{amount_};
    const auto& script_pubkey{*cast_script_pubkey(script_pubkey_)};

    if (!verify_flags(flags)) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS;
        return false;
    }

    if (!is_valid_flag_combination(flags)) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS_COMBINATION;
        return false;
    }

    if (flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT && spent_outputs_ == nullptr) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED;
        return false;
    }

    const CTransaction& tx{*cast_transaction(tx_to)};
    std::vector<CTxOut> spent_outputs;
    if (spent_outputs_ != nullptr) {
        if (spent_outputs_len != tx.vin.size()) {
            if (status) *status = kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_MISMATCH;
            return false;
        }
        spent_outputs.reserve(spent_outputs_len);
        for (size_t i = 0; i < spent_outputs_len; i++) {
            const CTxOut& tx_out{*reinterpret_cast<const CTxOut*>(spent_outputs_[i])};
            spent_outputs.push_back(tx_out);
        }
    }

    if (input_index >= tx.vin.size()) {
        if (status) *status = kernel_SCRIPT_VERIFY_ERROR_TX_INPUT_INDEX;
        return false;
    }
    PrecomputedTransactionData txdata{tx};

    if (spent_outputs_ != nullptr && flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT) {
        txdata.Init(tx, std::move(spent_outputs));
    }

    return VerifyScript(tx.vin[input_index].scriptSig,
                        script_pubkey,
                        &tx.vin[input_index].scriptWitness,
                        flags,
                        TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
                        nullptr);
}

bool kernel_add_log_level_category(const kernel_LogCategory category, const kernel_LogLevel level_)
{
    const auto level{log_level_to_string(level_)};
    if (category == kernel_LogCategory::kernel_LOG_ALL) {
        return LogInstance().SetLogLevel(level);
    }

    return LogInstance().SetCategoryLogLevel(log_category_to_string(category), level);
}

bool kernel_enable_log_category(const kernel_LogCategory category)
{
    return LogInstance().EnableCategory(log_category_to_string(category));
}

bool kernel_disable_log_category(const kernel_LogCategory category)
{
    return LogInstance().DisableCategory(log_category_to_string(category));
}

void kernel_disable_logging()
{
    LogInstance().DisableLogging();
}

kernel_LoggingConnection* kernel_logging_connection_create(kernel_LogCallback callback,
                                                           void* user_data,
                                                           const kernel_LoggingOptions options)
{
    LogInstance().m_log_timestamps = options.log_timestamps;
    LogInstance().m_log_time_micros = options.log_time_micros;
    LogInstance().m_log_threadnames = options.log_threadnames;
    LogInstance().m_log_sourcelocations = options.log_sourcelocations;
    LogInstance().m_always_print_category_level = options.always_print_category_levels;

    auto connection{LogInstance().PushBackCallback([callback, user_data](const std::string& str) { callback(user_data, str.c_str()); })};

    try {
        // Only start logging if we just added the connection.
        if (LogInstance().NumConnections() == 1 && !LogInstance().StartLogging()) {
            LogError("Logger start failed.\n");
            LogInstance().DeleteCallback(connection);
            return nullptr;
        }
    } catch (std::exception& e) {
        LogError("Logger start failed.\n");
        LogInstance().DeleteCallback(connection);
        return nullptr;
    }

    LogDebug(BCLog::KERNEL, "Logger connected.\n");

    auto heap_connection{new std::list<std::function<void(const std::string&)>>::iterator(connection)};
    return reinterpret_cast<kernel_LoggingConnection*>(heap_connection);
}

void kernel_logging_connection_destroy(kernel_LoggingConnection* connection_)
{
    auto connection{reinterpret_cast<std::list<std::function<void(const std::string&)>>::iterator*>(connection_)};
    if (!connection) {
        return;
    }

    LogDebug(BCLog::KERNEL, "Logger disconnected.\n");
    LogInstance().DeleteCallback(*connection);
    delete connection;

    // We are not buffering if we have a connection, so check that it is not the
    // last available connection.
    if (!LogInstance().Enabled()) {
        LogInstance().DisconnectTestLogger();
    }
}
