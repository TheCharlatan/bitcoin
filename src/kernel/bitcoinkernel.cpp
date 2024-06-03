// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <consensus/amount.h>
#include <kernel/chainparams.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/notifications_interface.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <util/result.h>
#include <util/signalinterrupt.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
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

std::string kernel_log_level_to_string(const kernel_LogLevel level)
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
    }
}

std::string kernel_log_category_to_string(const kernel_LogCategory category)
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
    case kernel_LogCategory::kernel_LOG_NONE: {
        return "none";
    }
    case kernel_LogCategory::kernel_LOG_ALL: {
        return "all";
    }
    }
}

struct ContextOptions {
    std::unique_ptr<const CChainParams> m_chainparams;

    void set_option(const kernel_ContextOptionType option, const void* value, kernel_Error* err)
    {
        switch (option) {
        case kernel_ContextOptionType::kernel_CHAIN_PARAMETERS_OPTION: {
            auto chain_params = reinterpret_cast<const CChainParams*>(value);
            if (!chain_params) {
                set_error_invalid_pointer(err, "Invalid kernel_ChainParameters pointer.");
                return;
            }
            m_chainparams = std::make_unique<const CChainParams>(*chain_params);
            set_error_ok(err);
            return;
        }
        default: {
            set_error(err, kernel_ErrorCode::kernel_ERROR_UNKNOWN_OPTION, "Unknown context option");
        }
        }
    }
};

class Context
{
public:
    std::unique_ptr<kernel::Context> m_context;

    std::unique_ptr<const kernel::Notifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

    std::unique_ptr<const CChainParams> m_chainparams;

    Context(kernel_Error* error, const ContextOptions* options)
        : m_context{std::make_unique<kernel::Context>()},
          m_notifications{std::make_unique<const kernel::Notifications>()},
          m_interrupt{std::make_unique<util::SignalInterrupt>()}
    {
        if (options && options->m_chainparams) {
            m_chainparams = std::make_unique<const CChainParams>(*options->m_chainparams);
        } else {
            m_chainparams = CChainParams::Main();
        }

        if (!kernel::SanityChecks(*m_context)) {
            set_error(error, kernel_ErrorCode::kernel_ERROR_INVALID_CONTEXT, "Context sanity check failed.");
        } else {
            set_error_ok(error);
        }
    }
};

ContextOptions* cast_context_options(kernel_ContextOptions* context_opts, kernel_Error* error)
{
    if (!context_opts) {
        set_error_invalid_pointer(error, "Invalid kernel_ContextOptions pointer.");
    }
    return reinterpret_cast<ContextOptions*>(context_opts);
}

} // namespace

void kernel_add_log_level_category(const kernel_LogCategory category_, const kernel_LogLevel level_)
{
    const auto level{kernel_log_level_to_string(level_)};
    if (category_ == kernel_LogCategory::kernel_LOG_ALL) {
        LogInstance().SetLogLevel(level);
        return;
    }

    LogInstance().SetCategoryLogLevel(kernel_log_category_to_string(category_), level);
}

void kernel_enable_log_category(const kernel_LogCategory category)
{
    LogInstance().EnableCategory(kernel_log_category_to_string(category));
}

void kernel_disable_log_category(const kernel_LogCategory category)
{
    LogInstance().DisableCategory(kernel_log_category_to_string(category));
}

kernel_LoggingConnection* kernel_logging_connection_create(kernel_LogCallback callback,
                                                           void* user_data,
                                                           const kernel_LoggingOptions options,
                                                           kernel_Error* error)
{
    if (!callback) {
        set_error_invalid_pointer(error, "Invalid kernel_LogCallback callback.");
        return nullptr;
    }
    LogInstance().m_log_timestamps = options.log_timestamps;
    LogInstance().m_log_time_micros = options.log_time_micros;
    LogInstance().m_log_threadnames = options.log_threadnames;
    LogInstance().m_log_sourcelocations = options.log_sourcelocations;
    LogInstance().m_always_print_category_level = options.always_print_category_levels;

    auto connection{LogInstance().PushBackCallback([callback, user_data](const std::string& str) { callback(user_data, str.c_str()); })};
    if (!LogInstance().StartLogging()) {
        set_error(error, kernel_ErrorCode::kernel_ERROR_LOGGING_FAILED, "Logger start failed.");
        return nullptr;
    }
    set_error_ok(error);

    auto heap_connection{new std::list<std::function<void(const std::string&)>>::iterator(connection)};
    return reinterpret_cast<kernel_LoggingConnection*>(heap_connection);
}

void kernel_logging_connection_destroy(kernel_LoggingConnection* connection_)
{
    auto connection{reinterpret_cast<std::list<std::function<void(const std::string&)>>::iterator*>(connection_)};
    if (!connection) {
        return;
    }
    LogInstance().DeleteCallback(*connection);
    delete connection;
}

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

const kernel_ChainParameters* kernel_chain_parameters_create(const kernel_ChainType chain_type)
{
    switch (chain_type) {
    case kernel_ChainType::kernel_CHAIN_TYPE_MAINNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(CChainParams::Main().release());
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_TESTNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(CChainParams::TestNet().release());
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_SIGNET: {
        return reinterpret_cast<const kernel_ChainParameters*>(CChainParams::SigNet({}).release());
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_REGTEST: {
        return reinterpret_cast<const kernel_ChainParameters*>(CChainParams::RegTest({}).release());
    }
    }
    assert(0);
}

void kernel_chain_parameters_destroy(const kernel_ChainParameters* chain_parameters)
{
    delete reinterpret_cast<const CChainParams*>(chain_parameters);
}

kernel_ContextOptions* kernel_context_options_create()
{
    return reinterpret_cast<kernel_ContextOptions*>(new ContextOptions{});
}

void kernel_context_options_set(kernel_ContextOptions* context_opts_, const kernel_ContextOptionType n_option, const void* value, kernel_Error* error)
{
    auto context_options{cast_context_options(context_opts_, error)};
    if (!context_options) {
        return;
    }
    context_options->set_option(n_option, value, error);
}

void kernel_context_options_destroy(kernel_ContextOptions* context_opts_)
{
    delete reinterpret_cast<ContextOptions*>(context_opts_);
}

kernel_Context* kernel_context_create(const kernel_ContextOptions* options, kernel_Error* error)
{
    auto context_options{reinterpret_cast<const ContextOptions*>(options)};
    return reinterpret_cast<kernel_Context*>(new Context{error, context_options});
}

void kernel_context_destroy(kernel_Context* context_)
{
    delete reinterpret_cast<Context*>(context_);
}
