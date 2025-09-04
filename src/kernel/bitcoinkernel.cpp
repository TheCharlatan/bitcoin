// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITCOINKERNEL_BUILD

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
#include <streams.h>
#include <tinyformat.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/translation.h>

#include <cassert>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <list>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context btck_context_static{};

namespace {

bool is_valid_flag_combination(unsigned int flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

class WriterStream
{
private:
    btck_WriteBytes m_writer;
    void* m_user_data;

public:
    WriterStream(btck_WriteBytes writer, void* user_data)
        : m_writer{writer}, m_user_data{user_data} {}

    //
    // Stream subset
    //
    void write(std::span<const std::byte> src)
    {
        if (m_writer(std::data(src), src.size(), m_user_data) != 0) {
            throw std::runtime_error("Failed to write serilization data");
        }
    }

    template <typename T>
    WriterStream& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }
};

template<typename C, typename CPP>
struct Handle {
    static C* ref(CPP* cpp_type) {
        return reinterpret_cast<C*>(cpp_type);
    }

    static const C* ref(const CPP* cpp_type) {
        return reinterpret_cast<const C*>(cpp_type);
    }

    static const CPP& get(const C* ptr) {
        return *reinterpret_cast<const CPP*>(ptr);
    }

    static void operator delete(void* ptr) {
        delete reinterpret_cast<CPP*>(ptr);
    }
};

BCLog::Level get_bclog_level(btck_LogLevel level)
{
    switch (level) {
    case btck_LogLevel_INFO: {
        return BCLog::Level::Info;
    }
    case btck_LogLevel_DEBUG: {
        return BCLog::Level::Debug;
    }
    case btck_LogLevel_TRACE: {
        return BCLog::Level::Trace;
    }
    }
    assert(false);
}

BCLog::LogFlags get_bclog_flag(btck_LogCategory category)
{
    switch (category) {
    case btck_LogCategory_BENCH: {
        return BCLog::LogFlags::BENCH;
    }
    case btck_LogCategory_BLOCKSTORAGE: {
        return BCLog::LogFlags::BLOCKSTORAGE;
    }
    case btck_LogCategory_COINDB: {
        return BCLog::LogFlags::COINDB;
    }
    case btck_LogCategory_LEVELDB: {
        return BCLog::LogFlags::LEVELDB;
    }
    case btck_LogCategory_MEMPOOL: {
        return BCLog::LogFlags::MEMPOOL;
    }
    case btck_LogCategory_PRUNE: {
        return BCLog::LogFlags::PRUNE;
    }
    case btck_LogCategory_RAND: {
        return BCLog::LogFlags::RAND;
    }
    case btck_LogCategory_REINDEX: {
        return BCLog::LogFlags::REINDEX;
    }
    case btck_LogCategory_VALIDATION: {
        return BCLog::LogFlags::VALIDATION;
    }
    case btck_LogCategory_KERNEL: {
        return BCLog::LogFlags::KERNEL;
    }
    case btck_LogCategory_ALL: {
        return BCLog::LogFlags::ALL;
    }
    }
    assert(false);
}

struct ContextOptions {
};

class Context
{
public:
    std::unique_ptr<kernel::Context> m_context;

    std::unique_ptr<kernel::Notifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

    std::unique_ptr<const CChainParams> m_chainparams;

    Context(const ContextOptions* options, bool& sane)
        : m_context{std::make_unique<kernel::Context>()},
          m_notifications{std::make_unique<kernel::Notifications>()},
          m_interrupt{std::make_unique<util::SignalInterrupt>()},
          m_chainparams{CChainParams::Main()}
    {
        if (!kernel::SanityChecks(*m_context)) {
            sane = false;
        }
    }
};

} // namespace

struct LoggingConnection {
    std::unique_ptr<std::list<std::function<void(const std::string&)>>::iterator> m_connection;
    void* user_data;
    std::function<void(void* user_data)> m_deleter;

    ~LoggingConnection()
    {
        if (user_data && m_deleter) {
            m_deleter(user_data);
        }
    }
};

struct btck_Transaction : Handle<btck_Transaction, std::shared_ptr<const CTransaction>> {};
struct btck_TransactionOutput : Handle<btck_TransactionOutput, CTxOut> {};
struct btck_ScriptPubkey : Handle<btck_ScriptPubkey, CScript> {};
struct btck_LoggingConnection : Handle<btck_LoggingConnection, LoggingConnection> {};
struct btck_ContextOptions : Handle<btck_ContextOptions, ContextOptions> {};
struct btck_Context : Handle<btck_Context, std::shared_ptr<const Context>> {};

btck_Transaction* btck_transaction_create(const void* raw_transaction, size_t raw_transaction_len)
{
    try {
        DataStream stream{std::span{reinterpret_cast<const std::byte*>(raw_transaction), raw_transaction_len}};
        return btck_Transaction::ref(new std::shared_ptr<const CTransaction>{new CTransaction{deserialize, TX_WITH_WITNESS, stream}});
    } catch (...) {
        return nullptr;
    }
}

size_t btck_transaction_count_outputs(const btck_Transaction* transaction)
{
    return btck_Transaction::get(transaction)->vout.size();
}

const btck_TransactionOutput* btck_transaction_get_output_at(const btck_Transaction* transaction, size_t output_index)
{
    assert(output_index < btck_Transaction::get(transaction)->vout.size());
    return btck_TransactionOutput::ref(&btck_Transaction::get(transaction)->vout[output_index]);
}

size_t btck_transaction_count_inputs(const btck_Transaction* transaction)
{
    return btck_Transaction::get(transaction)->vin.size();
}

btck_Transaction* btck_transaction_copy(const btck_Transaction* transaction)
{
    auto tx{new std::shared_ptr<const CTransaction>(btck_Transaction::get(transaction))};
    return btck_Transaction::ref(tx);
}

int btck_transaction_to_bytes(const btck_Transaction* transaction, btck_WriteBytes writer, void* user_data)
{
    try {
        WriterStream ws{writer, user_data};
        ws << TX_WITH_WITNESS(btck_Transaction::get(transaction));
        return 0;
    } catch (...) {
        return -1;
    }
}

void btck_transaction_destroy(btck_Transaction* transaction)
{
    if (!transaction) return;
    Assert(btck_Transaction::get(transaction)->vout.size() > 0);
    delete transaction;
}

btck_ScriptPubkey* btck_script_pubkey_create(const void* script_pubkey, size_t script_pubkey_len)
{
    auto data = std::span{reinterpret_cast<const uint8_t*>(script_pubkey), script_pubkey_len};
    return btck_ScriptPubkey::ref(new CScript(data.begin(), data.end()));
}

int btck_script_pubkey_to_bytes(const btck_ScriptPubkey* script_pubkey_, btck_WriteBytes writer, void* user_data)
{
    const auto& script_pubkey{btck_ScriptPubkey::get(script_pubkey_)};
    return writer(script_pubkey.data(), script_pubkey.size(), user_data);
}

btck_ScriptPubkey* btck_script_pubkey_copy(const btck_ScriptPubkey* script_pubkey)
{
    return btck_ScriptPubkey::ref(new CScript(btck_ScriptPubkey::get(script_pubkey)));
}

void btck_script_pubkey_destroy(btck_ScriptPubkey* script_pubkey)
{
    if (!script_pubkey) return;
    delete script_pubkey;
}

btck_TransactionOutput* btck_transaction_output_create(const btck_ScriptPubkey* script_pubkey, int64_t amount)
{
    const CAmount& value{amount};
    return btck_TransactionOutput::ref(new CTxOut(value, btck_ScriptPubkey::get(script_pubkey)));
}

btck_TransactionOutput* btck_transaction_output_copy(const btck_TransactionOutput* output)
{
    return btck_TransactionOutput::ref(new CTxOut{btck_TransactionOutput::get(output)});
}

const btck_ScriptPubkey* btck_transaction_output_get_script_pubkey(const btck_TransactionOutput* output)
{
    return btck_ScriptPubkey::ref(&btck_TransactionOutput::get(output).scriptPubKey);
}

int64_t btck_transaction_output_get_amount(const btck_TransactionOutput* output)
{
    return btck_TransactionOutput::get(output).nValue;
}

void btck_transaction_output_destroy(btck_TransactionOutput* output)
{
    if (!output) return;
    delete output;
}

int btck_script_pubkey_verify(const btck_ScriptPubkey* script_pubkey,
                          const int64_t amount_,
                          const btck_Transaction* tx_to,
                          const btck_TransactionOutput** spent_outputs_, size_t spent_outputs_len,
                          const unsigned int input_index,
                          const btck_ScriptVerificationFlags flags,
                          btck_ScriptVerifyStatus* status)
{
    const CAmount amount{amount_};

    // Assert that all specified flags are part of the interface before continuing
    assert((flags & ~btck_ScriptVerificationFlags_ALL) == 0);

    if (!is_valid_flag_combination(flags)) {
        if (status) *status = btck_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION;
        return 0;
    }

    if (flags & btck_ScriptVerificationFlags_TAPROOT  && spent_outputs_ == nullptr) {
        if (status) *status = btck_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED;
        return 0;
    }

    const CTransaction& tx{*btck_Transaction::get(tx_to)};
    std::vector<CTxOut> spent_outputs;
    if (spent_outputs_ != nullptr) {
        assert(spent_outputs_len == tx.vin.size());
        spent_outputs.reserve(spent_outputs_len);
        for (size_t i = 0; i < spent_outputs_len; i++) {
            const CTxOut& tx_out{btck_TransactionOutput::get(spent_outputs_[i])};
            spent_outputs.push_back(tx_out);
        }
    }

    assert(input_index < tx.vin.size());
    PrecomputedTransactionData txdata{tx};

    if (spent_outputs_ != nullptr && flags & btck_ScriptVerificationFlags_TAPROOT) {
        txdata.Init(tx, std::move(spent_outputs));
    }

    bool result = VerifyScript(tx.vin[input_index].scriptSig,
                        btck_ScriptPubkey::get(script_pubkey),
                        &tx.vin[input_index].scriptWitness,
                        flags,
                        TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
                        nullptr);
    return result ? 1 : 0;
}

void btck_logging_set_level_category(btck_LogCategory category, btck_LogLevel level)
{
    if (category == btck_LogCategory_ALL) {
        LogInstance().SetLogLevel(get_bclog_level(level));
    }

    LogInstance().AddCategoryLogLevel(get_bclog_flag(category), get_bclog_level(level));
}

void btck_logging_enable_category(btck_LogCategory category)
{
    LogInstance().EnableCategory(get_bclog_flag(category));
}

void btck_logging_disable_category(btck_LogCategory category)
{
    LogInstance().DisableCategory(get_bclog_flag(category));
}

void btck_logging_disable()
{
    LogInstance().DisableLogging();
}

btck_LoggingConnection* btck_logging_connection_create(btck_LogCallback callback,
                                                           void* user_data,
                                                           btck_DestroyCallback user_data_destroy_callback,
                                                           const btck_LoggingOptions options)
{
    LogInstance().m_log_timestamps = options.log_timestamps;
    LogInstance().m_log_time_micros = options.log_time_micros;
    LogInstance().m_log_threadnames = options.log_threadnames;
    LogInstance().m_log_sourcelocations = options.log_sourcelocations;
    LogInstance().m_always_print_category_level = options.always_print_category_levels;

    auto connection{LogInstance().PushBackCallback([callback, user_data](const std::string& str) { callback((void*)user_data, str.c_str(), str.length()); })};

    try {
        // Only start logging if we just added the connection.
        if (LogInstance().NumConnections() == 1 && !LogInstance().StartLogging()) {
            LogError("Logger start failed.");
            LogInstance().DeleteCallback(connection);
            user_data_destroy_callback(user_data);
            return nullptr;
        }
    } catch (std::exception& e) {
        LogError("Logger start failed: %s", e.what());
        LogInstance().DeleteCallback(connection);
        user_data_destroy_callback(user_data);
        return nullptr;
    }

    LogDebug(BCLog::KERNEL, "Logger connected.");

    return btck_LoggingConnection::ref(
            new LoggingConnection{std::make_unique<std::list<std::function<void(const std::string&)>>::iterator>(connection), user_data, user_data_destroy_callback});
}

void btck_logging_connection_destroy(btck_LoggingConnection* connection)
{
    if (!connection) {
        return;
    }

    LogDebug(BCLog::KERNEL, "Logger disconnected.");
    LogInstance().DeleteCallback(*btck_LoggingConnection::get(connection).m_connection);
    delete connection;

    // Switch back to buffering by calling DisconnectTestLogger if the
    // connection that was just removed was the last one.
    if (!LogInstance().Enabled()) {
        LogInstance().DisconnectTestLogger();
    }
}

btck_ContextOptions* btck_context_options_create()
{
    return btck_ContextOptions::ref(new ContextOptions{});
}

void btck_context_options_destroy(btck_ContextOptions* options)
{
    if (!options) return;
    delete options;
    options = nullptr;
}

btck_Context* btck_context_create(const btck_ContextOptions* options)
{
    bool sane{true};
    const ContextOptions* opts = options ? &btck_ContextOptions::get(options) : nullptr;
    auto context{std::make_shared<const Context>(opts, sane)};
    if (!sane) {
        LogError("Kernel context sanity check failed.");
        return nullptr;
    }
    return btck_Context::ref(new std::shared_ptr<const Context>(context));
}

btck_Context* btck_context_copy(const btck_Context* context)
{
    return btck_Context::ref(new std::shared_ptr<const Context>(btck_Context::get(context)));
}

void btck_context_destroy(btck_Context* context)
{
    if (!context) return;
    delete context;
    context = nullptr;
}
