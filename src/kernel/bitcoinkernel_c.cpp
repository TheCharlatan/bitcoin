// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <kernel/bitcoinkernel.hpp>
#include <kernel/logging_types.h>
#include <kernel/types.h>
#include <kernel/warning.h>
#include <util/chaintype.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <span>
#include <string_view>

using kernel_header::BlockIndex;
using kernel_header::ChainParameters;
using kernel_header::Context;
using kernel_header::ContextOptions;
using kernel_header::KernelNotifications;
using kernel_header::Logger;
using kernel_header::ScriptPubkey;
using kernel_header::Transaction;
using kernel_header::TransactionOutput;

using kernel_header::AddLogLevelCategory;
using kernel_header::DisableLogCategory;
using kernel_header::DisableLogging;
using kernel_header::EnableLogCategory;
using kernel_header::SetLogAlwaysPrintCategoryLevel;
using kernel_header::SetLogSourcelocations;
using kernel_header::SetLogThreadnames;
using kernel_header::SetLogTimeMicros;
using kernel_header::SetLogTimestamps;

namespace {

BCLog::Level get_bclog_level(const kernel_LogLevel level)
{
    switch (level) {
    case kernel_LogLevel::kernel_LOG_INFO: {
        return BCLog::Level::Info;
    }
    case kernel_LogLevel::kernel_LOG_DEBUG: {
        return BCLog::Level::Debug;
    }
    case kernel_LogLevel::kernel_LOG_TRACE: {
        return BCLog::Level::Trace;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

BCLog::LogFlags get_bclog_flag(const kernel_LogCategory category)
{
    switch (category) {
    case kernel_LogCategory::kernel_LOG_BENCH: {
        return BCLog::LogFlags::BENCH;
    }
    case kernel_LogCategory::kernel_LOG_BLOCKSTORAGE: {
        return BCLog::LogFlags::BLOCKSTORAGE;
    }
    case kernel_LogCategory::kernel_LOG_COINDB: {
        return BCLog::LogFlags::COINDB;
    }
    case kernel_LogCategory::kernel_LOG_LEVELDB: {
        return BCLog::LogFlags::LEVELDB;
    }
    case kernel_LogCategory::kernel_LOG_MEMPOOL: {
        return BCLog::LogFlags::MEMPOOL;
    }
    case kernel_LogCategory::kernel_LOG_PRUNE: {
        return BCLog::LogFlags::PRUNE;
    }
    case kernel_LogCategory::kernel_LOG_RAND: {
        return BCLog::LogFlags::RAND;
    }
    case kernel_LogCategory::kernel_LOG_REINDEX: {
        return BCLog::LogFlags::REINDEX;
    }
    case kernel_LogCategory::kernel_LOG_VALIDATION: {
        return BCLog::LogFlags::VALIDATION;
    }
    case kernel_LogCategory::kernel_LOG_KERNEL: {
        return BCLog::LogFlags::KERNEL;
    }
    case kernel_LogCategory::kernel_LOG_ALL: {
        return BCLog::LogFlags::ALL;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

ChainType get_chain_type(kernel_ChainType chain_type)


{
    switch (chain_type) {
    case kernel_ChainType::kernel_CHAIN_TYPE_MAINNET: {
        return ChainType::MAIN;
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_TESTNET: {
        return ChainType::TESTNET;
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_TESTNET_4: {
        return ChainType::TESTNET4;
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_SIGNET: {
        return ChainType::SIGNET;
    }
    case kernel_ChainType::kernel_CHAIN_TYPE_REGTEST: {
        return ChainType::REGTEST;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

kernel_SynchronizationState cast_state(SynchronizationState state)
{
    switch (state) {
    case SynchronizationState::INIT_REINDEX:
        return kernel_SynchronizationState::kernel_INIT_REINDEX;
    case SynchronizationState::INIT_DOWNLOAD:
        return kernel_SynchronizationState::kernel_INIT_DOWNLOAD;
    case SynchronizationState::POST_INIT:
        return kernel_SynchronizationState::kernel_POST_INIT;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

kernel_Warning cast_kernel_warning(kernel::Warning warning)
{
    switch (warning) {
    case kernel::Warning::UNKNOWN_NEW_RULES_ACTIVATED:
        return kernel_Warning::kernel_LARGE_WORK_INVALID_CHAIN;
    case kernel::Warning::LARGE_WORK_INVALID_CHAIN:
        return kernel_Warning::kernel_LARGE_WORK_INVALID_CHAIN;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

const Transaction* cast_transaction(const kernel_Transaction* transaction)
{
    assert(transaction);
    return reinterpret_cast<const Transaction*>(transaction);
}

const ScriptPubkey* cast_script_pubkey(const kernel_ScriptPubkey* script_pubkey)
{
    assert(script_pubkey);
    return reinterpret_cast<const ScriptPubkey*>(script_pubkey);
}

const TransactionOutput* cast_transaction_output(const kernel_TransactionOutput* transaction_output)
{
    assert(transaction_output);
    return reinterpret_cast<const TransactionOutput*>(transaction_output);
}

Logger* cast_logger(kernel_LoggingConnection* logging_connection)
{
    assert(logging_connection);
    return reinterpret_cast<Logger*>(logging_connection);
}

const ContextOptions* cast_const_context_options(const kernel_ContextOptions* options)
{
    assert(options);
    return reinterpret_cast<const ContextOptions*>(options);
}

ContextOptions* cast_context_options(kernel_ContextOptions* options)
{
    assert(options);
    return reinterpret_cast<ContextOptions*>(options);
}

const ChainParameters* cast_const_chain_params(const kernel_ChainParameters* chain_params)
{
    assert(chain_params);
    return reinterpret_cast<const ChainParameters*>(chain_params);
}

ChainParameters* cast_chain_params(kernel_ChainParameters* chain_params)
{
    assert(chain_params);
    return reinterpret_cast<ChainParameters*>(chain_params);
}

Context* cast_context(kernel_Context* context)
{
    assert(context);
    return reinterpret_cast<Context*>(context);
}

class CallbackKernelNotifications : public KernelNotifications
{
private:
    kernel_NotificationInterfaceCallbacks m_cbs;

public:
    CallbackKernelNotifications(kernel_NotificationInterfaceCallbacks cbs)
        : m_cbs{cbs}
    {
    }

    void BlockTipHandler(SynchronizationState state, BlockIndex index) override
    {
        if (m_cbs.block_tip) m_cbs.block_tip((void*)m_cbs.user_data, cast_state(state), reinterpret_cast<const kernel_BlockIndex*>(&index));
    }
    void HeaderTipHandler(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        if (m_cbs.header_tip) m_cbs.header_tip((void*)m_cbs.user_data, cast_state(state), height, timestamp, presync);
    }
    void ProgressHandler(std::string_view title, int progress_percent, bool resume_possible) override
    {
        if (m_cbs.progress) m_cbs.progress((void*)m_cbs.user_data, title.data(), title.length(), progress_percent, resume_possible);
    }
    void WarningSetHandler(kernel::Warning id, const std::string_view message) override
    {
        if (m_cbs.warning_set) m_cbs.warning_set((void*)m_cbs.user_data, cast_kernel_warning(id), message.data(), message.length());
    }
    void WarningUnsetHandler(kernel::Warning id) override
    {
        if (m_cbs.warning_unset) m_cbs.warning_unset((void*)m_cbs.user_data, cast_kernel_warning(id));
    }
    void FlushErrorHandler(std::string_view message) override
    {
        if (m_cbs.flush_error) m_cbs.flush_error((void*)m_cbs.user_data, message.data(), message.length());
    }
    void FatalErrorHandler(std::string_view message) override
    {
        if (m_cbs.fatal_error) m_cbs.fatal_error((void*)m_cbs.user_data, message.data(), message.length());
    }
};

} // namespace

kernel_Transaction* kernel_transaction_create(const unsigned char* raw_transaction, size_t raw_transaction_len)
{
    try {
        return reinterpret_cast<kernel_Transaction*>(new Transaction(std::span{raw_transaction, raw_transaction_len}));
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

kernel_ScriptPubkey* kernel_script_pubkey_create(const unsigned char* script_pubkey, size_t script_pubkey_len)
{
    return reinterpret_cast<kernel_ScriptPubkey*>(new ScriptPubkey(std::span{script_pubkey, script_pubkey_len}));
}

void kernel_script_pubkey_destroy(kernel_ScriptPubkey* script_pubkey)
{
    if (script_pubkey) {
        delete cast_script_pubkey(script_pubkey);
    }
}

kernel_TransactionOutput* kernel_transaction_output_create(const kernel_ScriptPubkey* script_pubkey_, int64_t amount)
{
    const auto& script_pubkey{*cast_script_pubkey(script_pubkey_)};
    return reinterpret_cast<kernel_TransactionOutput*>(new TransactionOutput{script_pubkey, amount});
}

void kernel_transaction_output_destroy(kernel_TransactionOutput* output)
{
    if (output) {
        delete cast_transaction_output(output);
    }
}

bool kernel_verify_script(const kernel_ScriptPubkey* script_pubkey_,
                          const int64_t amount,
                          const kernel_Transaction* tx_to,
                          const kernel_TransactionOutput** spent_outputs_, size_t spent_outputs_len,
                          const unsigned int input_index,
                          const unsigned int flags)
{
    const auto& script_pubkey{*cast_script_pubkey(script_pubkey_)};
    const auto& tx{*cast_transaction(tx_to)};

    std::span<const TransactionOutput> spent_outputs;
    if (spent_outputs_ != nullptr) {
        const TransactionOutput* first_output{reinterpret_cast<const TransactionOutput*>(*spent_outputs_)};
        spent_outputs = {first_output, spent_outputs_len};
    }

    return script_pubkey.VerifyScript(
        amount,
        tx,
        spent_outputs,
        input_index,
        flags);
}

void kernel_add_log_level_category(const kernel_LogCategory category, const kernel_LogLevel level)
{
    AddLogLevelCategory(get_bclog_flag(category), get_bclog_level(level));
}

void kernel_enable_log_category(const kernel_LogCategory category)
{
    EnableLogCategory(get_bclog_flag(category));
}

void kernel_disable_log_category(const kernel_LogCategory category)
{
    DisableLogCategory(get_bclog_flag(category));
}

void kernel_disable_logging()
{
    DisableLogging();
}

void kernel_set_log_always_print_category_level(bool log_always_print_category_level)
{
    SetLogAlwaysPrintCategoryLevel(log_always_print_category_level);
}

void kernel_set_log_timestamps(bool log_timestamps)
{
    SetLogTimestamps(log_timestamps);
}

void kernel_set_log_time_micros(bool log_time_micros)
{
    SetLogTimeMicros(log_time_micros);
}

void kerenl_set_log_threadname(bool log_threadnames)
{
    SetLogThreadnames(log_threadnames);
}

void kernel_set_log_sourcelocations(bool log_sourcelocations)
{
    SetLogSourcelocations(log_sourcelocations);
}

kernel_LoggingConnection* kernel_logging_connection_create(kernel_LogCallback callback, void* user_data)
{
    auto logger = new Logger([callback, user_data](std::string_view message) { callback(user_data, message.data(), message.length()); });
    return reinterpret_cast<kernel_LoggingConnection*>(logger);
}

void kernel_logging_connection_destroy(kernel_LoggingConnection* logging_connection)
{
    if (logging_connection) {
        delete cast_logger(logging_connection);
    }
}

kernel_ChainParameters* kernel_chain_parameters_create(const kernel_ChainType chain_type)
{
    return reinterpret_cast<kernel_ChainParameters*>(new ChainParameters(get_chain_type(chain_type)));
}

void kernel_chain_parameters_destroy(kernel_ChainParameters* chain_parameters)
{
    if (chain_parameters) {
        delete cast_chain_params(chain_parameters);
    }
}

kernel_ContextOptions* kernel_context_options_create()
{
    return reinterpret_cast<kernel_ContextOptions*>(new ContextOptions{});
}

void kernel_context_options_set_chainparams(kernel_ContextOptions* options_, const kernel_ChainParameters* chain_parameters)
{
    auto options{cast_context_options(options_)};
    auto chain_params{cast_const_chain_params(chain_parameters)};
    options->SetChainParameters(*chain_params);
}

void kernel_context_options_set_notifications(kernel_ContextOptions* options_, kernel_NotificationInterfaceCallbacks notifications)
{
    auto options{cast_context_options(options_)};
    options->SetNotifications(std::make_shared<CallbackKernelNotifications>(notifications));
}

void kernel_context_options_destroy(kernel_ContextOptions* options)
{
    if (options) {
        delete cast_context_options(options);
    }
}

kernel_Context* kernel_context_create(const kernel_ContextOptions* options_)
{
    auto options{cast_const_context_options(options_)};
    Context* context{nullptr};
    if (!options) {
        context = new Context{};
    } else {
        context = new Context{*options};
    }
    return reinterpret_cast<kernel_Context*>(context);
}

void kernel_context_destroy(kernel_Context* context_)
{
    delete cast_context(context_);
}
