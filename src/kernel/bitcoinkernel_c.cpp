// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <kernel/bitcoinkernel.hpp>

#include <cassert>
#include <cstddef>
#include <cstring>
#include <exception>
#include <span>
#include <string_view>

using kernel_header::BlockIndex;
using kernel_header::ChainParameters;
using kernel_header::Context;
using kernel_header::ContextOptions;
using kernel_header::KernelNotifications;
using kernel_header::Logger;
using kernel_header::Transaction;
using kernel_header::ScriptPubkey;
using kernel_header::TransactionOutput;

using kernel_header::AddLogLevelCategory;
using kernel_header::DisableLogCategory;
using kernel_header::DisableLogging;
using kernel_header::EnableLogCategory;

namespace {

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

    void BlockTipHandler(kernel_SynchronizationState state, BlockIndex index) override
    {
        if (m_cbs.block_tip) m_cbs.block_tip((void*)m_cbs.user_data, state, reinterpret_cast<const kernel_BlockIndex*>(&index));
    }
    void HeaderTipHandler(kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        if (m_cbs.header_tip) m_cbs.header_tip((void*)m_cbs.user_data, state, height, timestamp, presync);
    }
    void ProgressHandler(std::string_view title, int progress_percent, bool resume_possible) override
    {
        if (m_cbs.progress) m_cbs.progress((void*)m_cbs.user_data, title.data(), title.length(), progress_percent, resume_possible);
    }
    void WarningSetHandler(kernel_Warning id, const std::string_view message) override
    {
        if (m_cbs.warning_set) m_cbs.warning_set((void*)m_cbs.user_data, id, message.data(), message.length());
    }
    void WarningUnsetHandler(kernel_Warning id) override
    {
        if (m_cbs.warning_unset) m_cbs.warning_unset((void*)m_cbs.user_data, id);
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
                          const unsigned int flags,
                          kernel_ScriptVerifyStatus* status)
{
    const auto& script_pubkey{*cast_script_pubkey(script_pubkey_)};
    const auto& tx{*cast_transaction(tx_to)};

    const TransactionOutput* first_output{reinterpret_cast<const TransactionOutput*>(*spent_outputs_)};
    std::span<const TransactionOutput> spent_outputs{first_output, spent_outputs_len};

    return script_pubkey.VerifyScript(
                        amount,
                        tx,
                        spent_outputs,
                        input_index,
                        flags,
                        *status);
}

void kernel_add_log_level_category(const kernel_LogCategory category, const kernel_LogLevel level)
{
    AddLogLevelCategory(category, level);
}

void kernel_enable_log_category(const kernel_LogCategory category)
{
    EnableLogCategory(category);
}

void kernel_disable_log_category(const kernel_LogCategory category)
{
    DisableLogCategory(category);
}

void kernel_disable_logging()
{
    DisableLogging();
}

kernel_LoggingConnection* kernel_logging_connection_create(kernel_LogCallback callback,
                                                           void* user_data,
                                                           const kernel_LoggingOptions options)
{
    auto logger = new Logger([callback, user_data](std::string_view message) { callback(user_data, message.data(), message.length()); }, options);
    return reinterpret_cast<kernel_LoggingConnection*>(logger);
}

kernel_ChainParameters* kernel_chain_parameters_create(const kernel_ChainType chain_type)
{
    return reinterpret_cast<kernel_ChainParameters*>(new ChainParameters(chain_type));
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
