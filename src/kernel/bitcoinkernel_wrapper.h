// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
#define BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H

#include <kernel/bitcoinkernel.h>

#include <memory>
#include <span>
#include <vector>

class Transaction
{
private:
    struct Deleter {
        void operator()(kernel_Transaction* ptr) const
        {
            kernel_transaction_destroy(ptr);
        }
    };

public:
    std::unique_ptr<kernel_Transaction, Deleter> m_transaction;

    Transaction(std::span<const unsigned char> raw_transaction) noexcept
        : m_transaction{kernel_transaction_create(raw_transaction.data(), raw_transaction.size())}
    {
    }

    /** Check whether this Transaction object is valid. */
    explicit operator bool() const noexcept { return bool{m_transaction}; }
};

class ScriptPubkey
{
private:
    struct Deleter {
        void operator()(kernel_ScriptPubkey* ptr) const
        {
            kernel_script_pubkey_destroy(ptr);
        }
    };

public:
    std::unique_ptr<kernel_ScriptPubkey, Deleter> m_script_pubkey;

    ScriptPubkey(std::span<const unsigned char> script_pubkey) noexcept
        : m_script_pubkey{kernel_script_pubkey_create(script_pubkey.data(), script_pubkey.size())}
    {
    }

    /** Check whether this ScriptPubkey object is valid. */
    explicit operator bool() const noexcept { return bool{m_script_pubkey}; }
};

class TransactionOutput
{
private:
    struct Deleter {
        void operator()(kernel_TransactionOutput* ptr) const
        {
            kernel_transaction_output_destroy(ptr);
        }
    };

public:
    std::unique_ptr<kernel_TransactionOutput, Deleter> m_transaction_output;

    TransactionOutput(const ScriptPubkey& script_pubkey, int64_t amount) noexcept
        : m_transaction_output{kernel_transaction_output_create(script_pubkey.m_script_pubkey.get(), amount)}
    {
    }
};

int verify_script(const ScriptPubkey& script_pubkey,
                  int64_t amount,
                  const Transaction& tx_to,
                  const std::span<const TransactionOutput> spent_outputs,
                  unsigned int input_index,
                  unsigned int flags,
                  kernel_ScriptVerifyStatus& status) noexcept
{
    const kernel_TransactionOutput** spent_outputs_ptr = nullptr;
    std::vector<const kernel_TransactionOutput*> raw_spent_outputs;
    if (spent_outputs.size() > 0) {
        raw_spent_outputs.reserve(spent_outputs.size());

        for (const auto& output: spent_outputs) {
            raw_spent_outputs.push_back(output.m_transaction_output.get());
        }
        spent_outputs_ptr = raw_spent_outputs.data();
    }
    return kernel_verify_script(
        script_pubkey.m_script_pubkey.get(),
        amount,
        tx_to.m_transaction.get(),
        spent_outputs_ptr, spent_outputs.size(),
        input_index,
        flags,
        &status);
}

template <typename T>
concept Log = requires(T a, const char* message) {
    { a.LogMessage(message) } -> std::same_as<void>;
};

template <Log T>
class Logger
{
private:
    struct Deleter {
        void operator()(kernel_LoggingConnection* ptr) const
        {
            kernel_logging_connection_destroy(ptr);
        }
    };

    std::unique_ptr<T> m_log;
    std::unique_ptr<kernel_LoggingConnection, Deleter> m_connection;

public:
    Logger(std::unique_ptr<T> log, const kernel_LoggingOptions& logging_options) noexcept
        : m_log{std::move(log)},
          m_connection{kernel_logging_connection_create(
              [](void* user_data, const char* message) { static_cast<T*>(user_data)->LogMessage(message); },
              m_log.get(),
              logging_options)}
    {
    }

    /** Check whether this Logger object is valid. */
    explicit operator bool() const noexcept { return bool{m_connection}; }
};

template <typename T>
class KernelNotifications
{
private:
    struct Deleter {
        void operator()(kernel_Notifications* ptr) const
        {
            kernel_notifications_destroy(ptr);
        }
    };

    kernel_NotificationInterfaceCallbacks MakeCallbacks()
    {
        return kernel_NotificationInterfaceCallbacks{
            .user_data = this,
            .block_tip = [](void* user_data, kernel_SynchronizationState state, const kernel_BlockIndex* index) {
                static_cast<T*>(user_data)->BlockTipHandler(state, index);
            },
            .header_tip = [](void* user_data, kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {
                static_cast<T*>(user_data)->HeaderTipHandler(state, height, timestamp, presync);
            },
            .progress = [](void* user_data, const char* title, int progress_percent, bool resume_possible) {
                static_cast<T*>(user_data)->ProgressHandler(title, progress_percent, resume_possible);
            },
            .warning_set = [](void* user_data, kernel_Warning warning, const char* message) {
                static_cast<T*>(user_data)->WarningSetHandler(warning, message);
            },
            .warning_unset = [](void* user_data, kernel_Warning warning) { static_cast<T*>(user_data)->WarningUnsetHandler(warning); },
            .flush_error = [](void* user_data, const char* error) { static_cast<T*>(user_data)->FlushErrorHandler(error); },
            .fatal_error = [](void* user_data, const char* error) { static_cast<T*>(user_data)->FatalErrorHandler(error); },
        };
    }

    std::unique_ptr<kernel_Notifications, Deleter> m_notifications;

public:
    KernelNotifications() : m_notifications{kernel_notifications_create(MakeCallbacks())} {}

    virtual ~KernelNotifications() = default;

    virtual void BlockTipHandler(kernel_SynchronizationState state, const kernel_BlockIndex* index) {}

    virtual void HeaderTipHandler(kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {}

    virtual void ProgressHandler(const char* title, int progress_percent, bool resume_possible) {}

    virtual void WarningSetHandler(kernel_Warning warning, const char* message) {}

    virtual void WarningUnsetHandler(kernel_Warning warning) {}

    virtual void FlushErrorHandler(const char* error) {}

    virtual void FatalErrorHandler(const char* error) {}

    friend class ContextOptions;
};

class ChainParams
{
private:
    struct Deleter {
        void operator()(const kernel_ChainParameters* ptr) const
        {
            kernel_chain_parameters_destroy(ptr);
        }
    };

    std::unique_ptr<const kernel_ChainParameters, Deleter> m_chain_params;

public:
    ChainParams(kernel_ChainType chain_type) noexcept : m_chain_params{kernel_chain_parameters_create(chain_type)} {}

    friend class ContextOptions;
};

class ContextOptions
{
private:
    struct Deleter {
        void operator()(kernel_ContextOptions* ptr) const
        {
            kernel_context_options_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_ContextOptions, Deleter> m_options;

public:
    ContextOptions() noexcept : m_options{kernel_context_options_create()} {}

    void SetChainParams(ChainParams& chain_params) const noexcept
    {
        kernel_context_options_set_chainparams(m_options.get(), chain_params.m_chain_params.get());
    }

    template <typename T>
    void SetNotifications(KernelNotifications<T>& notifications) const noexcept
    {
        kernel_context_options_set_notifications(m_options.get(), notifications.m_notifications.get());
    }

    friend class Context;
};

class Context
{
private:
    struct Deleter {
        void operator()(kernel_Context* ptr) const
        {
            kernel_context_destroy(ptr);
        }
    };

public:
    std::unique_ptr<kernel_Context, Deleter> m_context;

    Context(ContextOptions& opts) noexcept
        : m_context{kernel_context_create(opts.m_options.get())}
    {
    }

    Context() noexcept
        : m_context{kernel_context_create(ContextOptions{}.m_options.get())}
    {
    }

    /** Check whether this Context object is valid. */
    explicit operator bool() const noexcept { return bool{m_context}; }
};

#endif // BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H