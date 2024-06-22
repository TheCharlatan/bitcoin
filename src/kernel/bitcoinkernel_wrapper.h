// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
#define BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H

#include <kernel/bitcoinkernel.h>

#include <memory>
#include <span>
#include <string>

int verify_script(const std::span<const unsigned char> script_pubkey,
                  int64_t amount,
                  const std::span<const unsigned char> tx_to,
                  const std::span<const kernel_TransactionOutput> spent_outputs,
                  unsigned int input_index,
                  unsigned int flags,
                  kernel_ScriptVerifyStatus& status) noexcept
{
    auto spent_outputs_ptr = spent_outputs.size() > 0 ? spent_outputs.data() : nullptr;
    return kernel_verify_script(
        script_pubkey.data(), script_pubkey.size(),
        amount,
        tx_to.data(), tx_to.size(),
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
        void operator()(const kernel_Notifications* ptr) const
        {
            kernel_notifications_destroy(ptr);
        }
    };

    kernel_NotificationInterfaceCallbacks MakeCallbacks()
    {
        return kernel_NotificationInterfaceCallbacks{
            .user_data = this,
            .block_tip = [](void* user_data, kernel_SynchronizationState state, kernel_BlockIndex* index) {
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

    std::unique_ptr<const kernel_Notifications, Deleter> m_notifications;

public:
    KernelNotifications() : m_notifications{kernel_notifications_create(MakeCallbacks())} {}

    virtual ~KernelNotifications() = default;

    virtual void BlockTipHandler(kernel_SynchronizationState state, kernel_BlockIndex* index) {}

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

    bool SetChainParams(ChainParams& chain_params) const noexcept
    {
        return kernel_context_options_set(
            m_options.get(),
            kernel_ContextOptionType::kernel_CHAIN_PARAMETERS_OPTION,
            chain_params.m_chain_params.get());
    }

    template <typename T>
    bool SetNotifications(KernelNotifications<T>& notifications) const noexcept
    {
        return kernel_context_options_set(
            m_options.get(),
            kernel_ContextOptionType::kernel_NOTIFICATIONS_OPTION,
            notifications.m_notifications.get());
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

class ChainstateManagerOptions
{
private:
    struct Deleter {
        void operator()(kernel_ChainstateManagerOptions* ptr) const
        {
            kernel_chainstate_manager_options_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_ChainstateManagerOptions, Deleter> m_options;

public:
    ChainstateManagerOptions(const Context& context, const std::string& data_dir) noexcept
        : m_options{kernel_chainstate_manager_options_create(context.m_context.get(), data_dir.c_str())}
    {
    }

    /** Check whether this ChainstateManagerOptions object is valid. */
    explicit operator bool() const noexcept { return bool{m_options}; }

    friend class ChainMan;
};

class BlockManagerOptions
{
private:
    struct Deleter {
        void operator()(kernel_BlockManagerOptions* ptr) const
        {
            kernel_block_manager_options_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_BlockManagerOptions, Deleter> m_options;

public:
    BlockManagerOptions(const Context& context, const std::string& data_dir) noexcept
        : m_options{kernel_block_manager_options_create(context.m_context.get(), data_dir.c_str())}
    {
    }

    /** Check whether this BlockManagerOptions object is valid. */
    explicit operator bool() const noexcept { return bool{m_options}; }

    friend class ChainMan;
};

class ChainstateLoadOptions
{
private:
    struct Deleter {
        void operator()(kernel_ChainstateLoadOptions* ptr) const
        {
            kernel_chainstate_load_options_destroy(ptr);
        }
    };

    const std::unique_ptr<kernel_ChainstateLoadOptions, Deleter> m_options;

public:
    ChainstateLoadOptions() noexcept
        : m_options{kernel_chainstate_load_options_create()}
    {
    }

    void SetWipeBlockTreeDb(bool wipe_block_tree) const noexcept
    {
        kernel_chainstate_load_options_set(m_options.get(),
                                           kernel_ChainstateLoadOptionType::kernel_WIPE_BLOCK_TREE_DB_CHAINSTATE_LOAD_OPTION,
                                           wipe_block_tree);
    }

    void SetWipeChainstateDb(bool wipe_chainstate) const noexcept
    {
        kernel_chainstate_load_options_set(m_options.get(),
                                           kernel_ChainstateLoadOptionType::kernel_WIPE_CHAINSTATE_DB_CHAINSTATE_LOAD_OPTION,
                                           wipe_chainstate);
    }

    void SetChainstateDbInMemory(bool chainstate_db_in_memory) const noexcept
    {
        kernel_chainstate_load_options_set(m_options.get(),
                                           kernel_ChainstateLoadOptionType::kernel_CHAINSTATE_DB_IN_MEMORY_CHAINSTATE_LOAD_OPTION,
                                           chainstate_db_in_memory);
    }

    void SetBlockTreeDbInMemory(bool block_tree_db_in_memory) const noexcept
    {
        kernel_chainstate_load_options_set(m_options.get(),
                                           kernel_ChainstateLoadOptionType::kernel_BLOCK_TREE_DB_IN_MEMORY_CHAINSTATE_LOAD_OPTION,
                                           block_tree_db_in_memory);
    }

    friend class ChainMan;
};

class Block
{
private:
    struct Deleter {
        void operator()(kernel_Block* ptr) const
        {
            kernel_block_destroy(ptr);
        }
    };

    const std::unique_ptr<kernel_Block, Deleter> m_block;

public:
    Block(const std::span<const unsigned char> raw_block) noexcept
        : m_block{kernel_block_create(raw_block.data(), raw_block.size())}
    {
    }

    /** Check whether this Block object is valid. */
    explicit operator bool() const noexcept { return bool{m_block}; }

    Block(kernel_Block* block) noexcept : m_block{block} {}

    friend class ChainMan;
};

class ChainMan
{
private:
    kernel_ChainstateManager* m_chainman;
    const Context& m_context;

public:
    ChainMan(const Context& context, const ChainstateManagerOptions& chainman_opts, const BlockManagerOptions& blockman_opts) noexcept
        : m_chainman{kernel_chainstate_manager_create(chainman_opts.m_options.get(), blockman_opts.m_options.get(), context.m_context.get())},
          m_context{context}
    {
    }

    /** Check whether this ChainMan object is valid. */
    explicit operator bool() const noexcept { return m_chainman != nullptr; }

    ChainMan(const ChainMan&) = delete;
    ChainMan& operator=(const ChainMan&) = delete;

    bool LoadChainstate(const ChainstateLoadOptions& chainstate_load_opts) const noexcept
    {
        return kernel_chainstate_manager_load_chainstate(m_context.m_context.get(), chainstate_load_opts.m_options.get(), m_chainman);
    }

    bool ProcessBlock(const Block& block, kernel_ProcessBlockStatus& status) const noexcept
    {
        return kernel_chainstate_manager_process_block(m_context.m_context.get(), m_chainman, block.m_block.get(), &status);
    }

    ~ChainMan()
    {
        kernel_chainstate_manager_destroy(m_chainman, m_context.m_context.get());
    }
};

#endif // BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
