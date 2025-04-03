// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
#define BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H

#include <kernel/bitcoinkernel.h>

#include <functional>
#include <memory>
#include <optional>
#include <string_view>
#include <span>

namespace kernel_header {

class TransactionOutput;
class Context;
class ContextOptions;

class Transaction
{
private:
    struct TransactionImpl;
    std::unique_ptr<TransactionImpl> m_impl;

public:
    explicit Transaction(std::span<const unsigned char> raw_transaction) noexcept;
    ~Transaction();

    /** Check whether this Transaction object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }

    friend class ScriptPubkey;
};

class ScriptPubkey
{
private:
    struct ScriptPubkeyImpl;
    std::unique_ptr<ScriptPubkeyImpl> m_impl;

public:
    explicit ScriptPubkey(std::span<const unsigned char> script_pubkey) noexcept;
    explicit ScriptPubkey(std::unique_ptr<ScriptPubkeyImpl> impl) noexcept;
    ~ScriptPubkey();

    ScriptPubkey(ScriptPubkey&& other) noexcept;

    /** Check whether this ScriptPubkey object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }

    std::vector<unsigned char> GetScriptPubkeyData() const noexcept;

    int VerifyScript(
        const int64_t amount,
        const Transaction& tx_to,
        std::span<const TransactionOutput> spent_outputs,
        const unsigned int input_index,
        const unsigned int flags,
        kernel_ScriptVerifyStatus& status) const noexcept;

    friend class TransactionOutput;
};

class TransactionOutput
{
private:
    struct TransactionOutputImpl;
    std::unique_ptr<TransactionOutputImpl> m_impl;

public:
    explicit TransactionOutput(const ScriptPubkey& script_pubkey, int64_t amount) noexcept;
    explicit TransactionOutput(std::unique_ptr<TransactionOutputImpl> impl) noexcept;
    ~TransactionOutput();

    TransactionOutput(TransactionOutput&& other) noexcept;
    TransactionOutput& operator=(TransactionOutput&& other) noexcept;

    ScriptPubkey GetScriptPubkey() const noexcept;

    int64_t GetOutputAmount() const noexcept;

    /** Check whether this TransactionOutput object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }

    friend class ScriptPubkey;
    friend class BlockUndo;
};

void AddLogLevelCategory(const kernel_LogCategory category, const kernel_LogLevel level);

void EnableLogCategory(const kernel_LogCategory category);

void DisableLogCategory(const kernel_LogCategory category);

void DisableLogging();

class Logger
{
private:
    struct LoggerImpl;
    std::unique_ptr<LoggerImpl> m_impl;

public:
    explicit Logger(std::function<void(std::string_view)> callback, const kernel_LoggingOptions& logging_options) noexcept;
    ~Logger();

    /** Check whether this Logger object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }
};

class BlockIndex
{
private:
    struct BlockIndexImpl;
    std::unique_ptr<BlockIndexImpl> m_impl;

public:
    BlockIndex(std::unique_ptr<BlockIndexImpl> impl) noexcept;
    ~BlockIndex() noexcept;

    // It is permitted to copy a BlockIndex. Its data is always valid for as long as the object it was retrieved is valid.
    BlockIndex(const BlockIndex& other) noexcept;
    BlockIndex& operator=(const BlockIndex& other) noexcept;

    std::optional<BlockIndex> GetPreviousBlockIndex() const noexcept;

    int32_t GetHeight() const noexcept;

    kernel_BlockHash GetHash() const noexcept;

    /** Check whether this BlockIndex object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }

    friend class KernelNotifications;
    friend class ChainstateManager;
};

class KernelNotifications
{
private:
    struct KernelNotificationsImpl;
    std::unique_ptr<KernelNotificationsImpl> m_impl;

public:
    explicit KernelNotifications() noexcept;
    virtual ~KernelNotifications() noexcept;

    virtual void BlockTipHandler(kernel_SynchronizationState state, BlockIndex index) {}

    virtual void HeaderTipHandler(kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {}

    virtual void ProgressHandler(std::string_view title, int progress_percent, bool resume_possible) {}

    virtual void WarningSetHandler(kernel_Warning warning, std::string_view message) {}

    virtual void WarningUnsetHandler(kernel_Warning warning) {}

    virtual void FlushErrorHandler(std::string_view error) {}

    virtual void FatalErrorHandler(std::string_view error) {}

    friend class ContextOptions;
    friend class ChainstateManagerOptions;
};

class ChainParameters
{
private:
    struct ChainParametersImpl;
    std::unique_ptr<ChainParametersImpl> m_impl;

public:
    explicit ChainParameters(const kernel_ChainType chain_type) noexcept;
    ~ChainParameters() noexcept;

    friend class ContextOptions;
};

class UnownedBlock
{
private:
	struct UnownedBlockImpl;
	std::unique_ptr<UnownedBlockImpl> m_impl;

public:
	explicit UnownedBlock(std::unique_ptr<UnownedBlockImpl> impl) noexcept;
	~UnownedBlock() noexcept;

	friend class ValidationInterface;

    std::vector<std::byte> GetBlockData() const noexcept;
};

class BlockValidationState
{
private:
	struct BlockValidationStateImpl;
	std::unique_ptr<BlockValidationStateImpl> m_impl;

public:
	explicit BlockValidationState(std::unique_ptr<BlockValidationStateImpl> impl) noexcept;
	~BlockValidationState() noexcept;

    kernel_ValidationMode ValidationMode() const noexcept;
    kernel_BlockValidationResult BlockValidationResult() const noexcept;

	friend class ValidationInterface;
};

class ValidationInterface
{
private:
	struct ValidationInterfaceImpl;
	std::unique_ptr<ValidationInterfaceImpl> m_impl;

public:
	explicit ValidationInterface() noexcept;
	virtual ~ValidationInterface() noexcept;

	virtual void BlockCheckedHandler(const UnownedBlock block, const BlockValidationState stateIn) {}

	friend class Context;
};

class ContextOptions
{
private:
    struct ContextOptionsImpl;
    std::unique_ptr<ContextOptionsImpl> m_impl;

public:
    explicit ContextOptions() noexcept;
    ~ContextOptions() noexcept;

    void SetChainParameters(const ChainParameters& chain_parameters) noexcept;

    void SetNotifications(std::shared_ptr<KernelNotifications> notifications) noexcept;

    void SetValidationInterface(std::shared_ptr<ValidationInterface> validation_interface) noexcept;

    friend class Context;
};

class Context
{
private:
    struct ContextImpl;
    std::unique_ptr<ContextImpl> m_impl;

public:
    explicit Context(const ContextOptions& opts) noexcept;
    Context() noexcept;
    ~Context() noexcept;

    /** Check whether this Context object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }

	bool Interrupt() noexcept;

    friend class ChainstateManagerOptions;
    friend class ChainstateManager;
};

class ChainstateManagerOptions
{
private:
    struct ChainstateManagerOptionsImpl;
    std::unique_ptr<ChainstateManagerOptionsImpl> m_impl;

public:
    explicit ChainstateManagerOptions(const Context& context, const std::string& data_dir, const std::string& blocks_dir) noexcept;
    ~ChainstateManagerOptions() noexcept;

    /** Check whether this ChainstateManagerOptions object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }

    void SetWorkerThreads(int worker_threads) const noexcept;

	bool SetWipeDbs(bool wipe_block_tree, bool wipe_chainstate) const noexcept;

   	void SetBlockTreeDbInMemory(bool block_tree_db_in_memory) const noexcept;

    void SetChainstateDbInMemory(bool chainstate_db_in_memory) const noexcept;

    friend class ChainstateManager;
};

class Block
{
private:
    struct BlockImpl;
    std::unique_ptr<BlockImpl> m_impl;

public:
    explicit Block(const std::span<const unsigned char> raw_block) noexcept;
    explicit Block(std::unique_ptr<BlockImpl> impl) noexcept;
    ~Block() noexcept;

    Block(Block&& other) noexcept;

    std::vector<std::byte> GetBlockData() const noexcept;

    /** Check whether this Block object is valid. */
    explicit operator bool() const noexcept { return bool{m_impl}; }

    friend class ChainstateManager;
};

class BlockUndo
{
private:
    struct BlockUndoImpl;
    std::unique_ptr<BlockUndoImpl> m_impl;

public:
    const uint64_t m_size;

    explicit BlockUndo(std::unique_ptr<BlockUndoImpl> impl) noexcept;
    ~BlockUndo() noexcept;

    BlockUndo(BlockUndo&& other) noexcept;

    uint64_t GetTxOutSize(uint64_t index) const noexcept;

    TransactionOutput GetTxUndoPrevoutByIndex(uint64_t tx_undo_index, uint64_t tx_prevout_index) const noexcept;

    friend class ChainstateManager;
};

class ChainstateManager
{
private:
    struct ChainstateManagerImpl;
    std::unique_ptr<ChainstateManagerImpl> m_impl;
    const Context& m_context;

public:
    explicit ChainstateManager(const Context& context, const ChainstateManagerOptions& chainstatemanager_options) noexcept;
    ~ChainstateManager() noexcept;

    bool ImportBlocks(const std::span<const std::string> paths) const noexcept;

    bool ProcessBlock(const Block& block, bool& new_block) const noexcept;

    BlockIndex GetBlockIndexFromTip() const noexcept;

    BlockIndex GetBlockIndexFromGenesis() const noexcept;

    std::optional<BlockIndex> GetBlockIndexByHash(const kernel_BlockHash& block_hash) const noexcept;

    std::optional<BlockIndex> GetBlockIndexByHeight(int height) const noexcept;

    std::optional<BlockIndex> GetNextBlockIndex(const BlockIndex& block_index) const noexcept;

    std::optional<Block> ReadBlock(const BlockIndex& block_index) const noexcept;

    std::optional<BlockUndo> ReadBlockUndo(const BlockIndex& block_index) const noexcept;

    /** Check whether this ChainMan object is valid. */
    explicit operator bool() const noexcept { return m_impl != nullptr; }
};

} // namespace kernel_header

#endif // BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
