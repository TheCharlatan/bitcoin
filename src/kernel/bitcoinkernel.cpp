// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITCOINKERNEL_BUILD

#include <kernel/bitcoinkernel.hpp>

#include <kernel/bitcoinkernel.h>

#include <chain.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <kernel/caches.h>
#include <kernel/chainparams.h>
#include <kernel/chainstatemanager_opts.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/notifications_interface.h>
#include <kernel/warning.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <undo.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/translation.h>
#include <util/task_runner.h>
#include <validation.h>
#include <validationinterface.h>

#include <cstring>
#include <exception>
#include <functional>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using util::ImmediateTaskRunner;

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context kernel_context_static{};

namespace kernel_header {

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

    ScriptPubkeyImpl(CScript script_pubkey)
        : m_script_pubkey{std::move(script_pubkey)}
    {
    }
};

ScriptPubkey::ScriptPubkey(std::span<const unsigned char> script_pubkey) noexcept
    : m_impl{std::make_unique<ScriptPubkey::ScriptPubkeyImpl>(script_pubkey)}
{}

ScriptPubkey::ScriptPubkey(std::unique_ptr<ScriptPubkeyImpl> impl) noexcept
    : m_impl{std::move(impl)}
{}


ScriptPubkey::ScriptPubkey(ScriptPubkey&& other) noexcept
    : m_impl{std::move(other.m_impl)}
{}

std::vector<unsigned char> ScriptPubkey::GetScriptPubkeyData() const noexcept
{
    return std::vector<unsigned char>(m_impl->m_script_pubkey.begin(), m_impl->m_script_pubkey.end());
}

ScriptPubkey::~ScriptPubkey() = default;

struct Transaction::TransactionImpl {
    CTransaction m_transaction;
};

Transaction::Transaction(std::span<const unsigned char> raw_transaction) noexcept
{
    try {
        DataStream stream{raw_transaction};
        m_impl = std::make_unique<Transaction::TransactionImpl>(CTransaction{deserialize, TX_WITH_WITNESS, stream});
    } catch (std::exception) {
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

    TransactionOutputImpl(CTxOut tx_out) : m_tx_out{tx_out} {}
};

TransactionOutput::TransactionOutput(const ScriptPubkey& script_pubkey, int64_t amount) noexcept
{
    m_impl = std::make_unique<TransactionOutput::TransactionOutputImpl>(CAmount{amount}, script_pubkey);
}

TransactionOutput::TransactionOutput(std::unique_ptr<TransactionOutputImpl> impl) noexcept
    : m_impl{std::move(impl)}
{
}

ScriptPubkey TransactionOutput::GetScriptPubkey() const noexcept
{
    return ScriptPubkey(std::make_unique<ScriptPubkey::ScriptPubkeyImpl>(m_impl->m_tx_out.scriptPubKey));
}

int64_t TransactionOutput::GetOutputAmount() const noexcept
{
    return m_impl->m_tx_out.nValue;
}

TransactionOutput::~TransactionOutput() = default;

TransactionOutput::TransactionOutput(TransactionOutput&& other) noexcept = default;
TransactionOutput& TransactionOutput::operator=(TransactionOutput&& other) noexcept = default;


/** Check that all specified flags are part of the libbitcoinkernel interface. */
bool verify_flags(unsigned int flags)
{
    return (flags & ~(kernel_SCRIPT_FLAGS_VERIFY_ALL)) == 0;
}

int ScriptPubkey::VerifyScript(
    const int64_t amount_,
    const Transaction& tx_to,
    std::span<const TransactionOutput> spent_outputs,
    const unsigned int input_index,
    const unsigned int flags,
    kernel_ScriptVerifyStatus& status) const noexcept
{
    const CAmount amount{amount_};

    if (!verify_flags(flags)) {
        status = kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS;
        return false;
    }

    if (!is_valid_flag_combination(flags)) {
        status = kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS_COMBINATION;
        return false;
    }

    if (flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT && spent_outputs.empty()) {
        status = kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED;
        return false;
    }

    const CTransaction& tx = tx_to.m_impl->m_transaction;
    std::vector<CTxOut> spent_outputs_vec;
    if (!spent_outputs.empty()) {
        if (spent_outputs.size() != tx.vin.size()) {
            status = kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_MISMATCH;
            return false;
        }
        spent_outputs_vec.reserve(spent_outputs.size());
        for (const auto& spent_output : spent_outputs) {
            spent_outputs_vec.push_back(spent_output.m_impl->m_tx_out);
        }
    }

    if (input_index >= tx.vin.size()) {
        status = kernel_SCRIPT_VERIFY_ERROR_TX_INPUT_INDEX;
        return false;
    }
    PrecomputedTransactionData txdata{tx};

    if (!spent_outputs_vec.empty() && flags & kernel_SCRIPT_FLAGS_VERIFY_TAPROOT) {
        txdata.Init(tx, std::move(spent_outputs_vec));
    }

    return ::VerifyScript(tx.vin[input_index].scriptSig,
                        m_impl->m_script_pubkey,
                        &tx.vin[input_index].scriptWitness,
                        flags,
                        TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
                        nullptr);
}

void AddLogLevelCategory(const kernel_LogCategory category, const kernel_LogLevel level)
{
    if (category == kernel_LogCategory::kernel_LOG_ALL) {
        LogInstance().SetLogLevel(get_bclog_level(level));
    }

    LogInstance().AddCategoryLogLevel(get_bclog_flag(category), get_bclog_level(level));
}

void EnableLogCategory(const kernel_LogCategory category)
{
    LogInstance().EnableCategory(get_bclog_flag(category));
}

void DisableLogCategory(const kernel_LogCategory category)
{
    LogInstance().DisableCategory(get_bclog_flag(category));
}

void DisableLogging()
{
    LogInstance().DisableLogging();
}

struct Logger::LoggerImpl {
    std::list<std::function<void(const std::string&)>>::iterator m_connection;

    LoggerImpl(std::function<void(std::string_view)> callback, const kernel_LoggingOptions options)
    {
        LogInstance().m_log_timestamps = options.log_timestamps;
        LogInstance().m_log_time_micros = options.log_time_micros;
        LogInstance().m_log_threadnames = options.log_threadnames;
        LogInstance().m_log_sourcelocations = options.log_sourcelocations;
        LogInstance().m_always_print_category_level = options.always_print_category_levels;

        m_connection = LogInstance().PushBackCallback([callback](const std::string& str) { callback(str); });

        try {
            // Only start logging if we just added the connection.
            if (LogInstance().NumConnections() == 1 && !LogInstance().StartLogging()) {
                LogError("Logger start failed.");
                LogInstance().DeleteCallback(m_connection);
            }
        } catch (std::exception& e) {
            LogError("Logger start failed.");
            LogInstance().DeleteCallback(m_connection);
            throw e;
        }

        LogDebug(BCLog::KERNEL, "Logger connected.");
    }

    ~LoggerImpl()
    {
        LogDebug(BCLog::KERNEL, "Logger disconnected.");
        LogInstance().DeleteCallback(m_connection);

        // We are not buffering if we have a connection, so check that it is not the
        // last available connection.
        if (!LogInstance().Enabled()) {
            LogInstance().DisconnectTestLogger();
        }
    }
};

Logger::Logger(std::function<void(std::string_view)> callback, const kernel_LoggingOptions& logging_options) noexcept
{
    try {
        m_impl = std::make_unique<LoggerImpl>(callback, logging_options);
    } catch (std::exception&) {
        m_impl = nullptr;
    }
}

Logger::~Logger() = default;

struct BlockIndex::BlockIndexImpl
{
    CBlockIndex& m_block_index;

    BlockIndexImpl(CBlockIndex& block_index) : m_block_index{block_index} {}

    friend struct KernelNotificationsImpl;
};

BlockIndex::BlockIndex(std::unique_ptr<BlockIndex::BlockIndexImpl> impl) noexcept
    : m_impl{std::move(impl)}
{
}

BlockIndex::BlockIndex(const BlockIndex& other) noexcept
    : m_impl{other.m_impl ? std::make_unique<BlockIndexImpl>(other.m_impl->m_block_index) : nullptr}
{
}

BlockIndex& BlockIndex::operator=(const BlockIndex& other) noexcept
{
    if (this != &other) {
        m_impl = other.m_impl ? std::make_unique<BlockIndexImpl>(other.m_impl->m_block_index) : nullptr;
    }
    return *this;
}

int32_t BlockIndex::GetHeight() const noexcept
{
    return m_impl->m_block_index.nHeight;
}

kernel_BlockHash BlockIndex::GetHash() const noexcept
{
    kernel_BlockHash block_hash{};
    std::memcpy(block_hash.hash, m_impl->m_block_index.phashBlock->begin(), sizeof(block_hash.hash));
    return block_hash;
}

std::optional<BlockIndex> BlockIndex::GetPreviousBlockIndex() const noexcept
{
    auto index{m_impl->m_block_index.pprev};
    if (!index) {
        LogTrace(BCLog::KERNEL, "The block index is the genesis, it has no previous.");
        return std::nullopt;
    }
    return std::make_optional<BlockIndex>(std::make_unique<BlockIndexImpl>(*index));
}

BlockIndex::~BlockIndex() noexcept = default;

struct KernelNotifications::KernelNotificationsImpl : public kernel::Notifications
{
    KernelNotifications& m_notifications;

    KernelNotificationsImpl(KernelNotifications& notifications)
        : m_notifications{notifications}
    {
    }

    kernel::InterruptResult blockTip(SynchronizationState state, CBlockIndex& index) override
    {
        m_notifications.BlockTipHandler(cast_state(state), BlockIndex{std::make_unique<BlockIndex::BlockIndexImpl>(index)});
        return {};
    }
    void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        m_notifications.HeaderTipHandler(cast_state(state), height, timestamp, presync);
    }
    void progress(const bilingual_str& title, int progress_percent, bool resume_possible) override
    {
        m_notifications.ProgressHandler(title.original, progress_percent, resume_possible);
    }
    void warningSet(kernel::Warning id, const bilingual_str& message) override
    {
        m_notifications.WarningSetHandler(cast_kernel_warning(id), message.original);
    }
    void warningUnset(kernel::Warning id) override
    {
        m_notifications.WarningUnsetHandler(cast_kernel_warning(id));
    }
    void flushError(const bilingual_str& message) override
    {
        m_notifications.FlushErrorHandler(message.original);
    }
    void fatalError(const bilingual_str& message) override
    {
        m_notifications.FatalErrorHandler(message.original);
    }
};

KernelNotifications::KernelNotifications() noexcept
{
    m_impl = std::make_unique<KernelNotificationsImpl>(*this);
}

KernelNotifications::~KernelNotifications() noexcept = default;

struct ChainParameters::ChainParametersImpl {
    std::unique_ptr<const CChainParams> m_chainparams;

    ChainParametersImpl(const kernel_ChainType chain_type)
    {
        switch (chain_type) {
        case kernel_ChainType::kernel_CHAIN_TYPE_MAINNET: {
            m_chainparams = CChainParams::Main();
            return;
        }
        case kernel_ChainType::kernel_CHAIN_TYPE_TESTNET: {
            m_chainparams = CChainParams::TestNet();
            return;
        }
        case kernel_ChainType::kernel_CHAIN_TYPE_TESTNET_4: {
            m_chainparams = CChainParams::TestNet4();
            return;
        }
        case kernel_ChainType::kernel_CHAIN_TYPE_SIGNET: {
            m_chainparams = CChainParams::SigNet({});
            return;
        }
        case kernel_ChainType::kernel_CHAIN_TYPE_REGTEST: {
            m_chainparams = CChainParams::RegTest({});
            return;
        }
        } // no default case, so the compiler can warn about missing cases
        assert(false);
    }
};

ChainParameters::ChainParameters(const kernel_ChainType chain_type) noexcept
{
    m_impl = std::make_unique<ChainParametersImpl>(chain_type);
}

ChainParameters::~ChainParameters() noexcept = default;

struct UnownedBlock::UnownedBlockImpl {
	const CBlock& m_block;

	UnownedBlockImpl(const CBlock& block) : m_block{block} {}
};

UnownedBlock::UnownedBlock(std::unique_ptr<UnownedBlockImpl> impl) noexcept
	: m_impl{std::move(impl)}
{}

std::vector<std::byte> UnownedBlock::GetBlockData() const noexcept
{
    DataStream ss{};
    ss << TX_WITH_WITNESS(m_impl->m_block);
    return std::vector<std::byte>{ss.begin(), ss.end()};
}

UnownedBlock::~UnownedBlock() noexcept = default;

struct BlockValidationState::BlockValidationStateImpl {
	::BlockValidationState m_block_validation_state;

	BlockValidationStateImpl() = default;
	BlockValidationStateImpl(const ::BlockValidationState& block_validation_state) : m_block_validation_state{block_validation_state} {}
};

BlockValidationState::BlockValidationState(std::unique_ptr<BlockValidationStateImpl> impl) noexcept
	: m_impl{std::move(impl)}
{}

kernel_ValidationMode BlockValidationState::ValidationMode() const noexcept
{
    if (m_impl->m_block_validation_state.IsValid()) return kernel_ValidationMode::kernel_VALIDATION_STATE_VALID;
    if (m_impl->m_block_validation_state.IsInvalid()) return kernel_ValidationMode::kernel_VALIDATION_STATE_INVALID;
    return kernel_ValidationMode::kernel_VALIDATION_STATE_ERROR;
}

kernel_BlockValidationResult BlockValidationState::BlockValidationResult() const noexcept
{
    switch (m_impl->m_block_validation_state.GetResult()) {
    case BlockValidationResult::BLOCK_RESULT_UNSET:
        return kernel_BlockValidationResult::kernel_BLOCK_RESULT_UNSET;
    case BlockValidationResult::BLOCK_CONSENSUS:
        return kernel_BlockValidationResult::kernel_BLOCK_CONSENSUS;
    case BlockValidationResult::BLOCK_CACHED_INVALID:
        return kernel_BlockValidationResult::kernel_BLOCK_CACHED_INVALID;
    case BlockValidationResult::BLOCK_INVALID_HEADER:
        return kernel_BlockValidationResult::kernel_BLOCK_INVALID_HEADER;
    case BlockValidationResult::BLOCK_MUTATED:
        return kernel_BlockValidationResult::kernel_BLOCK_MUTATED;
    case BlockValidationResult::BLOCK_MISSING_PREV:
        return kernel_BlockValidationResult::kernel_BLOCK_MISSING_PREV;
    case BlockValidationResult::BLOCK_INVALID_PREV:
        return kernel_BlockValidationResult::kernel_BLOCK_INVALID_PREV;
    case BlockValidationResult::BLOCK_TIME_FUTURE:
        return kernel_BlockValidationResult::kernel_BLOCK_TIME_FUTURE;
    case BlockValidationResult::BLOCK_HEADER_LOW_WORK:
        return kernel_BlockValidationResult::kernel_BLOCK_HEADER_LOW_WORK;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

BlockValidationState::~BlockValidationState() noexcept = default;

struct ValidationInterface::ValidationInterfaceImpl final : public CValidationInterface
{
	ValidationInterface& m_validation_interface;

	ValidationInterfaceImpl(ValidationInterface& validation_interface)
		: m_validation_interface{validation_interface}
	{
	}

    void BlockChecked(const CBlock& block, const ::BlockValidationState& block_validation_state) override
	{
		m_validation_interface.BlockCheckedHandler(
			UnownedBlock{std::make_unique<UnownedBlock::UnownedBlockImpl>(block)},
			BlockValidationState{std::make_unique<BlockValidationState::BlockValidationStateImpl>(block_validation_state)});
	}
};

ValidationInterface::ValidationInterface() noexcept
{
	m_impl = std::make_unique<ValidationInterfaceImpl>(*this);
}

ValidationInterface::~ValidationInterface() noexcept = default;

struct ContextOptions::ContextOptionsImpl {
    mutable Mutex m_mutex;
    std::unique_ptr<const CChainParams> m_chainparams GUARDED_BY(m_mutex);
    std::shared_ptr<KernelNotifications> m_notifications GUARDED_BY(m_mutex);
	std::shared_ptr<ValidationInterface> m_validation_interface GUARDED_BY(m_mutex);
};

ContextOptions::ContextOptions() noexcept
{
    m_impl = std::make_unique<ContextOptionsImpl>();
}

void ContextOptions::SetChainParameters(const ChainParameters& chain_parameters) noexcept
{
    LOCK(m_impl->m_mutex);
    m_impl->m_chainparams = std::make_unique<const CChainParams>(*chain_parameters.m_impl->m_chainparams);
}

void ContextOptions::SetNotifications(std::shared_ptr<KernelNotifications> notifications) noexcept
{
    LOCK(m_impl->m_mutex);
    m_impl->m_notifications = notifications;
}

void ContextOptions::SetValidationInterface(std::shared_ptr<ValidationInterface> validation_interface) noexcept
{
	LOCK(m_impl->m_mutex);
	m_impl->m_validation_interface = validation_interface;
}

ContextOptions::~ContextOptions() noexcept = default;

struct Context::ContextImpl
{
    std::unique_ptr<kernel::Context> m_context;

    std::shared_ptr<KernelNotifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

	std::unique_ptr<ValidationSignals> m_signals;

    std::unique_ptr<const CChainParams> m_chainparams;

	std::shared_ptr<ValidationInterface> m_validation_interface;

    ContextImpl(const ContextOptions& options, bool& sane)
        : m_context{std::make_unique<kernel::Context>()},
          m_interrupt{std::make_unique<util::SignalInterrupt>()},
		  m_signals{std::make_unique<ValidationSignals>(std::make_unique<ImmediateTaskRunner>())}
    {
        {
            LOCK(options.m_impl->m_mutex);
            if (options.m_impl->m_chainparams) {
                m_chainparams = std::make_unique<const CChainParams>(*options.m_impl->m_chainparams);
            }
            if (options.m_impl->m_notifications) {
                m_notifications = options.m_impl->m_notifications;
            }
			if (options.m_impl->m_validation_interface) {
				m_validation_interface = options.m_impl->m_validation_interface;
				m_signals->RegisterValidationInterface(m_validation_interface->m_impl.get());
			}
        }

        if (!m_chainparams) {
            m_chainparams = CChainParams::Main();
        }
        if (!m_notifications) {
            m_notifications = std::make_unique<KernelNotifications>();
        }

        if (!kernel::SanityChecks(*m_context)) {
            LogError("Kernel context sanity check failed.");
            sane = false;
        }
    }
};

Context::Context(const ContextOptions& options) noexcept
{
    bool sane{true};
    m_impl = std::make_unique<ContextImpl>(options, sane);
    if (!sane) m_impl = nullptr;
}

Context::Context() noexcept
{
    bool sane{true};
    ContextOptions options{};
    m_impl = std::make_unique<ContextImpl>(options, sane);
    if (!sane) m_impl = nullptr;
}

Context::~Context() noexcept
{
	if (m_impl->m_validation_interface) {
		m_impl->m_signals->UnregisterValidationInterface(m_impl->m_validation_interface->m_impl.get());
	}
}

bool Context::Interrupt() noexcept
{
	return (*m_impl->m_interrupt)();
}

struct Block::BlockImpl
{
    std::shared_ptr<CBlock> m_block;

    BlockImpl(std::span<const unsigned char> raw_block)
    {
        m_block = std::make_shared<CBlock>();
        DataStream stream{raw_block};
        stream >> TX_WITH_WITNESS(*m_block);
    }

    BlockImpl(std::shared_ptr<CBlock> block)
        : m_block{block}
    {}
};

Block::Block(std::span<const unsigned char> raw_block) noexcept
{
    try {
        m_impl = std::make_unique<BlockImpl>(raw_block);
    } catch (const std::exception& e) {
        LogDebug(BCLog::KERNEL, "Block decode failed: %s", e.what());
        m_impl = nullptr;
    }
};

Block::Block(std::unique_ptr<Block::BlockImpl> impl) noexcept
    : m_impl{std::move(impl)}
{}

Block::Block(Block&& other) noexcept
    : m_impl(std::move(other.m_impl))
{
}

std::vector<std::byte> Block::GetBlockData() const noexcept
{
    DataStream ss{};
    ss << TX_WITH_WITNESS(*m_impl->m_block);
    return std::vector<std::byte>{ss.begin(), ss.end()};
}

Block::~Block() noexcept = default;

struct BlockUndo::BlockUndoImpl
{
    std::shared_ptr<CBlockUndo> m_block_undo;

    BlockUndoImpl(std::shared_ptr<CBlockUndo> block_undo)
        : m_block_undo{block_undo}
    {}
};

BlockUndo::BlockUndo(std::unique_ptr<BlockUndoImpl> impl) noexcept
    : m_impl{std::move(impl)},
    m_size{m_impl->m_block_undo->vtxundo.size()}
{
}

BlockUndo::BlockUndo(BlockUndo&& other) noexcept
    : m_impl(std::move(other.m_impl)),
    m_size{m_impl->m_block_undo->vtxundo.size()}
{
}

BlockUndo::~BlockUndo() noexcept = default;

uint64_t BlockUndo::GetTxOutSize(uint64_t index) const noexcept
{
    if (m_impl->m_block_undo->vtxundo.size() <= index) return 0;
    return m_impl->m_block_undo->vtxundo[index].vprevout.size();
}

TransactionOutput BlockUndo::GetTxUndoPrevoutByIndex(
    uint64_t tx_undo_index,
    uint64_t tx_prevout_index) const noexcept
{
    if (tx_undo_index >= m_impl->m_block_undo->vtxundo.size()) {
        LogInfo("transaction undo index is out of bounds.");
        return TransactionOutput(nullptr);
    }
    const auto& tx_undo = m_impl->m_block_undo->vtxundo[tx_undo_index];
    if (tx_prevout_index >= tx_undo.vprevout.size()) {
        LogInfo("previous output index is out of bonds.");
        return TransactionOutput(nullptr);
    }
    return TransactionOutput(std::make_unique<TransactionOutput::TransactionOutputImpl>(tx_undo.vprevout[tx_prevout_index].out));
}

struct ChainstateManagerOptions::ChainstateManagerOptionsImpl
{
    mutable Mutex m_mutex;
    kernel::ChainstateManagerOpts m_chainman_options GUARDED_BY(m_mutex);
    node::BlockManager::Options m_blockman_options GUARDED_BY(m_mutex);
    node::ChainstateLoadOptions m_chainstate_load_options GUARDED_BY(m_mutex);

    ChainstateManagerOptionsImpl(const Context& context, const fs::path& data_dir, const fs::path& blocks_dir)
       : m_chainman_options{kernel::ChainstateManagerOpts{
              .chainparams = *context.m_impl->m_chainparams,
              .datadir = data_dir,
              .notifications = *context.m_impl->m_notifications->m_impl}},
          m_blockman_options{node::BlockManager::Options{
              .chainparams = *context.m_impl->m_chainparams,
              .blocks_dir = blocks_dir,
              .notifications = *context.m_impl->m_notifications->m_impl,
              .block_tree_db_params = DBParams{
                  .path = data_dir / "blocks" / "index",
                  .cache_bytes = kernel::CacheSizes{DEFAULT_KERNEL_CACHE}.block_tree_db,
              }}},
          m_chainstate_load_options{node::ChainstateLoadOptions{}}
    {
    }
};

ChainstateManagerOptions::ChainstateManagerOptions(const Context& context, const std::string& data_dir, const std::string& blocks_dir) noexcept
{
    try {
        fs::path abs_data_dir{fs::absolute(fs::PathFromString(data_dir))};
        fs::create_directories(abs_data_dir);
        fs::path abs_blocks_dir{fs::absolute(fs::PathFromString(blocks_dir))};
        fs::create_directories(abs_blocks_dir);
        m_impl = std::make_unique<ChainstateManagerOptionsImpl>(context, abs_data_dir, abs_blocks_dir);
    } catch (const std::exception& e) {
        LogError("Failed to create chainstate manager options: %s", e.what());
        m_impl = nullptr;
    }
}

void ChainstateManagerOptions::SetWorkerThreads(int worker_threads) const noexcept
{
    LOCK(m_impl->m_mutex);
    m_impl->m_chainman_options.worker_threads_num = worker_threads;
}

bool ChainstateManagerOptions::SetWipeDbs(bool wipe_block_tree, bool wipe_chainstate) const noexcept
{
    if (wipe_block_tree && !wipe_chainstate) {
        LogError("Wiping the block tree db without also wiping the chainstate db is currently unsupported.");
        return false;
    }
	LOCK(m_impl->m_mutex);
	m_impl->m_blockman_options.block_tree_db_params.wipe_data = wipe_block_tree;
	m_impl->m_chainstate_load_options.wipe_chainstate_db = wipe_chainstate;
	return true;
}

void ChainstateManagerOptions::SetBlockTreeDbInMemory(bool block_tree_db_in_memory) const noexcept
{
	LOCK(m_impl->m_mutex);
	m_impl->m_blockman_options.block_tree_db_params.memory_only = block_tree_db_in_memory;
}

void ChainstateManagerOptions::SetChainstateDbInMemory(bool chainstate_db_in_memory) const noexcept
{
	LOCK(m_impl->m_mutex);
	m_impl->m_chainstate_load_options.coins_db_in_memory = chainstate_db_in_memory;
}

ChainstateManagerOptions::~ChainstateManagerOptions() noexcept = default;

struct ChainstateManager::ChainstateManagerImpl
{
    ::ChainstateManager m_chainman;

    ChainstateManagerImpl(const Context& context, const ChainstateManagerOptions& chainman_opts)
        : m_chainman{::ChainstateManager(*context.m_impl->m_interrupt, chainman_opts.m_impl->m_chainman_options, chainman_opts.m_impl->m_blockman_options)}
    {}
};

ChainstateManager::ChainstateManager(const Context& context, const ChainstateManagerOptions& chainstate_manager_options) noexcept
    : m_context{context}
{
    try {
        LOCK(chainstate_manager_options.m_impl->m_mutex);
        m_impl = std::make_unique<ChainstateManagerImpl>(context, chainstate_manager_options);
    } catch (const std::exception& e) {
        LogError("Failed to create chainstate manager: %s", e.what());
        m_impl = nullptr;
        return;
    }
    try {
        const auto chainstate_load_opts{WITH_LOCK(chainstate_manager_options.m_impl->m_mutex, return chainstate_manager_options.m_impl->m_chainstate_load_options)};

        kernel::CacheSizes cache_sizes{DEFAULT_KERNEL_CACHE};
        auto [status, chainstate_err]{node::LoadChainstate(m_impl->m_chainman, cache_sizes, chainstate_load_opts)};
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            LogError("Failed to load chain state from your data directory: %s", chainstate_err.original);
            m_impl = nullptr;
            return;
        }
        std::tie(status, chainstate_err) = node::VerifyLoadedChainstate(m_impl->m_chainman, chainstate_load_opts);
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            LogError("Failed to verify loaded chain state from your datadir: %s", chainstate_err.original);
            m_impl = nullptr;
            return;
        }

        for (Chainstate* chainstate : WITH_LOCK(m_impl->m_chainman.GetMutex(), return m_impl->m_chainman.GetAll())) {
            ::BlockValidationState state;
            if (!chainstate->ActivateBestChain(state, nullptr)) {
                LogError("Failed to connect best block: %s", state.ToString());
                m_impl = nullptr;
                return;
            }
        }
    } catch (const std::exception& e) {
        LogError("Failed to load chainstate: %s", e.what());
        m_impl = nullptr;
    }
}

bool ChainstateManager::ImportBlocks(const std::span<const std::string> paths) const noexcept
{
	std::vector<fs::path> import_files;
	import_files.reserve(paths.size());
	for (const auto& path : paths) {
		import_files.emplace_back(path.c_str());
	}
	try {
		node::ImportBlocks(m_impl->m_chainman, import_files);
		m_impl->m_chainman.ActiveChainstate().ForceFlushStateToDisk();
    } catch (const std::exception& e) {
        LogError("Failed to import blocks: %s", e.what());
        return false;
    }
    return true;
}

bool ChainstateManager::ProcessBlock(const Block& block, bool& new_block) const noexcept
{
	return m_impl->m_chainman.ProcessNewBlock(block.m_impl->m_block, /*force_processing=*/ true, /*min_pow_checked=*/ true, /*new_block=*/ &new_block);
}


BlockIndex ChainstateManager::GetBlockIndexFromTip() const noexcept
{
    CBlockIndex* tip{WITH_LOCK(m_impl->m_chainman.GetMutex(), return m_impl->m_chainman.ActiveChain().Tip())};
    if (!tip) return BlockIndex(nullptr);
    return BlockIndex(std::make_unique<BlockIndex::BlockIndexImpl>(*tip));
}

BlockIndex ChainstateManager::GetBlockIndexFromGenesis() const noexcept
{
    return BlockIndex{std::make_unique<BlockIndex::BlockIndexImpl>(*WITH_LOCK(m_impl->m_chainman.GetMutex(), return m_impl->m_chainman.ActiveChain().Genesis()))};
}

std::optional<BlockIndex> ChainstateManager::GetBlockIndexByHash(const kernel_BlockHash& block_hash) const noexcept
{
    auto hash = uint256{std::span<const unsigned char>{block_hash.hash, 32}};
    auto block_index = WITH_LOCK(::cs_main, return m_impl->m_chainman.m_blockman.LookupBlockIndex(hash));
    if (!block_index) {
        LogDebug(BCLog::KERNEL, "A block with the given hash is not indexed: %s", hash.ToString());
        return std::nullopt;
    }
    return std::make_optional<BlockIndex>(std::make_unique<BlockIndex::BlockIndexImpl>(*block_index));
}

std::optional<BlockIndex> ChainstateManager::GetBlockIndexByHeight(int height) const noexcept
{
    LOCK(m_impl->m_chainman.GetMutex());
    if (height < 0 || height > m_impl->m_chainman.ActiveChain().Height()) {
        LogDebug(BCLog::KERNEL, "Block height is out of range.");
        return std::nullopt;
    }
    return std::make_optional<BlockIndex>(std::make_unique<BlockIndex::BlockIndexImpl>(*m_impl->m_chainman.ActiveChain()[height]));
}

std::optional<BlockIndex> ChainstateManager::GetNextBlockIndex(const BlockIndex& block_index) const noexcept
{
    auto next_block_index{WITH_LOCK(m_impl->m_chainman.GetMutex(), return m_impl->m_chainman.ActiveChain().Next(&block_index.m_impl->m_block_index))};

    if (!next_block_index) {
        LogTrace(BCLog::KERNEL, "The block index is the tip of the current chain, it does not have a next.");
    }

    return std::make_optional<BlockIndex>(std::make_unique<BlockIndex::BlockIndexImpl>(*next_block_index));
}

std::optional<Block> ChainstateManager::ReadBlock(const BlockIndex& block_index) const noexcept
{
    auto block{std::make_shared<CBlock>()};
    if (!m_impl->m_chainman.m_blockman.ReadBlock(*block, block_index.m_impl->m_block_index)) {
        LogError("Failed to read block.");
        return std::nullopt;
    }
    return std::make_optional<Block>(std::make_unique<Block::BlockImpl>(block));
}

std::optional<BlockUndo> ChainstateManager::ReadBlockUndo(const BlockIndex& block_index) const noexcept
{
    auto block_undo{std::make_shared<CBlockUndo>()};
    if (!m_impl->m_chainman.m_blockman.ReadBlockUndo(*block_undo, block_index.m_impl->m_block_index)) {
        LogError("Failed to read block undo.");
        return std::nullopt;
    }
    return std::make_optional<BlockUndo>(std::make_unique<BlockUndo::BlockUndoImpl>(block_undo));
}

ChainstateManager::~ChainstateManager() noexcept
{
    if (m_impl) {
        LOCK(m_impl->m_chainman.GetMutex());

        for (Chainstate* chainstate : m_impl->m_chainman.GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
    }
}

} // namespace kernel_header
