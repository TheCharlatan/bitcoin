// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

struct ByteArray {
    const unsigned char* data;
    size_t size;
};

std::string random_string(uint32_t length)
{
    const std::string chars = "0123456789"
                              "abcdefghijklmnopqrstuvwxyz"
                              "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    static std::random_device rd;
    static std::default_random_engine dre{rd()};
    static std::uniform_int_distribution<> distribution(0, chars.size() - 1);

    std::string random;
    random.reserve(length);
    for (uint32_t i = 0; i < length; i++) {
        random += chars[distribution(dre)];
    }
    return random;
}

std::vector<std::string> read_blocks(const std::string& file_path)
{
    std::vector<std::string> lines;
    std::ifstream file{file_path};

    if (!file.is_open()) {
        return lines;
    }

    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
    }
    file.close();
    return lines;
}

ByteArray hex_string_to_byte_array(const std::string& hex)
{
    std::vector<unsigned char> bytes;

    for (size_t i{0}; i < hex.length(); i += 2) {
        std::string byteString{hex.substr(i, 2)};
        unsigned char byte = (char)std::strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }

    std::unique_ptr<unsigned char[]> byte_array(new unsigned char[bytes.size()]);
    std::copy(bytes.begin(), bytes.end(), byte_array.get());

    ByteArray result;
    result.data = byte_array.release();
    result.size = bytes.size();
    return result;
}

std::string byte_array_to_hex_string(kernel_ByteArray* byte_array)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i{0}; i < byte_array->size; i++) {
        oss << std::setw(2) << static_cast<int>(byte_array->data[i]);
    }
    return oss.str();
}

const auto VERIFY_ALL_PRE_TAPROOT = kernel_SCRIPT_FLAGS_VERIFY_P2SH | kernel_SCRIPT_FLAGS_VERIFY_DERSIG |
                                    kernel_SCRIPT_FLAGS_VERIFY_NULLDUMMY | kernel_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                    kernel_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY | kernel_SCRIPT_FLAGS_VERIFY_WITNESS;

const auto VERIFY_ALL_PRE_SEGWIT = kernel_SCRIPT_FLAGS_VERIFY_P2SH | kernel_SCRIPT_FLAGS_VERIFY_DERSIG |
                                   kernel_SCRIPT_FLAGS_VERIFY_NULLDUMMY | kernel_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                   kernel_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY;


void assert_error_ok(kernel_Error& error)
{
    if (error.code != kernel_ErrorCode::kernel_ERROR_OK) {
        std::cout << error.message << " error code: " << error.message << "\n";
        assert(error.code == kernel_ErrorCode::kernel_ERROR_OK);
    }
}

void assert_is_error(kernel_Error& error)
{
    assert(error.code != kernel_ErrorCode::kernel_ERROR_OK);
    std::cout << "Error: " << error.message << std::endl;
}

void verify_test(std::string spent, std::string spending, int64_t amount, unsigned int nIn)
{
    ByteArray script_pubkey{hex_string_to_byte_array(spent)};
    ByteArray spending_tx{hex_string_to_byte_array(spending)};
    kernel_Error error{};
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    assert(kernel_verify_script_with_amount(
        script_pubkey.data,
        script_pubkey.size,
        amount,
        spending_tx.data,
        spending_tx.size,
        nIn,
        VERIFY_ALL_PRE_TAPROOT,
        &error));

    assert(kernel_verify_script(
        script_pubkey.data,
        script_pubkey.size,
        spending_tx.data,
        spending_tx.size,
        nIn,
        VERIFY_ALL_PRE_SEGWIT,
        &error));

    delete[] script_pubkey.data;
    delete[] spending_tx.data;

    assert_error_ok(error);
}

class Logger
{
private:
    kernel_LoggingConnection* m_connection;

public:
    Logger(kernel_Error& error)
    {
        kernel_LoggingOptions logging_options = {
            .log_timestamps = true,
            .log_time_micros = false,
            .log_threadnames = false,
            .log_sourcelocations = false,
            .always_print_category_levels = true,
        };
        kernel_enable_log_category(kernel_LogCategory::kernel_LOG_VALIDATION);
        auto logging_cb = [](void* user_data, const char* message) { reinterpret_cast<Logger*>(user_data)->LogMessage(message); };
        m_connection = kernel_logging_connection_create(logging_cb, this, logging_options, &error);
    }

    void LogMessage(const char* message)
    {
        std::cout << "kernel: " << message;
    }

    ~Logger()
    {
        kernel_logging_connection_destroy(m_connection);
    }
};

class ChainParams
{
private:
    const kernel_ChainParameters* m_chain_params;

public:
    ChainParams(kernel_ChainType chain_type) : m_chain_params{kernel_chain_parameters_create(chain_type)} {}

    ChainParams(const ChainParams&) = delete;
    ChainParams& operator=(const ChainParams&) = delete;

    ~ChainParams()
    {
        kernel_chain_parameters_destroy(m_chain_params);
    }

    friend class ContextOptions;
};

class KernelNotifications
{
public:
    kernel_NotificationInterfaceCallbacks MakeCallbacks()
    {
        return kernel_NotificationInterfaceCallbacks{
            .user_data = this,
            .block_tip = [](void* user_data, kernel_SynchronizationState state, kernel_BlockIndex* index) {
                reinterpret_cast<KernelNotifications*>(user_data)->BlockTipHandler(state, index);
            },
            .header_tip = [](void* user_data, kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {
                reinterpret_cast<KernelNotifications*>(user_data)->HeaderTipHandler(state, height, timestamp, presync);
            },
            .progress = [](void* user_data, const char* title, int progress_percent, bool resume_possible) {
                reinterpret_cast<KernelNotifications*>(user_data)->ProgressHandler(title, progress_percent, resume_possible);
            },
            .warning = [](void* user_data, const char* warning) { reinterpret_cast<KernelNotifications*>(user_data)->WarningHandler(warning); },
            .flush_error = [](void* user_data, const char* error) { reinterpret_cast<KernelNotifications*>(user_data)->FlushErrorHandler(error); },
            .fatal_error = [](void* user_data, const char* error) { reinterpret_cast<KernelNotifications*>(user_data)->FatalErrorHandler(error); },
        };
    }

    void BlockTipHandler(kernel_SynchronizationState state, kernel_BlockIndex* index)
    {
        std::cout << "Block tip changed" << std::endl;
    }

    void HeaderTipHandler(kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync)
    {
        assert(timestamp > 0);
    }

    void ProgressHandler(const char* title, int progress_percent, bool resum_possible)
    {
        std::cout << "Made progress: " << title << " " << progress_percent << "%" << std::endl;
    }

    void WarningHandler(const char* warning)
    {
        std::cout << warning << std::endl;
    }

    void FlushErrorHandler(const char* error)
    {
        std::cout << error << std::endl;
        assert(0);
    }

    void FatalErrorHandler(const char* error)
    {
        std::cout << error << std::endl;
        assert(0);
    }
};

class ImmediateTaskRunner
{
public:
    kernel_TaskRunnerCallbacks MakeCallbacks()
    {
        return kernel_TaskRunnerCallbacks{
            .user_data = this,
            .insert = [](void* user_data, kernel_ValidationEvent* event) { kernel_execute_event_and_destroy(event, nullptr); },
            .flush = [](void* user_data) {},
            .size = [](void* user_data) -> unsigned int { return 0; },
        };
    }
};

class ContextOptions
{
private:
    kernel_ContextOptions* m_options;

public:
    ContextOptions()
        : m_options{kernel_context_options_create()}
    {
    }

    ContextOptions(const ContextOptions&) = delete;
    ContextOptions& operator=(const ContextOptions&) = delete;

    void SetChainParams(ChainParams& chain_params, kernel_Error& error)
    {
        kernel_context_options_set(
            m_options,
            kernel_ContextOptionType::kernel_CHAIN_PARAMETERS_OPTION,
            reinterpret_cast<const void*>(chain_params.m_chain_params),
            &error);
    }

    void SetNotificationCallbacks(KernelNotifications& notifications, kernel_Error& error)
    {
        auto callbacks = notifications.MakeCallbacks();
        kernel_context_options_set(
            m_options,
            kernel_ContextOptionType::kernel_NOTIFICATION_INTERFACE_CALLBACKS_OPTION,
            &callbacks,
            &error);
    }

    void SetTaskRunnerCallbacks(ImmediateTaskRunner& task_runner, kernel_Error& error)
    {
        auto callbacks = task_runner.MakeCallbacks();
        kernel_context_options_set(m_options, kernel_ContextOptionType::kernel_TASK_RUNNER_CALLBACKS_OPTION, &callbacks, &error);
    }

    ~ContextOptions()
    {
        kernel_context_options_destroy(m_options);
    }

    friend class Context;
};

class Context
{
public:
    kernel_Context* m_context;

public:
    Context(ContextOptions& opts, kernel_Error& error)
        : m_context{kernel_context_create(opts.m_options, &error)}
    {
    }

    Context(kernel_Error& error)
        : m_context{kernel_context_create(nullptr, &error)}
    {
    }

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    ~Context()
    {
        kernel_context_destroy(m_context);
    }
};

void default_context_test()
{
    kernel_Error error;
    error.code = kernel_ErrorCode::kernel_ERROR_OK;
    Context context{error};
    assert_error_ok(error);
}

class ValidationInterface
{
private:
    kernel_ValidationInterface* m_validation_interface;

public:
    std::optional<std::string> m_expected_valid_block = std::nullopt;

    ValidationInterface() : m_validation_interface{kernel_validation_interface_create(kernel_ValidationInterfaceCallbacks{
                                .user_data = this,
                                .block_checked = [](void* user_data, const kernel_BlockPointer* block, const kernel_BlockValidationState* state) {
                                    reinterpret_cast<ValidationInterface*>(user_data)->BlockChecked(block, state);
                                },
                            })}
    {
    }

    ValidationInterface(const ValidationInterface&) = delete;
    ValidationInterface& operator=(const ValidationInterface&) = delete;

    void BlockChecked(const kernel_BlockPointer* block, const kernel_BlockValidationState* state)
    {
        std::cout << "Block checked: ";
        {
            kernel_Error error;
            error.code = kernel_ErrorCode::kernel_ERROR_OK;
            auto serialized_block{kernel_copy_block_pointer_data(block, &error)};
            assert_error_ok(error);

            if (m_expected_valid_block.has_value()) {
                assert(m_expected_valid_block.value() == byte_array_to_hex_string(serialized_block));
            }
            kernel_byte_array_destroy(serialized_block);
        }

        auto mode{kernel_get_validation_mode_from_block_validation_state(state)};
        switch (mode) {
        case kernel_ValidationMode::kernel_VALIDATION_STATE_VALID: {
            std::cout << "Valid block\n";
            return;
        }
        case kernel_ValidationMode::kernel_VALIDATION_STATE_INVALID: {
            std::cout << "Invalid block: ";
            auto result = kernel_get_block_validation_result_from_block_validation_state(state);
            switch (result) {
            case kernel_BlockValidationResult::kernel_BLOCK_RESULT_UNSET:
                std::cout << "initial value. Block has not yet been rejected" << std::endl;
                break;
            case kernel_BlockValidationResult::kernel_BLOCK_HEADER_LOW_WORK:
                std::cout << "the block header may be on a too-little-work chain" << std::endl;
                break;
            case kernel_BlockValidationResult::kernel_BLOCK_CONSENSUS:
                std::cout << "invalid by consensus rules (excluding any below reasons)" << std::endl;
                break;
            case kernel_BlockValidationResult::kernel_BLOCK_RECENT_CONSENSUS_CHANGE:
                std::cout << "Invalid by a change to consensus rules more recent than SegWit." << std::endl;
                break;
            case kernel_BlockValidationResult::kernel_BLOCK_CACHED_INVALID:
                std::cout << "this block was cached as being invalid and we didn't store the reason why" << std::endl;
                break;
            case kernel_BlockValidationResult::kernel_BLOCK_INVALID_HEADER:
                std::cout << "invalid proof of work or time too old" << std::endl;
                break;
            case kernel_BlockValidationResult::kernel_BLOCK_MUTATED:
                std::cout << "the block's data didn't match the data committed to by the PoW" << std::endl;
                break;
            case kernel_BlockValidationResult::kernel_BLOCK_MISSING_PREV:
                std::cout << "We don't have the previous block the checked one is built on" << std::endl;
                break;
            case kernel_BlockValidationResult::kernel_BLOCK_INVALID_PREV:
                std::cout << "A block this one builds on is invalid" << std::endl;
                break;
            case kernel_BlockValidationResult::kernel_BLOCK_TIME_FUTURE:
                std::cout << "block timestamp was > 2 hours in the future (or our clock is bad)" << std::endl;
                break;
            case kernel_BlockValidationResult::kernel_BLOCK_CHECKPOINT:
                std::cout << "the block failed to meet one of our checkpoints" << std::endl;
                break;
            }
            return;
        }
        case kernel_ValidationMode::kernel_VALIDATION_STATE_ERROR: {
            std::cout << "Internal error\n";
            return;
        }
        }
    }

    void Register(Context& context, kernel_Error& error)
    {
        kernel_validation_interface_register(context.m_context, m_validation_interface, &error);
    }

    void Unregister(Context& context, kernel_Error& error)
    {
        kernel_validation_interface_unregister(context.m_context, m_validation_interface, &error);
    }

    ~ValidationInterface()
    {
        kernel_validation_interface_destroy(m_validation_interface);
    }
};

class ChainstateManagerOptions
{
private:
    kernel_ChainstateManagerOptions* m_options;

public:
    ChainstateManagerOptions(Context& context, const std::string& data_dir, kernel_Error& error)
        : m_options{kernel_chainstate_manager_options_create(context.m_context, data_dir.c_str(), &error)}
    {
    }

    ChainstateManagerOptions(const ChainstateManagerOptions&) = delete;
    ChainstateManagerOptions& operator=(const ChainstateManagerOptions&) = delete;

    ~ChainstateManagerOptions()
    {
        kernel_chainstate_manager_options_destroy(m_options);
    }

    friend class ChainMan;
};

class BlockManagerOptions
{
private:
    kernel_BlockManagerOptions* m_options;

public:
    BlockManagerOptions(Context& context, const std::string& data_dir, kernel_Error& error)
    {
        m_options = kernel_block_manager_options_create(context.m_context, data_dir.c_str(), &error);
        assert(m_options);
    }

    BlockManagerOptions(const BlockManagerOptions&) = delete;
    BlockManagerOptions& operator=(const BlockManagerOptions&) = delete;

    ~BlockManagerOptions()
    {
        kernel_block_manager_options_destroy(m_options);
    }

    friend class ChainMan;
};

class ChainstateLoadOptions
{
private:
    kernel_ChainstateLoadOptions* m_options;

public:
    ChainstateLoadOptions()
        : m_options{kernel_chainstate_load_options_create()}
    {
    }

    ChainstateLoadOptions(const ChainstateLoadOptions&) = delete;
    ChainstateLoadOptions& operator=(const ChainstateLoadOptions&) = delete;

    ~ChainstateLoadOptions()
    {
        kernel_chainstate_load_options_destroy(m_options);
    }

    void SetWipeBlockTreeDb(bool reindex, kernel_Error& error)
    {
        kernel_chainstate_load_options_set(m_options,
                                           kernel_ChainstateLoadOptionType::kernel_WIPE_BLOCK_TREE_DB_CHAINSTATE_LOAD_OPTION,
                                           &reindex,
                                           &error);
    }

    void SetWipeChainstateDb(bool reindex_chainstate, kernel_Error& error)
    {
        kernel_chainstate_load_options_set(m_options,
                                           kernel_ChainstateLoadOptionType::kernel_WIPE_CHAINSTATE_DB_CHAINSTATE_LOAD_OPTION,
                                           &reindex_chainstate,
                                           &error);
    }

    friend class ChainMan;
};

class Block
{
private:
    kernel_Block* m_block;

public:
    Block(std::string& block_str, kernel_Error& error)
        : m_block{kernel_block_from_string(block_str.c_str(), &error)}
    {
    }

    Block(kernel_Block* block) : m_block{block} {}

    Block(const Block&) = delete;
    Block& operator=(const Block&) = delete;

    std::string ToHexString(kernel_Error& error)
    {
        auto serialized_block{kernel_copy_block_data(m_block, &error)};
        if (error.code != kernel_ErrorCode::kernel_ERROR_OK) {
            return "";
        }
        auto hex_block{byte_array_to_hex_string(serialized_block)};
        kernel_byte_array_destroy(serialized_block);
        return hex_block;
    }

    ~Block()
    {
        kernel_block_destroy(m_block);
    }

    friend class ChainMan;
};

class BlockIndex
{
private:
    kernel_BlockIndex* m_block_index;

public:
    BlockIndex(kernel_BlockIndex* block_index) : m_block_index{block_index} {}

    BlockIndex(const BlockIndex&) = delete;
    BlockIndex& operator=(const BlockIndex&) = delete;

    BlockIndex GetPreviousBlockIndex(kernel_Error& error)
    {
        return kernel_get_previous_block_index(m_block_index, &error);
    }

    bool IsNull()
    {
        return m_block_index == nullptr;
    }

    ~BlockIndex()
    {
        kernel_block_index_destroy(m_block_index);
    }

    friend class ChainMan;
};

class BlockUndo
{
private:
    kernel_BlockUndo* m_block_undo;

public:
    uint64_t m_size;

    BlockUndo(kernel_BlockUndo* block_undo, kernel_Error& error) : m_block_undo{block_undo}
    {
        m_size = kernel_block_undo_size(block_undo, &error);
    }

    BlockUndo(const BlockUndo&) = delete;
    BlockUndo& operator=(const BlockUndo&) = delete;

    uint64_t GetTxOutSize(uint64_t index, kernel_Error& error)
    {
        return kernel_get_transaction_undo_size(m_block_undo, index, &error);
    }

    kernel_TransactionOutput* GetTxUndoPrevoutByIndex(uint64_t tx_undo_index, uint64_t tx_prevout_index, kernel_Error& error)
    {
        return kernel_get_undo_output_by_index(m_block_undo, tx_undo_index, tx_prevout_index, &error);
    }

    ~BlockUndo()
    {
        kernel_block_undo_destroy(m_block_undo);
    }
};

class ChainMan
{
private:
    kernel_ChainstateManager* m_chainman;
    Context& m_context;

public:
    ChainMan(Context& context, ChainstateManagerOptions& chainman_opts, BlockManagerOptions& blockman_opts, kernel_Error& error)
        : m_chainman{kernel_chainstate_manager_create(chainman_opts.m_options, blockman_opts.m_options, context.m_context, &error)},
          m_context{context}
    {
    }

    ChainMan(const ChainMan&) = delete;
    ChainMan& operator=(const ChainMan&) = delete;

    void LoadChainstate(ChainstateLoadOptions& chainstate_load_opts, kernel_Error& error)
    {
        kernel_chainstate_manager_load_chainstate(m_context.m_context, chainstate_load_opts.m_options, m_chainman, &error);
    }

    void ImportBlocks(std::vector<std::filesystem::path> paths, kernel_Error& error)
    {
        std::vector<const char*> c_paths;
        std::vector<std::string> str_paths;
        c_paths.reserve(paths.size());
        str_paths.reserve(paths.size());
        for (const auto& path : paths) {
            str_paths.push_back(path.string());
        }
        for (const auto& path : str_paths) {
            c_paths.push_back(path.c_str());
        }

        kernel_import_blocks(m_context.m_context, m_chainman, c_paths.data(), c_paths.size(), &error);
    }

    BlockIndex GetBlockIndexFromTip(kernel_Error& error)
    {
        return kernel_get_block_index_from_tip(m_context.m_context, m_chainman, &error);
    }

    BlockIndex GetBlockIndexFromGenesis(kernel_Error& error)
    {
        return kernel_get_block_index_from_genesis(m_context.m_context, m_chainman, &error);
    }

    BlockIndex GetBlockIndexByHeight(int height, kernel_Error& error)
    {
        return kernel_get_block_index_by_height(m_context.m_context, m_chainman, height, &error);
    }

    BlockIndex GetNextBlockIndex(BlockIndex& block_index, kernel_Error& error)
    {
        return kernel_get_next_block_index(m_context.m_context, block_index.m_block_index, m_chainman, &error);
    }

    Block ReadBlock(BlockIndex& block_index, kernel_Error& error)
    {
        return Block{kernel_read_block_from_disk(m_context.m_context, m_chainman, block_index.m_block_index, &error)};
    }

    BlockUndo ReadBlockUndo(BlockIndex& block_index, kernel_Error& error)
    {
        return BlockUndo{kernel_read_block_undo_from_disk(m_context.m_context, m_chainman, block_index.m_block_index, &error), error};
    }

    bool ValidateBlock(Block& block, kernel_Error& error)
    {
        return kernel_chainstate_manager_process_block(m_context.m_context, m_chainman, block.m_block, &error);
    }

    ~ChainMan()
    {
        kernel_Error error;
        kernel_chainstate_manager_destroy(m_chainman, m_context.m_context, &error);
        assert_error_ok(error);
    }
};

Context create_context(KernelNotifications& notifications, kernel_Error& error, kernel_ChainType chain_type, ImmediateTaskRunner* task_runner = nullptr)
{
    ContextOptions options{};
    ChainParams params{chain_type};
    options.SetChainParams(params, error);
    assert_error_ok(error);
    options.SetNotificationCallbacks(notifications, error);
    assert_error_ok(error);
    if (task_runner) {
        options.SetTaskRunnerCallbacks(*task_runner, error);
        assert_error_ok(error);
    }

    return Context{options, error};
}

std::unique_ptr<ChainMan> create_chainman(std::filesystem::path path_root,
                                          bool reindex,
                                          bool wipe_chainstate,
                                          kernel_Error& error,
                                          Context& context)
{
    ChainstateManagerOptions chainman_opts{context, path_root, error};
    assert_error_ok(error);
    BlockManagerOptions blockman_opts{context, path_root / "blocks", error};
    assert_error_ok(error);
    assert_error_ok(error);

    auto chainman{std::make_unique<ChainMan>(context, chainman_opts, blockman_opts, error)};
    assert_error_ok(error);

    ChainstateLoadOptions chainstate_load_opts{};
    if (reindex) {
        chainstate_load_opts.SetWipeBlockTreeDb(reindex, error);
        assert_error_ok(error);
        chainstate_load_opts.SetWipeChainstateDb(reindex, error);
        assert_error_ok(error);
    }
    if (wipe_chainstate) {
        chainstate_load_opts.SetWipeChainstateDb(wipe_chainstate, error);
    }
    assert_error_ok(error);
    chainman->LoadChainstate(chainstate_load_opts, error);
    assert_error_ok(error);

    return chainman;
}

void chainman_mainnet_validation_test(std::filesystem::path path_root)
{
    kernel_Error error{};
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    KernelNotifications notifications{};
    ImmediateTaskRunner task_runner{};

    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_MAINNET, &task_runner)};
    assert_error_ok(error);

    ValidationInterface validation_interface{};
    validation_interface.Register(context, error);
    assert_error_ok(error);

    auto chainman{create_chainman(path_root, false, false, error, context)};
    assert_error_ok(error);

    std::string block_str{"010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"};
    validation_interface.m_expected_valid_block.emplace(block_str);
    Block block{block_str, error};
    chainman->ValidateBlock(block, error);
    assert_error_ok(error);

    auto tip = chainman->GetBlockIndexFromTip(error);
    assert_error_ok(error);
    auto read_block = chainman->ReadBlock(tip, error);
    assert_error_ok(error);
    assert(read_block.ToHexString(error) == block_str);
    assert_error_ok(error);

    // Check that we can read the previous block
    auto tip_2 = tip.GetPreviousBlockIndex(error);
    assert_error_ok(error);
    auto read_block_2 = chainman->ReadBlock(tip_2, error);
    assert_error_ok(error);

    // It should be an error if we go another block back, since the genesis has no ancestor
    auto tip_3 = tip_2.GetPreviousBlockIndex(error);
    assert_is_error(error);

    // If we try to validate it again, it should be a duplicate
    assert(!chainman->ValidateBlock(block, error));
    assert_is_error(error);

    validation_interface.Unregister(context, error);
    assert_error_ok(error);
}

void chainman_regtest_validation_test()
{
    const auto rand_str{random_string(16)};
    auto path_root{std::filesystem::temp_directory_path() / ("test_bitcoin_kernel_" + rand_str)};
    std::filesystem::create_directories(path_root);

    kernel_Error error{};
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    KernelNotifications notifications{};
    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_REGTEST)};
    assert_error_ok(error);
    auto chainman{create_chainman(path_root, false, false, error, context)};
    assert_error_ok(error);

    auto blocks{read_blocks("block_data.txt")};
    for (auto& block_str : blocks) {
        Block block{block_str, error};
        assert_error_ok(error);
        chainman->ValidateBlock(block, error);
        assert_error_ok(error);
    }

    auto tip = chainman->GetBlockIndexFromTip(error);
    assert_error_ok(error);
    auto read_block = chainman->ReadBlock(tip, error);
    assert_error_ok(error);
    assert(read_block.ToHexString(error) == blocks[blocks.size() - 1]);
    assert(read_block.ToHexString(error) == blocks[blocks.size() - 1]);
    assert_error_ok(error);

    auto tip_2 = tip.GetPreviousBlockIndex(error);
    assert_error_ok(error);
    auto read_block_2 = chainman->ReadBlock(tip_2, error);
    assert_error_ok(error);
    assert(read_block_2.ToHexString(error) == blocks[blocks.size() - 2]);
    assert(read_block_2.ToHexString(error) == blocks[blocks.size() - 2]);
    assert_error_ok(error);

    auto block_undo = chainman->ReadBlockUndo(tip, error);
    assert_error_ok(error);
    auto tx_undo_size = block_undo.GetTxOutSize(block_undo.m_size - 1, error);
    assert_error_ok(error);
    auto output = block_undo.GetTxUndoPrevoutByIndex(block_undo.m_size - 1, tx_undo_size - 1, error);
    assert_error_ok(error);
    std::cout << "last prevout pubkey length: " << output->script_pubkey_len << ", value: " << output->value << std::endl;
    kernel_transaction_output_destroy(output);
}

void chainman_reindex_test(std::filesystem::path path_root)
{
    kernel_Error error{};
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    KernelNotifications notifications{};
    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_MAINNET)};
    assert_error_ok(error);
    auto chainman{create_chainman(path_root, true, false, error, context)};
    assert_error_ok(error);

    std::vector<std::filesystem::path> import_files;
    chainman->ImportBlocks(import_files, error);
    assert_error_ok(error);

    // Sanity check some block retrievals
    auto genesis_index{chainman->GetBlockIndexFromGenesis(error)};
    assert_error_ok(error);
    auto genesis_block_string{chainman->ReadBlock(genesis_index, error).ToHexString(error)};
    assert_error_ok(error);
    auto first_index{chainman->GetBlockIndexByHeight(0, error)};
    assert_error_ok(error);
    auto first_block_string{chainman->ReadBlock(genesis_index, error).ToHexString(error)};
    assert_error_ok(error);
    assert(genesis_block_string == first_block_string);

    auto next_index{chainman->GetNextBlockIndex(first_index, error)};
    assert_error_ok(error);
    auto next_block_string{chainman->ReadBlock(next_index, error).ToHexString(error)};
    assert_error_ok(error);
    auto tip_index{chainman->GetBlockIndexFromTip(error)};
    assert_error_ok(error);
    auto tip_block_string{chainman->ReadBlock(tip_index, error).ToHexString(error)};
    assert_error_ok(error);
    auto second_index{chainman->GetBlockIndexByHeight(1, error)};
    assert_error_ok(error);
    auto second_block_string{chainman->ReadBlock(second_index, error).ToHexString(error)};
    assert_error_ok(error);
    assert(next_block_string == tip_block_string);
    assert(next_block_string == second_block_string);
}

void chainman_reindex_chainstate_test(std::filesystem::path path_root)
{
    kernel_Error error{};
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    KernelNotifications notifications{};
    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_MAINNET)};
    assert_error_ok(error);
    auto chainman{create_chainman(path_root, false, true, error, context)};

    std::vector<std::filesystem::path> import_files;
    import_files.push_back(path_root / "blocks" / "blk00000.dat");
    chainman->ImportBlocks(import_files, error);
    assert_error_ok(error);
}

int main()
{
    kernel_Error error;
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    Logger logger{error};
    assert_error_ok(error);

    verify_test(
        "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
        "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
        0, 0);

    default_context_test();

    const auto rand_str{random_string(16)};
    auto path_root{std::filesystem::temp_directory_path() / ("test_bitcoin_kernel_" + rand_str)};
    std::filesystem::create_directories(path_root);

    chainman_mainnet_validation_test(path_root);

    chainman_regtest_validation_test();

    chainman_reindex_test(path_root);

    chainman_reindex_chainstate_test(path_root);

    std::cout << "Libbitcoinkernel test completed.\n";
    return 0;
}
