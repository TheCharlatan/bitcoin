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
#include <iostream>
#include <memory>
#include <random>
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

    Block(const Block&) = delete;
    Block& operator=(const Block&) = delete;

    ~Block()
    {
        kernel_block_destroy(m_block);
    }

    friend class ChainMan;
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

Context create_context(KernelNotifications& notifications, kernel_Error& error, kernel_ChainType chain_type)
{
    ContextOptions options{};
    ChainParams params{chain_type};
    options.SetChainParams(params, error);
    assert_error_ok(error);
    options.SetNotificationCallbacks(notifications, error);
    assert_error_ok(error);

    return Context{options, error};
}

std::unique_ptr<ChainMan> create_chainman(std::filesystem::path path_root, kernel_Error& error, Context& context)
{
    ChainstateManagerOptions chainman_opts{context, path_root, error};
    assert_error_ok(error);
    BlockManagerOptions blockman_opts{context, path_root / "blocks", error};
    assert_error_ok(error);

    auto chainman{std::make_unique<ChainMan>(context, chainman_opts, blockman_opts, error)};
    assert_error_ok(error);

    ChainstateLoadOptions chainstate_load_opts{};
    chainman->LoadChainstate(chainstate_load_opts, error);
    assert_error_ok(error);

    return chainman;
}

void chainman_mainnet_validation_test()
{
    kernel_Error error{};
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    const auto rand_str{random_string(16)};
    auto path_root{std::filesystem::temp_directory_path() / ("test_bitcoin_kernel_" + rand_str)};
    std::filesystem::create_directories(path_root);

    KernelNotifications notifications{};
    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_MAINNET)};
    assert_error_ok(error);
    auto chainman{create_chainman(path_root, error, context)};
    assert_error_ok(error);

    std::string block_str{"010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"};
    Block block{block_str, error};
    chainman->ValidateBlock(block, error);
    assert_error_ok(error);

    // If we try to validate it again, it should be a duplicate
    assert(!chainman->ValidateBlock(block, error));
    assert_is_error(error);
}

void chainman_regtest_validation_test()
{
    kernel_Error error{};
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    const auto rand_str{random_string(16)};
    auto path_root{std::filesystem::temp_directory_path() / ("test_bitcoin_kernel_" + rand_str)};
    std::filesystem::create_directories(path_root);

    KernelNotifications notifications{};
    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_REGTEST)};
    assert_error_ok(error);
    auto chainman{create_chainman(path_root, error, context)};
    assert_error_ok(error);

    auto blocks{read_blocks("block_data.txt")};
    for (auto& block_str : blocks) {
        Block block{block_str, error};
        assert_error_ok(error);
        chainman->ValidateBlock(block, error);
        assert_error_ok(error);
    }
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

    chainman_mainnet_validation_test();

    chainman_regtest_validation_test();

    std::cout << "Libbitcoinkernel test completed.\n";
    return 0;
}
