// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>
#include <kernel/bitcoinkernel_wrapper.h>

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

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

std::vector<unsigned char> hex_string_to_char_vec(const std::string& hex)
{
    std::vector<unsigned char> bytes;

    for (size_t i{0}; i < hex.length(); i += 2) {
        std::string byteString{hex.substr(i, 2)};
        unsigned char byte = (char)std::strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

std::vector<std::vector<unsigned char>> read_blocks(const std::string& file_path)
{
    std::vector<std::vector<unsigned char>> lines;
    std::ifstream file{file_path};

    if (!file.is_open()) {
        return lines;
    }

    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(hex_string_to_char_vec(line));
    }
    file.close();
    return lines;
}

void assert_is_error(kernel_Error& error, kernel_ErrorCode code)
{
    if (error.code != code) {
        std::cout << error.message << " error code: " << error.code << "\n";
    }
    assert(error.code == code);
}

void assert_error_ok(kernel_Error& error)
{
    if (error.code != kernel_ErrorCode::kernel_ERROR_OK) {
        std::cout << error.message << " error code: " << error.code << "\n";
        assert(error.code == kernel_ErrorCode::kernel_ERROR_OK);
    }
}

class TestLog
{
public:
    void LogMessage(const char* message)
    {
        std::cout << "kernel: " << message;
    }
};

class TestKernelNotifications : public KernelNotifications<TestKernelNotifications>
{
public:
    void BlockTipHandler(kernel_SynchronizationState state, kernel_BlockIndex* index) override
    {
        std::cout << "Block tip changed" << std::endl;
    }

    void HeaderTipHandler(kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        assert(timestamp > 0);
    }

    void ProgressHandler(const char* title, int progress_percent, bool resume_possible) override
    {
        std::cout << "Made progress: " << title << " " << progress_percent << "%" << std::endl;
    }

    void WarningSetHandler(kernel_Warning warning, const char* message) override
    {
        std::cout << "Kernel warning is set: " << message << std::endl;
    }

    void WarningUnsetHandler(kernel_Warning warning) override
    {
        std::cout << "Kernel warning was unset." << std::endl;
    }

    void FlushErrorHandler(const char* error) override
    {
        std::cout << error << std::endl;
    }

    void FatalErrorHandler(const char* error) override
    {
        std::cout << error << std::endl;
    }
};

class TestTaskRunner : public TaskRunner<TestTaskRunner>
{
};

class TestValidationInterface : public ValidationInterface<TestValidationInterface>
{
public:
    TestValidationInterface() : ValidationInterface() {}

    std::optional<std::vector<unsigned char>> m_expected_valid_block = std::nullopt;

    void BlockChecked(const UnownedBlock block, const kernel_BlockValidationState* state) override
    {
        {
            auto serialized_block{block.GetBlockData()};
            if (m_expected_valid_block.has_value()) {
                assert(m_expected_valid_block.value() == serialized_block);
            }
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
};

const auto VERIFY_ALL_PRE_TAPROOT = kernel_SCRIPT_FLAGS_VERIFY_P2SH | kernel_SCRIPT_FLAGS_VERIFY_DERSIG |
                                    kernel_SCRIPT_FLAGS_VERIFY_NULLDUMMY | kernel_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                    kernel_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY | kernel_SCRIPT_FLAGS_VERIFY_WITNESS;

const auto VERIFY_ALL_PRE_SEGWIT = kernel_SCRIPT_FLAGS_VERIFY_P2SH | kernel_SCRIPT_FLAGS_VERIFY_DERSIG |
                                   kernel_SCRIPT_FLAGS_VERIFY_NULLDUMMY | kernel_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                   kernel_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY;

void verify_test(std::string spent, std::string spending, int64_t amount, unsigned int nIn)
{
    std::vector<unsigned char> script_pubkey{hex_string_to_char_vec(spent)};
    std::vector<unsigned char> spending_tx{hex_string_to_char_vec(spending)};
    std::vector<kernel_TransactionOutput> spent_outputs;
    kernel_Error error{};
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    assert(verify_script(
        script_pubkey,
        amount,
        spending_tx,
        spent_outputs,
        nIn,
        VERIFY_ALL_PRE_TAPROOT,
        error));
    assert_error_ok(error);

    assert(verify_script(
        script_pubkey,
        0,
        spending_tx,
        spent_outputs,
        nIn,
        VERIFY_ALL_PRE_SEGWIT,
        error));
    assert_error_ok(error);

    assert(!verify_script(
        script_pubkey,
        amount,
        spending_tx,
        spent_outputs,
        nIn,
        VERIFY_ALL_PRE_TAPROOT << 2,
        error));
    assert_is_error(error, kernel_ERROR_INVALID_FLAGS);

    assert(!verify_script(
        script_pubkey,
        amount,
        spending_tx,
        spent_outputs,
        nIn,
        kernel_SCRIPT_FLAGS_VERIFY_ALL,
        error));
    assert_is_error(error, kernel_ERROR_SPENT_OUTPUTS_REQUIRED);

    assert(!verify_script(
        script_pubkey,
        amount,
        spending_tx,
        spent_outputs,
        5,
        VERIFY_ALL_PRE_TAPROOT,
        error));
    assert_is_error(error, kernel_ERROR_TX_INDEX);

    auto broken_tx = std::vector<unsigned char>{spending_tx.begin(), spending_tx.begin() + 10};
    assert(!verify_script(
        script_pubkey,
        amount,
        broken_tx,
        spent_outputs,
        nIn,
        VERIFY_ALL_PRE_TAPROOT,
        error));
    assert_is_error(error, kernel_ERROR_TX_DESERIALIZE);
}

void default_context_test()
{
    kernel_Error error;
    error.code = kernel_ErrorCode::kernel_ERROR_OK;
    Context context{error};
    assert_error_ok(error);
}

Context create_context(TestKernelNotifications& notifications, kernel_Error& error, kernel_ChainType chain_type, TestTaskRunner* task_runner = nullptr)
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
                                          bool block_tree_db_in_memory,
                                          bool chainstate_db_in_memory,
                                          kernel_Error& error,
                                          Context& context)
{
    ChainstateManagerOptions chainman_opts{context, path_root, error};
    assert_error_ok(error);
    BlockManagerOptions blockman_opts{context, path_root / "blocks", error};
    assert_error_ok(error);
    assert_error_ok(error);

    // Check that creating invalid options gives us an error
    {
        kernel_Error opts_error{};
        ChainstateManagerOptions opts{context, "////\\\\", opts_error};
        assert_is_error(opts_error, kernel_ERROR_INTERNAL);
    }

    {
        kernel_Error opts_error{};
        BlockManagerOptions opts{context, "////\\\\", opts_error};
        assert_is_error(opts_error, kernel_ERROR_INTERNAL);
    }

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
        assert_error_ok(error);
    }
    if (block_tree_db_in_memory) {
        chainstate_load_opts.SetBlockTreeDbInMemory(block_tree_db_in_memory, error);
        assert_error_ok(error);
    }
    if (chainstate_db_in_memory) {
        chainstate_load_opts.SetChainstateDbInMemory(chainstate_db_in_memory, error);
        assert_error_ok(error);
    }
    chainman->LoadChainstate(chainstate_load_opts, error);
    assert_error_ok(error);

    return chainman;
}

void chainman_in_memory_test()
{
    const auto rand_str{random_string(16)};
    auto path_root{std::filesystem::temp_directory_path() / ("test_bitcoin_kernel_" + rand_str)};
    std::filesystem::create_directories(path_root);
    kernel_Error error;
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    TestKernelNotifications notifications{};
    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_REGTEST)};
    assert_error_ok(error);
    std::cout << "What is going on here?" << std::endl;
    auto chainman{create_chainman(path_root, false, false, true, true, error, context)};

    auto blocks{read_blocks("block_data.txt")};
    for (auto& raw_block: blocks) {
        Block block{raw_block, error};
        assert_error_ok(error);
        chainman->ProcessBlock(block, error);
        assert_error_ok(error);
    }

    assert(!std::filesystem::exists(path_root / "blocks" / "index"));
    assert(!std::filesystem::exists(path_root / "chainstate"));
}

void chainman_mainnet_validation_test(std::filesystem::path path_root)
{
    kernel_Error error{};
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    TestKernelNotifications notifications{};
    TestTaskRunner task_runner{};

    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_MAINNET, &task_runner)};
    assert_error_ok(error);

    TestValidationInterface validation_interface{};
    validation_interface.Register(context, error);
    assert_error_ok(error);

    auto chainman{create_chainman(path_root, false, false, false, false, error, context)};
    assert_error_ok(error);

    {
        // Process an invalid block
        auto raw_block = hex_string_to_char_vec("012300");
        Block block{raw_block, error};
        assert_is_error(error, kernel_ERROR_INTERNAL);
        error.code = kernel_ERROR_OK;
    }
    {
        // Process an empty block
        auto raw_block = hex_string_to_char_vec("");
        Block block{raw_block, error};
        assert_is_error(error, kernel_ERROR_INTERNAL);
        error.code = kernel_ERROR_OK;
    }

    auto raw_block = hex_string_to_char_vec("010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000");
    Block block{raw_block, error};
    assert_error_ok(error);
    validation_interface.m_expected_valid_block.emplace(raw_block);
    assert(block.GetBlockData() == raw_block);
    chainman->ProcessBlock(block, error);
    assert_error_ok(error);

    auto tip = chainman->GetBlockIndexFromTip();
    auto read_block = chainman->ReadBlock(tip, error);
    assert_error_ok(error);
    assert(read_block.GetBlockData() == raw_block);

    // Check that we can read the previous block
    auto tip_2 = tip.GetPreviousBlockIndex(error);
    assert_error_ok(error);
    auto read_block_2 = chainman->ReadBlock(tip_2, error);
    assert_error_ok(error);

    // It should be an error if we go another block back, since the genesis has no ancestor
    auto tip_3 = tip_2.GetPreviousBlockIndex(error);
    assert_is_error(error, kernel_ERROR_OUT_OF_BOUNDS);

    // If we try to validate it again, it should be a duplicate
    assert(!chainman->ProcessBlock(block, error));
    assert_is_error(error, kernel_ERROR_DUPLICATE_BLOCK);

    validation_interface.Unregister(context, error);
    assert_error_ok(error);
}

void chainman_regtest_validation_test()
{
    const auto rand_str{random_string(16)};
    auto path_root{std::filesystem::temp_directory_path() / ("test_bitcoin_kernel_" + rand_str)};
    std::filesystem::create_directories(path_root);
    kernel_Error error;
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    TestKernelNotifications notifications{};
    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_REGTEST)};
    assert_error_ok(error);
    auto chainman{create_chainman(path_root, false, false, false, false, error, context)};
    assert_error_ok(error);

    auto blocks{read_blocks("block_data.txt")};
    for (auto& raw_block: blocks) {
        Block block{raw_block, error};
        assert_error_ok(error);
        chainman->ProcessBlock(block, error);
        assert_error_ok(error);
    }

    auto tip = chainman->GetBlockIndexFromTip();
    auto read_block = chainman->ReadBlock(tip, error);
    assert_error_ok(error);
    assert(read_block.GetBlockData() == blocks[blocks.size() - 1]);

    auto tip_2 = tip.GetPreviousBlockIndex(error);
    assert_error_ok(error);
    auto read_block_2 = chainman->ReadBlock(tip_2, error);
    assert_error_ok(error);
    assert(read_block_2.GetBlockData() == blocks[blocks.size() - 2]);

    auto block_undo = chainman->ReadBlockUndo(tip, error);
    assert_error_ok(error);
    auto tx_undo_size = block_undo.GetTxOutSize(block_undo.m_size - 1);
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

    TestKernelNotifications notifications{};
    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_MAINNET)};
    assert_error_ok(error);
    auto chainman{create_chainman(path_root, true, false, false, false, error, context)};
    assert_error_ok(error);

    std::vector<std::string> import_files;
    chainman->ImportBlocks(import_files, error);
    assert_error_ok(error);

    // Sanity check some block retrievals
    auto genesis_index{chainman->GetBlockIndexFromGenesis()};
    auto genesis_block_raw{chainman->ReadBlock(genesis_index, error).GetBlockData()};
    auto first_index{chainman->GetBlockIndexByHeight(0, error)};
    assert_error_ok(error);
    auto first_block_raw{chainman->ReadBlock(genesis_index, error).GetBlockData()};
    assert(genesis_block_raw == first_block_raw);
    auto first_info{first_index.GetInfo()};
    assert(first_info->height == 0);
    delete first_info;

    auto next_index{chainman->GetNextBlockIndex(first_index, error)};
    assert_error_ok(error);
    auto next_block_string{chainman->ReadBlock(next_index, error).GetBlockData()};
    auto tip_index{chainman->GetBlockIndexFromTip()};
    auto tip_block_string{chainman->ReadBlock(tip_index, error).GetBlockData()};
    auto second_index{chainman->GetBlockIndexByHeight(1, error)};
    assert_error_ok(error);
    auto second_block_string{chainman->ReadBlock(second_index, error).GetBlockData()};
    auto second_info{second_index.GetInfo()};
    assert(second_info->height == 1);
    delete second_info;
    assert(next_block_string == tip_block_string);
    assert(next_block_string == second_block_string);
}

void chainman_reindex_chainstate_test(std::filesystem::path path_root)
{
    kernel_Error error{};
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    TestKernelNotifications notifications{};
    auto context{create_context(notifications, error, kernel_ChainType::kernel_CHAIN_TYPE_MAINNET)};
    assert_error_ok(error);
    auto chainman{create_chainman(path_root, false, true, false, false, error, context)};
    assert_error_ok(error);

    std::vector<std::string> import_files;
    import_files.push_back(path_root / "blocks" / "blk00000.dat");
    chainman->ImportBlocks(import_files, error);
    assert_error_ok(error);
}

int main()
{
    // legacy transaction
    verify_test(
        "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
        "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
        0, 0);

    // segwit transaction
    verify_test(
        "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d",
        "010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
        18393430 , 0);

    kernel_Error error;
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    kernel_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };

    Logger<TestLog>::EnableLogCategory(kernel_LogCategory::kernel_LOG_VALIDATION);
    // Check that connecting, connecting another, and then disconnecting and connecting a logger again works.
    {
        Logger logger{std::make_unique<TestLog>(TestLog{}), logging_options, error};
        assert_error_ok(error);
        Logger logger_2{std::make_unique<TestLog>(TestLog{}), logging_options, error};
        assert_error_ok(error);
    }
    Logger logger{std::make_unique<TestLog>(TestLog{}), logging_options, error};
    assert_error_ok(error);

    default_context_test();

    const auto rand_str{random_string(16)};
    auto path_root{std::filesystem::temp_directory_path() / ("test_bitcoin_kernel_" + rand_str)};
    std::filesystem::create_directories(path_root);

    chainman_in_memory_test();

    chainman_mainnet_validation_test(path_root);

    chainman_regtest_validation_test();

    chainman_reindex_test(path_root);

    chainman_reindex_chainstate_test(path_root);

    std::cout << "Libbitcoinkernel test completed.\n";
    return 0;
}
