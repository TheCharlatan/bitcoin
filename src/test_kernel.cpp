// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>
#include <kernel/bitcoinkernel_wrapper.h>

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

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

void context_test()
{
    kernel_Error error;
    error.code = kernel_ErrorCode::kernel_ERROR_OK;
    ContextOptions options{};
    Context context{options, error};
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

    context_test();

    std::cout << "Libbitcoinkernel test completed.\n";
    return 0;
}
