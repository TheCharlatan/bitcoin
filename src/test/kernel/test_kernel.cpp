// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>
#include <kernel/bitcoinkernel_wrapper.h>

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <span>
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

class TestLog
{
public:
    void LogMessage(const char* message)
    {
        std::cout << "kernel: " << message;
    }
};

constexpr auto VERIFY_ALL_PRE_SEGWIT{kernel_SCRIPT_FLAGS_VERIFY_P2SH | kernel_SCRIPT_FLAGS_VERIFY_DERSIG |
                                     kernel_SCRIPT_FLAGS_VERIFY_NULLDUMMY | kernel_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY |
                                     kernel_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY};
constexpr auto VERIFY_ALL_PRE_TAPROOT{VERIFY_ALL_PRE_SEGWIT | kernel_SCRIPT_FLAGS_VERIFY_WITNESS};

void run_verify_test(
    const ScriptPubkey& spent_script_pubkey,
    const Transaction& spending_tx,
    std::span<TransactionOutput> spent_outputs,
    int64_t amount,
    unsigned int input_index,
    bool taproot)
{
    assert(spending_tx);
    assert(spent_script_pubkey);
    auto status = kernel_ScriptVerifyStatus::kernel_SCRIPT_VERIFY_OK;

    if (taproot) {
        verify_script(
            spent_script_pubkey,
            amount,
            spending_tx,
            spent_outputs,
            input_index,
            kernel_SCRIPT_FLAGS_VERIFY_ALL,
            status);
        assert(status == kernel_SCRIPT_VERIFY_OK);
    } else {
        assert(!verify_script(
            spent_script_pubkey,
            amount,
            spending_tx,
            spent_outputs,
            input_index,
            kernel_SCRIPT_FLAGS_VERIFY_ALL,
            status));
        assert(status == kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED);
        status = kernel_SCRIPT_VERIFY_OK;
    }

    assert(verify_script(
        spent_script_pubkey,
        amount,
        spending_tx,
        spent_outputs,
        input_index,
        VERIFY_ALL_PRE_TAPROOT,
        status));
    assert(status == kernel_SCRIPT_VERIFY_OK);

    assert(verify_script(
        spent_script_pubkey,
        0,
        spending_tx,
        spent_outputs,
        input_index,
        VERIFY_ALL_PRE_SEGWIT,
        status));
    assert(status == kernel_SCRIPT_VERIFY_OK);

    assert(!verify_script(
        spent_script_pubkey,
        amount,
        spending_tx,
        spent_outputs,
        input_index,
        VERIFY_ALL_PRE_TAPROOT << 2,
        status));
    assert(status == kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS);

    assert(!verify_script(
        spent_script_pubkey,
        amount,
        spending_tx,
        spent_outputs,
        5,
        VERIFY_ALL_PRE_TAPROOT,
        status));
    assert(status == kernel_SCRIPT_VERIFY_ERROR_TX_INPUT_INDEX);
    status = kernel_SCRIPT_VERIFY_OK;
}

void transaction_test()
{
    auto tx_data{hex_string_to_char_vec("02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700")};
    auto tx{Transaction{tx_data}};
    assert(tx);
    auto broken_tx_data{std::span<unsigned char>{tx_data.begin(), tx_data.begin() + 10}};
    auto broken_tx{Transaction{broken_tx_data}};
    assert(!broken_tx);
}

void script_verify_test()
{
    // Legacy transaction aca326a724eda9a461c10a876534ecd5ae7b27f10f26c3862fb996f80ea2d45d
    run_verify_test(
        /*spent_script_pubkey*/ ScriptPubkey{hex_string_to_char_vec("76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac")},
        /*spending_tx*/ Transaction{hex_string_to_char_vec("02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700")},
        /*spent_outputs*/ {},
        /*amount*/ 0,
        /*input_index*/ 0,
        /*is_taproot*/ false);

    // Segwit transaction 1a3e89644985fbbb41e0dcfe176739813542b5937003c46a07de1e3ee7a4a7f3
    run_verify_test(
        /*spent_script_pubkey*/ ScriptPubkey{hex_string_to_char_vec("0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d")},
        /*spending_tx*/ Transaction{hex_string_to_char_vec("010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000")},
        /*spent_outputs*/ {},
        /*amount*/ 18393430,
        /*input_index*/ 0,
        /*is_taproot*/ false);

    // Taproot transaction 33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036
    auto taproot_spent_script_pubkey{ScriptPubkey{hex_string_to_char_vec("5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0")}};
    std::vector<TransactionOutput> spent_outputs;
    spent_outputs.emplace_back(taproot_spent_script_pubkey, 88480);
    run_verify_test(
        /*spent_script_pubkey*/ taproot_spent_script_pubkey,
        /*spending_tx*/ Transaction{hex_string_to_char_vec("01000000000101b9cb0da76784960e000d63f0453221aeeb6df97f2119d35c3051065bc9881eab0000000000fdffffff020000000000000000186a16546170726f6f74204654572120406269746275673432a059010000000000225120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc00247304402204bf50f2fea3a2fbf4db8f0de602d9f41665fe153840c1b6f17c0c0abefa42f0b0220631fe0968b166b00cb3027c8817f50ce8353e9d5de43c29348b75b6600f231fc012102b14f0e661960252f8f37486e7fe27431c9f94627a617da66ca9678e6a2218ce1ffd30a00")},
        /*spent_outputs*/ spent_outputs,
        /*amount*/ 88480,
        /*input_index*/ 0,
        /*is_taproot*/ true);
}

void logging_test()
{
    kernel_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };

    assert(kernel_add_log_level_category(kernel_LogCategory::kernel_LOG_BENCH, kernel_LogLevel::kernel_LOG_TRACE));
    assert(kernel_disable_log_category(kernel_LogCategory::kernel_LOG_BENCH));
    assert(kernel_enable_log_category(kernel_LogCategory::kernel_LOG_VALIDATION));
    assert(kernel_disable_log_category(kernel_LogCategory::kernel_LOG_VALIDATION));

    // Check that connecting, connecting another, and then disconnecting and connecting a logger again works.
    {
        assert(kernel_add_log_level_category(kernel_LogCategory::kernel_LOG_KERNEL, kernel_LogLevel::kernel_LOG_TRACE));
        assert(kernel_enable_log_category(kernel_LogCategory::kernel_LOG_KERNEL));
        Logger logger{std::make_unique<TestLog>(TestLog{}), logging_options};
        assert(logger);
        Logger logger_2{std::make_unique<TestLog>(TestLog{}), logging_options};
        assert(logger_2);
    }
    Logger logger{std::make_unique<TestLog>(TestLog{}), logging_options};
    assert(logger);
}

void context_test()
{
    { // test default context
        Context context{};
        assert(context);
    }

    { // test with context options
        ContextOptions options{};
        Context context{options};
        assert(context);
    }
}

int main()
{
    transaction_test();
    script_verify_test();
    logging_test();

    kernel_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };
    Logger logger{std::make_unique<TestLog>(TestLog{}), logging_options};

    context_test();

    std::cout << "Libbitcoinkernel test completed." << std::endl;
    return 0;
}
