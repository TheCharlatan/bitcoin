// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

struct ByteArray {
    const unsigned char* data;
    size_t size;
};


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

    ~ContextOptions()
    {
        kernel_context_options_destroy(m_options);
    }

    friend class Context;
};

class Context
{
private:
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
    kernel_Error error;
    error.code = kernel_ErrorCode::kernel_ERROR_OK;

    Logger logger{error};
    assert_error_ok(error);

    verify_test(
        "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
        "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
        0, 0);

    default_context_test();

    context_test();

    std::cout << "Libbitcoinkernel test completed.\n";
    return 0;
}
