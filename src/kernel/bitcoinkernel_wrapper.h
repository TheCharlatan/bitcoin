// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
#define BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H

#include <kernel/bitcoinkernel.h>

#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <vector>

class Transaction;
class TransactionOutput;

enum class LogCategory : btck_LogCategory
{
    ALL = btck_LogCategory_ALL,
    BENCH = btck_LogCategory_BENCH,
    BLOCKSTORAGE = btck_LogCategory_BLOCKSTORAGE,
    COINDB = btck_LogCategory_COINDB,
    LEVELDB = btck_LogCategory_LEVELDB,
    MEMPOOL = btck_LogCategory_MEMPOOL,
    PRUNE = btck_LogCategory_PRUNE,
    RAND = btck_LogCategory_RAND,
    REINDEX = btck_LogCategory_REINDEX,
    VALIDATION = btck_LogCategory_VALIDATION,
    KERNEL = btck_LogCategory_KERNEL
};

enum class LogLevel : btck_LogLevel
{
    TRACE_LEVEL = btck_LogLevel_TRACE,
    DEBUG_LEVEL = btck_LogLevel_DEBUG,
    INFO_LEVEL = btck_LogLevel_INFO
};

enum class ScriptVerifyStatus : btck_ScriptVerifyStatus
{
    OK = btck_ScriptVerifyStatus_SCRIPT_VERIFY_OK,
    ERROR_INVALID_FLAGS_COMBINATION = btck_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION,
    ERROR_SPENT_OUTPUTS_REQUIRED = btck_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED,
};

enum class ScriptVerificationFlags : btck_ScriptVerificationFlags
{
    NONE = btck_ScriptVerificationFlags_NONE,
    P2SH = btck_ScriptVerificationFlags_P2SH,
    DERSIG = btck_ScriptVerificationFlags_DERSIG,
    NULLDUMMY = btck_ScriptVerificationFlags_NULLDUMMY,
    CHECKLOCKTIMEVERIFY = btck_ScriptVerificationFlags_CHECKLOCKTIMEVERIFY,
    CHECKSEQUENCEVERIFY = btck_ScriptVerificationFlags_CHECKSEQUENCEVERIFY,
    WITNESS = btck_ScriptVerificationFlags_WITNESS,
    TAPROOT = btck_ScriptVerificationFlags_TAPROOT,
    ALL = btck_ScriptVerificationFlags_ALL
};

template<typename T>
struct is_bitmask_enum : std::false_type {};

template<>
struct is_bitmask_enum<ScriptVerificationFlags> : std::true_type {};

template<typename T>
concept BitmaskEnum = is_bitmask_enum<T>::value;

template<BitmaskEnum T>
constexpr T operator|(T lhs, T rhs) {
    return static_cast<T>(
        static_cast<std::underlying_type_t<T>>(lhs) | static_cast<std::underlying_type_t<T>>(rhs)
    );
}

template<BitmaskEnum T>
constexpr T operator&(T lhs, T rhs) {
    return static_cast<T>(
        static_cast<std::underlying_type_t<T>>(lhs) & static_cast<std::underlying_type_t<T>>(rhs)
    );
}

template<BitmaskEnum T>
constexpr T operator^(T lhs, T rhs) {
    return static_cast<T>(
        static_cast<std::underlying_type_t<T>>(lhs) ^ static_cast<std::underlying_type_t<T>>(rhs)
    );
}

template<BitmaskEnum T>
constexpr T operator~(T value) {
    return static_cast<T>(~static_cast<std::underlying_type_t<T>>(value));
}

template<BitmaskEnum T>
constexpr T& operator|=(T& lhs, T rhs) {
    return lhs = lhs | rhs;
}

template<BitmaskEnum T>
constexpr T& operator&=(T& lhs, T rhs) {
    return lhs = lhs & rhs;
}

template<BitmaskEnum T>
constexpr T& operator^=(T& lhs, T rhs) {
    return lhs = lhs ^ rhs;
}

template <typename T>
T check(T ptr)
{
    if (ptr == nullptr) {
        throw std::runtime_error("failed to instantiate btck object");
    }
    return ptr;
}

template <typename T>
class RefWrapper
{
private:
    T m_ref_data;

public:
    RefWrapper(T&& data) : m_ref_data{std::move(data)} {}

    // Copying this data type might be dangerous, so prohibit it.
    RefWrapper(const RefWrapper&) = delete;
    RefWrapper& operator=(const RefWrapper& other) = delete;

    T& Get()
    {
        return m_ref_data;
    }
};

template <typename T>
std::vector<std::byte> write_bytes(const T* object, int (*to_bytes)(const T*, btck_WriteBytes, void*))
{
    std::vector<std::byte> bytes;
    struct UserData {
        std::vector<std::byte>* bytes;
        std::exception_ptr exception;
    };
    UserData user_data = UserData{.bytes = &bytes, .exception = nullptr};

    constexpr auto const write = +[](const void* buffer, size_t len, void* user_data) {
        auto& data = *reinterpret_cast<UserData*>(user_data);
        auto& bytes = *data.bytes;
        try {
            auto const* first = static_cast<const std::byte*>(buffer);
            auto const* last = first + len;
            bytes.insert(bytes.end(), first, last);
            return 0;
        } catch (...) {
            data.exception = std::current_exception();
            return -1;
        }
    };

    if (to_bytes(object, write, &user_data) != 0) {
        std::rethrow_exception(user_data.exception);
    }
    return bytes;
}

template <typename T, void(*DeleterFunc)(T*)>
class Handle
{
private:
    struct Deleter {
        void operator()(T* ptr) const noexcept
        {
            if (ptr) DeleterFunc(ptr);
        }
    };

    std::unique_ptr<T, Deleter> m_handle;

protected:
    explicit Handle(T* handle) : m_handle(handle) {}

public:
    T* impl() { return m_handle.get(); }
    const T* impl() const { return m_handle.get(); }

    void reset(T* handle = nullptr) { m_handle.reset(handle); }
};

class ScriptPubkey : public Handle<btck_ScriptPubkey, btck_script_pubkey_destroy>
{
public:
    ScriptPubkey(std::span<const std::byte> script_pubkey)
        : Handle(check(btck_script_pubkey_create(script_pubkey.data(), script_pubkey.size())))
    {
    }

    bool Verify(int64_t amount,
               const Transaction& tx_to,
               const std::span<const TransactionOutput> spent_outputs,
               unsigned int input_index,
               ScriptVerificationFlags flags,
               ScriptVerifyStatus& status) const;

    // Copy constructor and assignment
    ScriptPubkey(const ScriptPubkey& other)
        : Handle(check(btck_script_pubkey_copy(other.impl())))
    {
    }
    ScriptPubkey& operator=(const ScriptPubkey& other)
    {
        if (this != &other) {
            reset(check(btck_script_pubkey_copy(other.impl())));
        }
        return *this;
    }

    ScriptPubkey(btck_ScriptPubkey* script_pubkey)
        : Handle{check(script_pubkey)}
    {
    }

    std::vector<std::byte> ToBytes() const
    {
        return write_bytes(impl(), btck_script_pubkey_to_bytes);
    }

    friend class TransactionOutput;
};

class TransactionOutput : public Handle<btck_TransactionOutput, btck_transaction_output_destroy>
{
public:
    TransactionOutput(const ScriptPubkey& script_pubkey, int64_t amount)
        : Handle{check(btck_transaction_output_create(script_pubkey.impl(), amount))}
    {
    }

    // Copy constructor and assignment
    TransactionOutput(const TransactionOutput& other)
        : Handle{check(btck_transaction_output_copy(other.impl()))} {}
    TransactionOutput& operator=(const TransactionOutput& other)
    {
        if (this != &other) {
            reset(check(btck_transaction_output_copy(other.impl())));
        }
        return *this;
    }

    TransactionOutput(btck_TransactionOutput* transaction_output)
        : Handle{check(transaction_output)}
    {
    }

    uint64_t GetAmount() const
    {
        return btck_transaction_output_get_amount(impl());
    }

    RefWrapper<ScriptPubkey> GetScriptPubkey() const
    {
        return ScriptPubkey{btck_transaction_output_get_script_pubkey(impl())};
    }

    friend class ScriptPubkey;
    friend class Transaction;
};

class Transaction : public Handle<btck_Transaction, btck_transaction_destroy>
{
public:
    Transaction(std::span<const std::byte> raw_transaction)
        : Handle{check(btck_transaction_create(raw_transaction.data(), raw_transaction.size()))}
    {
    }

    // Copy constructor and assignment
    Transaction(const Transaction& other)
        : Handle{check(btck_transaction_copy(other.impl()))} {}
    Transaction& operator=(const Transaction& other)
    {
        if (this != &other) {
            reset(check(btck_transaction_copy(other.impl())));
        }
        return *this;
    }

    uint64_t CountOutputs() const
    {
        return btck_transaction_count_outputs(impl());
    }

    uint64_t CountInputs() const
    {
        return btck_transaction_count_inputs(impl());
    }

    RefWrapper<TransactionOutput> GetOutput(uint64_t index) const
    {
        return TransactionOutput{btck_transaction_get_output_at(impl(), index)};
    }

    std::vector<std::byte> ToBytes() const
    {
        return write_bytes(impl(), btck_transaction_to_bytes);
    }

    friend class ScriptPubkey;
};

bool ScriptPubkey::Verify(int64_t amount,
                  const Transaction& tx_to,
                  const std::span<const TransactionOutput> spent_outputs,
                  unsigned int input_index,
                  ScriptVerificationFlags flags,
                  ScriptVerifyStatus& status) const
{
    const btck_TransactionOutput** spent_outputs_ptr = nullptr;
    std::vector<const btck_TransactionOutput*> raw_spent_outputs;
    if (spent_outputs.size() > 0) {
        raw_spent_outputs.reserve(spent_outputs.size());

        for (const auto& output : spent_outputs) {
            raw_spent_outputs.push_back(output.impl());
        }
        spent_outputs_ptr = raw_spent_outputs.data();
    }
    auto result = btck_script_pubkey_verify(
        impl(),
        amount,
        tx_to.impl(),
        spent_outputs_ptr, spent_outputs.size(),
        input_index,
        static_cast<btck_ScriptVerificationFlags>(flags),
        reinterpret_cast<btck_ScriptVerifyStatus*>(&status));
    return result == 1;
}

void logging_disable()
{
    btck_logging_disable();
}

void logging_set_level_category(LogCategory category, LogLevel level)
{
    btck_logging_set_level_category(static_cast<btck_LogCategory>(category), static_cast<btck_LogLevel>(level));
}

void logging_enable_category(LogCategory category)
{
    btck_logging_enable_category(static_cast<btck_LogCategory>(category));
}

void logging_disable_category(LogCategory category)
{
    btck_logging_disable_category(static_cast<btck_LogCategory>(category));
}

template <typename T>
concept Log = requires(T a, std::string_view message) {
    { a.LogMessage(message) } -> std::same_as<void>;
};

template <Log T>
class Logger : Handle<btck_LoggingConnection, btck_logging_connection_destroy>
{
private:
    std::unique_ptr<T> m_log;

public:
    Logger(std::unique_ptr<T> log, const btck_LoggingOptions& logging_options)
        : Handle{check(btck_logging_connection_create(
              [](void* user_data, const char* message, size_t message_len) { static_cast<T*>(user_data)->LogMessage({message, message_len}); },
              log.get(),
              logging_options))},
          m_log{std::move(log)}
    {
    }
};

#endif // BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
