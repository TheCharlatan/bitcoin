// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_ABORT_H
#define BITCOIN_NODE_ABORT_H

#include <kernel/fatal_error.h>
#include <util/result.h>
#include <util/translation.h>
#include <validation.h>

#include <atomic>
#include <optional>
#include <string>

namespace util {
class SignalInterrupt;
} // namespace util

namespace node {
void AbortNode(util::SignalInterrupt* shutdown, std::atomic<int>& exit_status, const std::string& debug_message, const bilingual_str& user_message = {});

template <typename T>
std::optional<T> HandleFatalError(util::Result<T, kernel::FatalError> result, util::SignalInterrupt* shutdown, std::atomic<int>& exit_status)
{
    if (!result.GetErrors().empty() || !result) {
        AbortNode(shutdown, exit_status, ErrorString(result).original, ErrorString(result));
    }
    if (!result) return std::nullopt;
    return result.value();
}

template <typename T>
[[nodiscard]] T CheckFatal(util::Result<T, kernel::FatalError> result, util::SignalInterrupt* shutdown, std::atomic<int>& exit_status)
{
    if (IsFatal(result)) {
        AbortNode(shutdown, exit_status, ErrorString(result).original, ErrorString(result));
    }
    if constexpr (std::is_same_v<T, bool>) {
        if (!result) {
            return false;
        }
        return result.value();
    }
}

#define UNWRAP_OR_RETURN_FATAL(VALUE, RESULT, SHUTDOWN, EXIT_STATUS) \
    const auto res{HandleFatalError(RESULT, SHUTDOWN, EXIT_STATUS)}; \
    if (!res) { \
        return; \
    } \
    VALUE{res.value()};

#define UNWRAP_OR_RETURN_TYPED_FATAL(VALUE, RESULT, SHUTDOWN, EXIT_STATUS, RETURN_VALUE) \
    const auto res{HandleFatalError(RESULT, SHUTDOWN, EXIT_STATUS)}; \
    if (!res) { \
        return RETURN_VALUE; \
    } \
    VALUE{res.value()};

} // namespace node

#endif // BITCOIN_NODE_ABORT_H