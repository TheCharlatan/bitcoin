// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_ABORT_H
#define BITCOIN_NODE_ABORT_H

#include <kernel/fatal_condition.h>
#include <util/result.h>
#include <util/translation.h>

#include <atomic>
#include <string>

namespace util {
class SignalInterrupt;
} // namespace util

namespace node {
void AbortNode(util::SignalInterrupt* shutdown, std::atomic<int>& exit_status, const std::string& debug_message, const bilingual_str& user_message = {});

template<typename T>
[[nodiscard]] T CheckFatal(util::Result<T, FatalCondition> condition, util::SignalInterrupt* shutdown, std::atomic<int>& exit_status) {
    if (!condition.GetErrors().empty() || !condition) {
        AbortNode(shutdown, exit_status, ErrorString(condition).original, ErrorString(condition));
    }
    if constexpr(std::is_same_v<T, bool>) {
        if (!condition) {
            return false;
        }
        return condition.value();
    }
}

} // namespace node

#endif // BITCOIN_NODE_ABORT_H
