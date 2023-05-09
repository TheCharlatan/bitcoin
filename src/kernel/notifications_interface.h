// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_NOTIFICATIONS_INTERFACE_H
#define BITCOIN_KERNEL_NOTIFICATIONS_INTERFACE_H

#include <util/translation.h>

#include <cstdint>
#include <string>

class CBlockIndex;
enum class SynchronizationState;

namespace kernel {

/**
 * A base class defining functions for notifying about certain kernel
 * events.
 */
class Notifications
{
public:
    virtual ~Notifications(){};

    virtual void blockTip(SynchronizationState state, CBlockIndex* index) {}
    virtual void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {}
    virtual void progress(const std::string& title, int progress_percent, bool resume_possible) {}
    virtual void warning(const bilingual_str& warning) {}
    virtual void fatalError(const std::string& debug_message, bilingual_str user_message = {}) {}
};
} // namespace kernel

#endif // BITCOIN_KERNEL_NOTIFICATIONS_INTERFACE_H
