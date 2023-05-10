// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_VALIDATION_NOTIFICATIONS_INTERFACE_H
#define BITCOIN_KERNEL_VALIDATION_NOTIFICATIONS_INTERFACE_H

#include <cstdint>

class CBlockIndex;
enum class SynchronizationState;

namespace kernel {

/**
 * A base class defining functions for notifying about certain validation
 * events.
 */
class ValidationNotifications
{
public:
    virtual ~ValidationNotifications(){};

    virtual void notifyBlockTip(SynchronizationState state, CBlockIndex* index) = 0;
    virtual void notifyHeaderTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) = 0;
};
} // namespace kernel

#endif // BITCOIN_KERNEL_VALIDATION_NOTIFICATIONS_INTERFACE_H
