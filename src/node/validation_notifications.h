// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_VALIDATION_NOTIFICATIONS_H
#define BITCOIN_NODE_VALIDATION_NOTIFICATIONS_H

#include <kernel/validation_notifications_interface.h>

#include <cstdint>
#include <string>

class CBlockIndex;

namespace node {
class ValidationNotificationsImpl : public kernel::ValidationNotifications
{
public:
    void notifyBlockTip(SynchronizationState state, CBlockIndex* index) override;

    void notifyHeaderTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override;

    void showProgress(const std::string& title, int nProgress, bool resume_possible) override;
};
} // namespace node

#endif // BITCOIN_NODE_VALIDATION_NOTIFICATIONS_H
