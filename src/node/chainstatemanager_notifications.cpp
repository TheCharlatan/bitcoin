// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstatemanager_notifications.h>

#include <kernel/chainstatemanager_opts.h>
#include <node/interface_ui.h>

#include <cstdint>
#include <functional>
#include <string>

using kernel::ChainstateManagerNotificationCallbacks;

class CBlockIndex;

namespace node {

ChainstateManagerNotificationCallbacks DefaultChainstateManagerNotifications()
{
    return ChainstateManagerNotificationCallbacks{
        .notify_block_tip = [](SynchronizationState state, CBlockIndex* index) { uiInterface.NotifyBlockTip(state, index); },
        .notify_header_tip = [](SynchronizationState state, int64_t height, int64_t timestamp, bool presync) { uiInterface.NotifyHeaderTip(state, height, timestamp, presync); },
        .show_progress = [](const std::string& title, int nProgress, bool resume_possible) { uiInterface.ShowProgress(title, nProgress, resume_possible); },
    };
}
} // namespace node
