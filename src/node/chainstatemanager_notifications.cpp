// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstatemanager_notifications.h>

#include <kernel/chainstatemanager_opts.h>
#include <node/interface_ui.h>

#include <functional>

using kernel::ChainstateManagerNotificationCallbacks;

class CBlockIndex;

namespace node {

ChainstateManagerNotificationCallbacks DefaultChainstateManagerNotifications()
{
    return ChainstateManagerNotificationCallbacks{
        .notify_block_tip = [](SynchronizationState state, CBlockIndex* index) { uiInterface.NotifyBlockTip(state, index); },
    };
}
} // namespace node
