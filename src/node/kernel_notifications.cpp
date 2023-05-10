// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/kernel_notifications.h>

#include <node/interface_ui.h>

namespace node {

void KernelNotifications::notifyBlockTip(SynchronizationState state, CBlockIndex* index)
{
    uiInterface.NotifyBlockTip(state, index);
}

void KernelNotifications::notifyHeaderTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync)
{
    uiInterface.NotifyHeaderTip(state, height, timestamp, presync);
}

void KernelNotifications::notifyProgress(const std::string& title, int progress_percent, bool resume_possible)
{
    uiInterface.ShowProgress(title, progress_percent, resume_possible);
}

} // namespace node
