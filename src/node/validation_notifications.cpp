// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/validation_notifications_interface.h>
#include <node/validation_notifications.h>

#include <node/interface_ui.h>

namespace node {

void ValidationNotificationsImpl::notifyBlockTip(SynchronizationState state, CBlockIndex* index)
{
    uiInterface.NotifyBlockTip(state, index);
}

void ValidationNotificationsImpl::notifyHeaderTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync)
{
    uiInterface.NotifyHeaderTip(state, height, timestamp, presync);
}

void ValidationNotificationsImpl::showProgress(const std::string& title, int nProgress, bool resume_possible)
{
    uiInterface.ShowProgress(title, nProgress, resume_possible);
}

} // namespace node
