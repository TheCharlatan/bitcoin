// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_CHAINSTATEMANAGER_NOTIFICATIONS_H
#define BITCOIN_NODE_CHAINSTATEMANAGER_NOTIFICATIONS_H

#include <kernel/chainstatemanager_opts.h>

namespace node {
kernel::ChainstateManagerNotificationCallbacks DefaultChainstateManagerNotifications();
} // namespace node

#endif // BITCOIN_NODE_CHAINSTATEMANAGER_NOTIFICATIONS_H
