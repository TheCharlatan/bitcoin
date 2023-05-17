// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/notifications_interface.h>

#include <string>

namespace kernel {

std::string ShutdownReasonToString(ShutdownReason reason)
{
    switch (reason) {
    case kernel::ShutdownReason::FailedConnectingBestBlock:
        return "Failed connecting best block.";
    case kernel::ShutdownReason::StopAfterBlockImport:
        return "Stopping after block import.";
    case kernel::ShutdownReason::StopAtHeight:
        return "Reached block height specified by stop at height.";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

} // namespace kernel
