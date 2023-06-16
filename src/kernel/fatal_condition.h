// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_FATAL_CONDITION_H
#define BITCOIN_KERNEL_FATAL_CONDITION_H

enum class FatalCondition {
    BlockFileImportSystemError,
    ChainstateRenameFailed,
    ConnectBestBlockFailed,
    DisconnectBlockFailed,
    NoChainstatePaths,
    ReadBlockFailed,
    SnapshotAlreadyValidated,
    SnapshotBaseBlockhashMismatch,
    SnapshotChainstateDirRemovalFailed,
    SnapshotHashMismatch,
    SnapshotMissingChainparams,
    SnapshotStatsFailed,
    SystemError,
};

#endif // BITCOIN_KERNEL_FATAL_CONDITION_H
