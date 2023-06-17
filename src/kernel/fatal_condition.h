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

    SnapshotAlreadyValidated,

    // The blockhash of the current tip of the background validation chainstate does
    // not match the one expected by the snapshot chainstate.
    SnapshotBaseBlockhashMismatch,

    SnapshotChainstateDirRemovalFailed,

    // The UTXO set hash of the background validation chainstate does not match
    // the one expected by assumeutxo chainparams.
    SnapshotHashMismatch,

    // Expected assumeutxo configuration data is not found for the height of the
    // base block.
    SnapshotMissingChainparams,

    // Failed to generate UTXO statistics (to check UTXO set hash) for the background
    // chainstate.
    SnapshotStatsFailed,
    SystemError,
};

#endif // BITCOIN_KERNEL_FATAL_CONDITION_H
