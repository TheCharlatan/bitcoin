// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_TYPES_H
#define BITCOIN_KERNEL_TYPES_H

/** Current sync state passed to tip changed callbacks. */
enum class SynchronizationState {
    INIT_REINDEX,
    INIT_DOWNLOAD,
    POST_INIT
};

/** A "reason" why a block was invalid, suitable for determining whether the
  * provider of the block should be banned/ignored/disconnected/etc.
  * These are much more granular than the rejection codes, which may be more
  * useful for some other use-cases.
  */
enum class BlockValidationResult {
    BLOCK_RESULT_UNSET = 0,  //!< initial value. Block has not yet been rejected
    BLOCK_CONSENSUS,         //!< invalid by consensus rules (excluding any below reasons)
    BLOCK_CACHED_INVALID,    //!< this block was cached as being invalid and we didn't store the reason why
    BLOCK_INVALID_HEADER,    //!< invalid proof of work or time too old
    BLOCK_MUTATED,           //!< the block's data didn't match the data committed to by the PoW
    BLOCK_MISSING_PREV,      //!< We don't have the previous block the checked one is built on
    BLOCK_INVALID_PREV,      //!< A block this one builds on is invalid
    BLOCK_TIME_FUTURE,       //!< block timestamp was > 2 hours in the future (or our clock is bad)
    BLOCK_HEADER_LOW_WORK    //!< the block header may be on a too-little-work chain
};

#endif // BITCOIN_KERNEL_TYPES_H
