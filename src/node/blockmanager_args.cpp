// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockmanager_args.h>
#include <util/system.h>

namespace node {
void ApplyArgsManOptions(const ArgsManager& args, BlockManager::Options& opts)
{
    if (auto value{args.GetBoolArg("-fastprune")}) opts.fast_prune = *value;
    if (auto value{args.GetBoolArg("-stopafterblockimport")}) opts.stop_after_block_import = *value;
}
} // namespace node
