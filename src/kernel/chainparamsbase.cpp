// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparamsbase.h>

#include <tinyformat.h>

const std::string CBaseChainParams::MAIN = "main";
const std::string CBaseChainParams::TESTNET = "test";
const std::string CBaseChainParams::SIGNET = "signet";
const std::string CBaseChainParams::REGTEST = "regtest";

/**
 * Port numbers for incoming Tor connections (8334, 18334, 38334, 18445) have
 * been chosen arbitrarily to keep ranges of used ports tight.
 */
std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::make_unique<CBaseChainParams>("", 8332, 8334);
    } else if (chain == CBaseChainParams::TESTNET) {
        return std::make_unique<CBaseChainParams>("testnet3", 18332, 18334);
    } else if (chain == CBaseChainParams::SIGNET) {
        return std::make_unique<CBaseChainParams>("signet", 38332, 38334);
    } else if (chain == CBaseChainParams::REGTEST) {
        return std::make_unique<CBaseChainParams>("regtest", 18443, 18445);
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

void SetGlobalBaseParams(const std::string& chain)
{
    globalChainBaseParams = CreateBaseChainParams(chain);
}

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}
