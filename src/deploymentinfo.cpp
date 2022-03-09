// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deploymentinfo.h>

#include <consensus/params.h>

const struct VBDeploymentInfo VersionBitsDeploymentInfo[Consensus::MAX_VERSION_BITS_DEPLOYMENTS] = {
    {
        /*.name =*/ "testdummy",
        /*.gbt_force =*/ true,
    },
    {
        /*.name =*/ "taproot",
        /*.gbt_force =*/ true,
    },
};

std::string DeploymentName(Consensus::BuriedDeployment dep)
{
    assert(ValidDeployment(dep));
    switch (dep) {
    case Consensus::DEPLOYMENT_HEIGHTINCB:
        return "bip34";
    case Consensus::DEPLOYMENT_CLTV:
        return "bip65";
    case Consensus::DEPLOYMENT_DERSIG:
        return "bip66";
    case Consensus::DEPLOYMENT_CSV:
        return "csv";
    case Consensus::DEPLOYMENT_SEGWIT:
        return "segwit";
    } // no default case, so the compiler can warn about missing cases
    return "";
}

std::optional<Consensus::BuriedDeployment> GetBuriedDeployment(const std::string& deployment_name) {
    if (deployment_name == "segwit") {
        return Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT;
    } else if (deployment_name == "bip34") {
        return Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB;
    } else if (deployment_name == "dersig") {
        return Consensus::BuriedDeployment::DEPLOYMENT_DERSIG;
    } else if (deployment_name == "cltv") {
        return Consensus::BuriedDeployment::DEPLOYMENT_CLTV;
    } else if (deployment_name == "csv") {
        return Consensus::BuriedDeployment::DEPLOYMENT_CSV;
    }
    return std::nullopt;
}
