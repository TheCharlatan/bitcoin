// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <util/args.h>
#include <util/time.h>
#include <validation.h>

#include <cstdint>
#include <vector>

namespace {
const TestingSetup* g_setup;
} // namespace

void initialize_validation_load_mempool()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

FUZZ_TARGET_INIT(validation_load_mempool, initialize_validation_load_mempool)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    SetMockTime(ConsumeTime(fuzzed_data_provider));
    FuzzedFileProvider fuzzed_file_provider = ConsumeFile(fuzzed_data_provider);

    CTxMemPool::Limits limits{};
    limits.ancestor_count = gArgs.GetIntArg("-limitancestorcount", limits.ancestor_count);
    limits.ancestor_size = gArgs.GetIntArg("-limitancestorsize", limits.ancestor_size);
    limits.descendant_count = gArgs.GetIntArg("-limitdescendantcount", limits.descendant_count);
    limits.descendant_size = gArgs.GetIntArg("-limitdescendantsize", limits.descendant_size);

    CTxMemPool pool{limits};
    auto fuzzed_fopen = [&](const fs::path&, const char*) {
        return fuzzed_file_provider.open();
    };
    (void)LoadMempool(pool, g_setup->m_node.chainman->ActiveChainstate(), fuzzed_fopen);
    (void)DumpMempool(pool, g_setup->m_node.args->GetDataDirNet() / "mempool.dat", fuzzed_fopen, true);
}
