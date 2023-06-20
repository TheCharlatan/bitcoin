// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/db.h>
#include <wallet/dump.h>
#include <wallet/migrate.h>

#include <iostream>

using wallet::DatabaseOptions;
using wallet::DatabaseStatus;

namespace {
const TestingSetup* g_setup;
} // namespace

void initialize_wallet_bdb_parser()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

void SetDumpFile(ArgsManager& args) {
    auto dumpfile{args.GetDataDirNet() / "fuzzed_dumpfile.dat"};
    if (fs::exists(dumpfile)) { // Writing into an existing dump file will throw an exception
        remove(dumpfile);
    }
    args.ForceSetArg("-dumpfile", args.GetDataDirNet() / "fuzzed_dumpfile.dat");
}

FUZZ_TARGET_INIT(wallet_bdb_parser, initialize_wallet_bdb_parser)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    const auto wallet_path = g_setup->m_args.GetDataDirNet() / "fuzzed_wallet.dat";

    {
        AutoFile outfile{fsbridge::fopen(wallet_path, "wb")};
        const auto file_data{ConsumeRandomLengthByteVector(fuzzed_data_provider)};
        outfile << Span{file_data};
    }

    const DatabaseOptions options{};
    DatabaseStatus status;
    bilingual_str error;

    try {
        auto db{MakeBerkeleyRODatabase(wallet_path, options, status, error)};
        const auto& node = g_setup->m_node;
        SetDumpFile(*node.args);
        assert(DumpWallet(g_setup->m_args, *db, error));
    }
    catch (const std::runtime_error& e) {
        if (std::string(e.what()) == "AutoFile::ignore: end of file: iostream error") return;
        if (std::string(e.what()) == "AutoFile::read: end of file: iostream error") return;
        if (std::string(e.what()) == "Not a BDB file") return;
        if (std::string(e.what()) == "Unsupported BDB data file version number") return;
        if (std::string(e.what()) == "Unexpected page type, should be 9 (BTree Metadata)") return;
        if (std::string(e.what()) == "Unexpected database flags, should only be 0x20 (subdatabases)") return;
        if (std::string(e.what()) == "Unexpected outer database root page type") return;
        if (std::string(e.what()) == "Unexpected number of entries in outer database root page") return;
        if (std::string(e.what()) == "Subdatabase has an unexpected name") return;
        if (std::string(e.what()) == "Subdatabase page number has unexpected length") return;
        if (std::string(e.what()) == "Unexpected inner database page type") return;
        throw e;
    }
}