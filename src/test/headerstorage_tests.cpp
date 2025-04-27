// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <kernel/headerstorage.h>
#include <logging.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/hasher.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(headerstorage_tests, BasicTestingSetup)

static void print_contents(const fs::path& data_file)
{
    FILE* file = fsbridge::fopen(data_file, "rb");
    std::vector<unsigned char> buffer(350);
    size_t read = fread(buffer.data(), 1, 350, file);
    fclose(file);

    std::cout << "File contents " << data_file << "(hex, " << read << " bytes):" << std::endl;
    for (size_t i = 0; i < read; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
        if (i % 16 == 15) std::cout << std::endl;
    }
    std::cout << std::dec << std::endl;
}


CBlockIndex* InsertBlockIndex(std::unordered_map<uint256, CBlockIndex, BlockHasher>& block_map, const uint256& hash)
{
    if (hash.IsNull()) {
        return nullptr;
    }
    LogInfo("Inserting a new element");
    const auto [mi, inserted]{block_map.try_emplace(hash)};
    CBlockIndex* pindex = &(*mi).second;
    if (inserted) {
        pindex->phashBlock = &((*mi).first);
    }
    return pindex;
}

void check_block_file_info(uint32_t file, CBlockFileInfo& file_info, BlockTreeStore& store)
{
    CBlockFileInfo retrieve_info;
    BOOST_CHECK(store.ReadBlockFileInfo(file, retrieve_info));
    BOOST_CHECK(file_info.nBlocks == retrieve_info.nBlocks);
    BOOST_CHECK(file_info.nSize == retrieve_info.nSize);
    BOOST_CHECK(file_info.nUndoSize == retrieve_info.nUndoSize);
    BOOST_CHECK(file_info.nHeightFirst == retrieve_info.nHeightFirst);
    BOOST_CHECK(file_info.nHeightLast == retrieve_info.nHeightLast);
    BOOST_CHECK(file_info.nTimeFirst == retrieve_info.nTimeFirst);
    BOOST_CHECK(file_info.nTimeLast == retrieve_info.nTimeLast);
}

void check_block_map(const std::unordered_map<uint256, CBlockIndex, BlockHasher>& block_map, const std::vector<CBlockIndex*>& blockinfo)
{
    LOCK(::cs_main);
    BOOST_CHECK_EQUAL(block_map.size(), blockinfo.size());
    for (const auto& block : blockinfo) {
        auto hash{block->GetBlockHeader().GetHash()};
        auto it = block_map.find(hash);
        BOOST_CHECK(it != block_map.end());
        const auto& index = it->second;
        BOOST_CHECK_EQUAL(index.nHeight, block->nHeight);
        BOOST_CHECK_EQUAL(index.nTime, block->nTime);
        BOOST_CHECK_EQUAL(index.nBits, block->nBits);
        BOOST_CHECK_EQUAL(index.nStatus, block->nStatus);
    }
}

BOOST_AUTO_TEST_CASE(HeaderFilesFormat)
{
    fs::path block_tree_store_dir{m_args.GetDataDirBase()};
    auto header_file{block_tree_store_dir / HEADER_FILE_NAME};
    auto block_files_file{block_tree_store_dir / BLOCK_FILES_FILE_NAME};
    auto params{CreateChainParams(gArgs, ChainType::REGTEST)};
    BlockTreeStore store{block_tree_store_dir, *params};

    // Check headers.dat
    {
        auto file = AutoFile{fsbridge::fopen(header_file, "rb")};
        uint32_t magic;
        file >> magic;
        BOOST_CHECK_EQUAL(magic, HEADER_FILE_MAGIC);

        uint32_t version;
        file >> version;
        BOOST_CHECK_EQUAL(version, HEADER_FILE_VERSION);

        bool reindexing;
        file >> reindexing;
        BOOST_CHECK_EQUAL(reindexing, false);

        int64_t data_end;
        file >> data_end;
        BOOST_CHECK_EQUAL(data_end, HEADER_FILE_DATA_START_POS);

        file.seek(0, SEEK_END);
        long filesize = file.tell();
        BOOST_CHECK_GE(filesize, params->AssumedHeaderStoreSize());
    }

    // Check blockfiles.dat
    {
        auto file = AutoFile{fsbridge::fopen(block_files_file, "rb")};
        uint32_t magic;
        file >> magic;
        BOOST_CHECK_EQUAL(magic, BLOCK_FILES_FILE_MAGIC);

        uint32_t version;
        file >> version;
        BOOST_CHECK_EQUAL(version, BLOCK_FILES_FILE_VERSION);

        int32_t last_block;
        file >> last_block;
        BOOST_CHECK_EQUAL(last_block, 0);

        bool pruned;
        file >> pruned;
        BOOST_CHECK_EQUAL(pruned, false);

        file.seek(0, SEEK_END);
        long filesize = file.tell();
        BOOST_CHECK_GE(filesize, BLOCK_FILES_PRUNE_FLAG_POS + 1);
    }
}

BOOST_AUTO_TEST_CASE(HeaderStore)
{
    LOCK(::cs_main);
    std::unordered_map<uint256, CBlockIndex, BlockHasher> block_map;
    fs::path block_tree_store_dir{m_args.GetDataDirBase()};
    auto header_file{block_tree_store_dir / HEADER_FILE_NAME};
    auto block_files_file{block_tree_store_dir / BLOCK_FILES_FILE_NAME};
    auto params{CreateChainParams(gArgs, ChainType::REGTEST)};
    BlockTreeStore store{block_tree_store_dir, *params};

    BOOST_CHECK(fs::exists(header_file));
    bool reindexing = true;
    store.ReadReindexing(reindexing);
    BOOST_CHECK(!reindexing);

    store.WriteReindexing(true);
    store.ReadReindexing(reindexing);
    BOOST_CHECK(reindexing);

    store.WriteReindexing(false);
    store.ReadReindexing(reindexing);
    BOOST_CHECK(!reindexing);
    print_contents(header_file);

    BOOST_CHECK(fs::exists(block_files_file));
    print_contents(block_files_file);
    int last_block;
    store.ReadLastBlockFile(last_block);
    BOOST_CHECK_EQUAL(last_block, 0);
    bool pruned = false;
    store.ReadPruned(pruned);
    BOOST_CHECK(!pruned);

    store.WritePruned(true);
    store.ReadPruned(pruned);
    BOOST_CHECK(pruned);
    store.WritePruned(false);
    store.ReadPruned(pruned);
    BOOST_CHECK(!pruned);

    std::vector<std::pair<int, CBlockFileInfo*>> fileinfo;
    CBlockFileInfo info{};
    info.nBlocks = 1;
    info.nSize = 2;
    info.nUndoSize = 3;
    info.nHeightFirst = 4;
    info.nHeightLast = 5;
    info.nTimeFirst = 6;
    info.nTimeLast = 7;

    fileinfo.emplace_back(0, &info);
    int32_t last_file{1};
    std::vector<CBlockIndex*> blockinfo;
    auto block_index = std::make_unique<CBlockIndex>();
    {
        block_index->nHeight = 46367;
        block_index->nTime = 1269211443;
        block_index->nBits = 0x1f111111;
        block_index->nStatus = 1;
    }
    blockinfo.emplace_back(block_index.get());

    BOOST_CHECK(store.WriteBatchSync(fileinfo, last_file, blockinfo));
    print_contents(block_files_file);
    print_contents(header_file);

    BOOST_CHECK(!store.LoadBlockIndexGuts(
        Consensus::Params(),
        [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
        m_interrupt));
    BOOST_CHECK(store.LoadBlockIndexGuts(
        Consensus::Params(),
        [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
        m_interrupt,
        false));
    check_block_map(block_map, blockinfo);

    info.nBlocks = 2;
    info.nSize = 3;
    info.nUndoSize = 4;
    info.nHeightFirst = 5;
    info.nHeightLast = 6;
    info.nTimeFirst = 7;
    info.nTimeLast = 8;
    CBlockFileInfo info_two{};
    info_two.nBlocks = 1;
    info_two.nSize = 2;
    info_two.nUndoSize = 3;
    info_two.nHeightFirst = 4;
    info_two.nHeightLast = 5;
    info_two.nTimeFirst = 6;
    info_two.nTimeLast = 7;

    fileinfo.emplace_back(1, &info_two);

    {
        block_index->nHeight = 46000;
        block_index->nTime = 1269210000;
        block_index->nBits = 0x1d111111;
        block_index->nStatus = 120;
    }

    BOOST_CHECK(store.WriteBatchSync(fileinfo, last_file, blockinfo));
    print_contents(block_files_file);
    print_contents(header_file);

    block_map.clear();
    BOOST_CHECK(store.LoadBlockIndexGuts(
        Consensus::Params(),
        [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
        m_interrupt,
        false));
    check_block_map(block_map, blockinfo);

    auto block_index_two = std::make_unique<CBlockIndex>();
    {
        block_index_two->nHeight = 999;
        block_index_two->nTime = 1269990000;
        block_index_two->nBits = 0x1d111122;
        block_index_two->nStatus = 45;
    }
    blockinfo.emplace_back(block_index_two.get());
    block_map.clear();
    BOOST_CHECK(store.WriteBatchSync(fileinfo, last_file, blockinfo));
    print_contents(block_files_file);
    print_contents(header_file);
    BOOST_CHECK(store.LoadBlockIndexGuts(
        Consensus::Params(),
        [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
        m_interrupt,
        false));
    check_block_map(block_map, blockinfo);

    {
        block_index_two->nHeight = 999;
        block_index_two->nTime = 1269990000;
        block_index_two->nBits = 0x1d111122;
        block_index_two->nStatus = 99;
    }
    info_two.nBlocks = 2;
    info_two.nSize = 3;
    info_two.nUndoSize = 4;
    info_two.nHeightFirst = 5;
    info_two.nHeightLast = 6;
    info_two.nTimeFirst = 7;
    info_two.nTimeLast = 8;
    block_map.clear();
    BOOST_CHECK(store.WriteBatchSync(fileinfo, last_file, blockinfo));
    print_contents(block_files_file);
    print_contents(header_file);
    BOOST_CHECK(store.LoadBlockIndexGuts(
        Consensus::Params(),
        [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
        m_interrupt,
        false));
    check_block_map(block_map, blockinfo);
    check_block_file_info(0, info, store);
    check_block_file_info(1, info_two, store);
}

BOOST_AUTO_TEST_SUITE_END()
