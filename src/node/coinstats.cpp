// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coinstats.h>

#include <coins.h>
#include <crypto/muhash.h>
#include <hash.h>
#include <index/coinstatsindex.h>
#include <optional>
#include <serialize.h>
#include <uint256.h>
#include <util/overflow.h>
#include <util/system.h>
#include <validation.h>

#include <map>

namespace node {
// Database-independent metric indicating the UTXO set size
uint64_t GetBogoSize(const CScript& script_pub_key)
{
    return 32 /* txid */ +
           4 /* vout index */ +
           4 /* height + coinbase */ +
           8 /* amount */ +
           2 /* scriptPubKey len */ +
           script_pub_key.size() /* scriptPubKey */;
}

CDataStream TxOutSer(const COutPoint& outpoint, const Coin& coin) {
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << outpoint;
    ss << static_cast<uint32_t>(coin.nHeight * 2 + coin.fCoinBase);
    ss << coin.out;
    return ss;
}

class UTXOHasher
{
public:
    virtual void Prepare(const uint256& hash_block){};
    virtual void Apply(const uint256& hash, const std::map<uint32_t, Coin>& outputs){};
    virtual uint256 Finalize() = 0;
    virtual ~UTXOHasher();
};

UTXOHasher::~UTXOHasher() = default;

class NullHasher : public UTXOHasher {
public:
    uint256 Finalize() override {
        return {};
    }
};

std::unique_ptr<UTXOHasher> MakeNullHasher() {
    return std::make_unique<NullHasher>();
}

class SHA256DHasher : public UTXOHasher
{
    CHashWriter ss{SER_GETHASH, PROTOCOL_VERSION};
public:
    // The legacy hash serializes the hashBlock
    void Prepare(const uint256& hash_block) override {
        ss << hash_block;
    }

    //! Warning: be very careful when changing this! assumeutxo and UTXO snapshot
    //! validation commitments are reliant on the hash constructed by this
    //! function.
    //!
    //! If the construction of this hash is changed, it will invalidate
    //! existing UTXO snapshots. This will not result in any kind of consensus
    //! failure, but it will force clients that were expecting to make use of
    //! assumeutxo to do traditional IBD instead.
    //!
    //! It is also possible, though very unlikely, that a change in this
    //! construction could cause a previously invalid (and potentially malicious)
    //! UTXO snapshot to be considered valid.
    void Apply(const uint256& hash, const std::map<uint32_t, Coin>& outputs) override {
        for (auto it = outputs.begin(); it != outputs.end(); ++it) {
            if (it == outputs.begin()) {
                ss << hash;
                ss << VARINT(it->second.nHeight * 2 + it->second.fCoinBase ? 1u : 0u);
            }

            ss << VARINT(it->first + 1);
            ss << it->second.out.scriptPubKey;
            ss << VARINT_MODE(it->second.out.nValue, VarIntMode::NONNEGATIVE_SIGNED);

            if (it == std::prev(outputs.end())) {
                ss << VARINT(0u);
            }
        }
    }
    uint256 Finalize() override {
        return ss.GetHash();
    }
};

std::unique_ptr<UTXOHasher> MakeSHA256DHasher() {
    return std::make_unique<SHA256DHasher>();
}

class MuHashHasher : public UTXOHasher
{
    MuHash3072 muhash;
public:
    void Apply(const uint256& hash, const std::map<uint32_t, Coin>& outputs) override {
        for (auto it = outputs.begin(); it != outputs.end(); ++it) {
            COutPoint outpoint = COutPoint(hash, it->first);
            Coin coin = it->second;
            muhash.Insert(MakeUCharSpan(TxOutSer(outpoint, coin)));
        }
    }
    uint256 Finalize() override {
        uint256 out;
        muhash.Finalize(out);
        return out;
    }
};

std::unique_ptr<UTXOHasher> MakeMuHashHasher() {
    return std::make_unique<MuHashHasher>();
}

std::unique_ptr<UTXOHasher> MakeUTXOHasher(const CoinStatsHashType& hash_type)
{
    switch (hash_type) {
    case(CoinStatsHashType::HASH_SERIALIZED): {
        return MakeSHA256DHasher();
    }
    case(CoinStatsHashType::MUHASH): {
        return MakeMuHashHasher();
    }
    case(CoinStatsHashType::NONE): {
        return MakeNullHasher();
    }
    } // no default case, so the compiler can warn about missing cases
}

static void ApplyStats(CCoinsStats& stats, const uint256& hash, const std::map<uint32_t, Coin>& outputs)
{
    assert(!outputs.empty());
    stats.nTransactions++;
    for (auto it = outputs.begin(); it != outputs.end(); ++it) {
        stats.nTransactionOutputs++;
        if (stats.total_amount.has_value()) {
            stats.total_amount = CheckedAdd(*stats.total_amount, it->second.out.nValue);
        }
        stats.nBogoSize += GetBogoSize(it->second.out.scriptPubKey);
    }
}

static CCoinsStats MakeCoinStatsPrefilledWithBlockIndexInfo(const CBlockIndex* pindex)
{
    CCoinsStats stats{};

    stats.nHeight = Assert(pindex)->nHeight;
    stats.hashBlock = pindex->GetBlockHash();

    return stats;
}

static bool GetUTXOStatsWithHasher(UTXOHasher& hasher, CCoinsStats& stats, CCoinsView* view, BlockManager& blockman, const std::function<void()>& interruption_point)
{
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    assert(pcursor);

    hasher.Prepare(stats.hashBlock);

    uint256 prevkey;
    std::map<uint32_t, Coin> outputs;
    while (pcursor->Valid()) {
        interruption_point();
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (!outputs.empty() && key.hash != prevkey) {
                ApplyStats(stats, prevkey, outputs);
                hasher.Apply(prevkey, outputs);
                outputs.clear();
            }
            prevkey = key.hash;
            outputs[key.n] = std::move(coin);
            stats.coins_count++;
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    if (!outputs.empty()) {
        ApplyStats(stats, prevkey, outputs);
        hasher.Apply(prevkey, outputs);
    }

    stats.hashSerialized = hasher.Finalize();

    stats.nDiskSize = view->EstimateSize();

    return true;
}

std::optional<CCoinsStats> GetUTXOStatsWithHasher(UTXOHasher& hasher, CCoinsView* view, BlockManager& blockman, const std::function<void()>& interruption_point)
{
    CBlockIndex* pindex = WITH_LOCK(cs_main, return blockman.LookupBlockIndex(view->GetBestBlock()));
    CCoinsStats stats = MakeCoinStatsPrefilledWithBlockIndexInfo(pindex);

    GetUTXOStatsWithHasher(hasher, stats, view, blockman, interruption_point);

    return stats;
}

std::optional<CCoinsStats> GetUTXOStatsWithIndex(CoinStatsIndex& coin_stats_index, const CBlockIndex* pindex)
{
    CCoinsStats stats = MakeCoinStatsPrefilledWithBlockIndexInfo(pindex);

    stats.index_used = true;
    if (!coin_stats_index.LookUpStats(pindex, stats)) {
        return std::nullopt;
    }

    return stats;
}

std::optional<CCoinsStats> GetUTXOStatsWithIndex(CoinStatsIndex& coin_stats_index, CCoinsView* view, BlockManager& blockman)
{
    CBlockIndex* pindex = WITH_LOCK(cs_main, return blockman.LookupBlockIndex(view->GetBestBlock()));

    return GetUTXOStatsWithIndex(coin_stats_index, pindex);
}

//! Calculate statistics about the unspent transaction output set
std::optional<CCoinsStats> GetUTXOStats(CCoinsView* view, BlockManager& blockman, CoinStatsHashType hash_type, const std::function<void()>& interruption_point, const CBlockIndex* pindex, bool index_requested)
{
    // Use CoinStatsIndex if it is requested and available and a hash_type of Muhash or None was requested
    if ((hash_type == CoinStatsHashType::MUHASH || hash_type == CoinStatsHashType::NONE) && g_coin_stats_index && index_requested) {
        if (pindex) {
            return GetUTXOStatsWithIndex(*g_coin_stats_index, pindex);
        } else {
            return GetUTXOStatsWithIndex(*g_coin_stats_index, view, blockman);
        }
    }

    auto hasher = MakeUTXOHasher(hash_type);
    return GetUTXOStatsWithHasher(*hasher, view, blockman, interruption_point);
}
} // namespace node
