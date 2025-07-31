#include <bench/bench.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>

#include <atomic>
#include <span>

struct Transaction
{
    std::shared_ptr<const CTransaction> m_tx;
};

struct TransactionOutput
{
    std::shared_ptr<const CTxOut> m_txout;
};

struct ScriptPubkey
{
    std::shared_ptr<const CScript> m_script;
};

Transaction* transaction_create(const unsigned char* raw_tx, size_t raw_tx_len)
{
    try {
        DataStream stream{std::span{raw_tx, raw_tx_len}};
        auto tx = std::make_shared<const CTransaction>(deserialize, TX_WITH_WITNESS, stream);
        return new Transaction{std::move(tx)};
    } catch (const std::exception&) {
        return nullptr;
    }
}

size_t transaction_get_output_size(Transaction* tx)
{
    return tx->m_tx->vout.size();
}

TransactionOutput* transaction_get_output(Transaction* tx, int64_t i)
{
    const auto& txn = tx->m_tx;
    const CTxOut* tx_out = &txn->vout[i];
    std::shared_ptr<const CTxOut> alias(txn, tx_out);
    return new TransactionOutput{std::move(alias)};
}

ScriptPubkey* transaction_output_get_script_pubkey(TransactionOutput* output)
{
    const auto& txout = output->m_txout;
    const CScript* script_pubkey = &txout->scriptPubKey;
    std::shared_ptr<const CScript> alias(txout, script_pubkey);
    return new ScriptPubkey{std::move(alias)};
}

Transaction* create_tx()
{
    const auto raw_tx = "02000000000101680c6c0a2259cdc6558de5b76e65e93c4fc6e1feb2cc1480f774712951f28e3f4f00000000ffffffff775841020000000000160014356ba6571de9403acec092f61f055ccee8b87901b735010000000000160014dfc82a57b7a5aafdf55fd6427689ff4c19e2ae13881300000000000017a914bc945864bc1d8bc22a13e1014479cc63a117c3b187d4930200000000001600146f10abe4bb06ec6a55f0e3e4485531fdeee425fc80ea000000000000160014826427b4d3b6bb85973eb0618d88449734ba01060694000000000000160014e5b3b180197867f8dfd3ab7719b14c998f5f01657594000000000000160014597c3011c1500accc3d425a06dbe7bb46bb4a6d500440000000000001600143f7a991d5170bb6bed0e37b480da06426c0e7370159b050000000000160014a4963f89d173e77ecdf8a6c84db67bf34723c6338a520000000000002200204794529b1f15032eadaac33d13a2a0893e8589d7fa0ac54642bde560eb00964917870c0000000000160014e68f5abb61d84de5415133f8b0fe88d433c851399c520000000000001976a914c4f8b689e311ddea002cfc9899eba56401c2de8988acdb6a000000000000220020c82edee5ae12dbb5b95673c9c2e6c06ee6d9bb10337d6ea1cb54af947d554264a8380100000000001600148c945f423c186cbb326718345cab4c8a56b1c004c519030000000000160014f02b813470aa0986446098d047fbf363bb49e7a710fa01000000000016001472c660f135486255d584ebef08b7e7f711b6ca3a02480000000000001600140ba242778564a907ed95f2ab0b0ccaa0700e9be1801a060000000000160014a62d5371d1a5a233706b718bc63cc1ba99d2c3bfb6850100000000001600141baf1bd61f763c3ac1b1180726f73bdd191ae75d838b01000000000016001459995fd63a965bcf5d37627705f37b598efa0662281505000000000016001440df1af43a9229e0ce336db37dccae93179bfeb8a918000000000000220020c9bcc92e05200d65c77a9941a238fa81f3605e73141b1cf0da414c39aa19a831842f01000000000017a914935ec6206dacb27f542fda7febcb1cc9b76558df875f150000000000001976a914128f197c311fee24cbc5c5010b057ab8273cfb8088acf9620000000000001976a914383c124a8e7e56358ac4890513dc26eadea03ed788ac099911000000000017a91420b7037af3728f8dddf61212e1ac3e64e9f3f78887f71401000000000017a914c27030175d4c79199e9b0dc81d9ac2f7a13cdcc487fdf00500000000001976a914d2e13289ec4aa7621a1386aaa9d9e3eaaa2b6b6288ac5c730000000000001600148c57da774057c2afc00ae1cd82a00346c3bc4d3fa2140000000000001600143f9d844b0a37ce8f9d91985144d8fb0532176625e8070100000000001600141b3490b7ef42ecffbfc0edad5309721afbe5e571fea50000000000001600140eaffff2b082dd683adf178ad92bbafc1e7a62c5fe20000000000000160014d035820565436c4d300f22bcedeb4884167d0fc23f7300000000000016001420cacdda48ecc6a2c44408d67c4608e5f3b873000440010000000000160014cc7269affbd2571cc05c19f033803bbc2e582d4022d601000000000016001448a9ce11ea4e00fee2f65a23e09e1e4e07c1b2ec5c730000000000001600147c718500e026a0c80dc966d58d75384dad95be18df93000000000000160014016ad501f087b98e1449804cf6af319063aae4b22559000000000000160014e0f4eb39909ac416d18babbdbf88210ebd46ae517c310000000000001976a9141b15ab3fd9ef255150f18869daf956f0fa68685988ac9448000000000000160014e9e3cb7169482106412cd86bbaf1ba3e0ba24c81b03300000000000016001408e540a10b9c32827fdfefd13a53fa07ac6558ec7873000000000000160014b6c2255cdf3c1a8e48d260dde226575a3c2d5acde84901000000000016001452cfe1907cd4a9475538b10b8957f0ab03a7e319fe20000000000000160014de7bfceec6bae48341434a8326b7c35e549b0c7b92438603000000001600149cd12009d52ce9d0483420f39520743170fed5a4f4390300000000001600148c2cb34c3138e29c3591c13783956aca01980b15d7cf00000000000016001408978b8ea0dfc9efeb3d69f4ddff69316156c4b9e9490100000000001976a914c1f5e84a24777a69bef6ddc289e4c6d8b0c06eec88ac9243860300000000160014112bc7df54b720e1d2dc4a07162f428b7287431e98438603000000001600140788401b0b24b96a76cac180121476110b6fb5cfa8a1000000000000220020a74102e15367e73015f9d1159434bab2eb696c473faf577b919a6ca5e97e75e0f4a40000000000001600143c162a86e65d27a89eec3caeb9f4abd13e6d3e0d787300000000000022002078829ede5ded7ab80abd1986c4c520efcc222430dddbaa875fd48c6b2487f68cf4a400000000000016001494d14c536a59d883eccc00b5a725e6613432d2461c1d0c00000000001600144a544d5fb25e0fe9daa0081eb56473cf7326bad9a540000000000000160014e2d94115c733636ea68dfd20a6957227d9d8b3d4b049010000000000160014c2f459bec5405cce629da9223f5c12bba8781a947c31000000000000160014c30c9e1396d00cec5a490808ba2dbe85f4178365f4140100000000001600144bd5cdf5db092d2bf106c16fa1617df0f8b2347c709e0000000000001976a914b53d476f283c0dfcf8cab7571914df25415937c688ac0bdd02000000000017a914b449fd8efec2c22bcc1fb8f8993b7e6df50ecece870c8e0200000000001600149bf34f1354ab30d0cb02e76ecd7b71066b4aa2d7a452000000000000160014f5e06c06f5ec849fbbafdf4522f48ce78c926c58e48b0100000000001976a914f38561dfc5c8ce3553e7a49f48be76852767178c88ac9243860300000000160014c42e9b456a8f5463a0352e218f8c3448f0a3a84ca13501000000000017a9146275054efb714e4ffe0f84f7c4730b326566ed8d874b2b00000000000017a91456d28d050244f30cee5f87e654daf0c04c4e2f8887b255010000000000160014e0c0a754fcb8b97ad029fba0ae9d9b2fdb60fc2300710200000000001976a9141f9691a289df8192149a3706784437e7c893147488acfb41000000000000160014b7e8f200afd6cb946bbc990f5c721ea322994a80e94901000000000017a91453bcb595e90af2ce92f61c924c7b92aa999e9d46877e2e010000000000160014590b9bef23ee2e8095f3180342633e1a250c1be9242400000000000016001451c3df9a21a8ef5eaab15de4b43cb68ecd7e6849bb6511000000000022002042f24f7c7f67ea4ae6dc3409c315d00dd519a3f98b6ae0663e4fe8ebaf33aa5ead5f000000000000160014ee0f2c4b0ad46a09c283e0600d2d3a07b039787c3a2f0300000000001600141bc3214c2a3c8631bd11be0a08012bcc302479d7f1620000000000001600144eea1d2750f740c314725ef0eeeb7d3da02d03338c14000000000000220020155b61650f7bdfe01d15409c7e6d12ab3524b9a9c4624f64a60db7c0761c9e816ff7000000000000160014948ace1513ba803fe32dd11b8f2e8e09a52e26e3bb400000000000001600149542071a711f012b457db241e1e32c5519d13f5c7873000000000000160014cca435d7f618f187a88b372fd03d41e76a603a7aaf3e000000000000160014e872da912e59865615ca2f5e7029a06adfdfd1b585dd0000000000001600140f7b49602331b9ccfa574f33b59f4a141b606fd1e9300100000000001600142d40efe367e81abcb6a0ab099348d5808f5d038d5d3d060000000000160014a6db43bfae49809de5d652511326c06b93db7341633901000000000016001422a2dc0ebac204c954cd3b909362c39104a30030f4a4000000000000160014e3761c9f21f470c05f677eb660ed7c9b25326a077a5200000000000017a914379bede39db5d47696cccd2d5153f01365b5fc1887baba0300000000001600149e93993f11191a8e631790a37a371ac49e01e6eaecba01000000000016001488ba1ad77173792a93234bc63a9edd98758838bf306c0200000000001600146d0c7aa856fc4ce1a691a797c0c888c6918a083af9620000000000001976a9146ede1ce9dc323634266a4238fc9703e4559056bc88ac8652000000000000160014862c3fa17f681439cc891ead8f59083faef8c2ca222700000000000017a914020e8909255877aea86950e6f9ef607aba7e280787caf6020000000000160014eb12bb94127dfe550049a7697dc4c92621c564ebaaa20000000000001600147183977a889d4b3071f60bc6a50f05daf63b7b3c8d7200000000000017a9140515c4a44d0d837afe4090ee06508ef6b8b85f0987eab2000000000000160014eb73bf8e5a5b8627d8eb4ddd742f7557debdf9009243860300000000160014c4f70a6faf104949d5d7c915fba9c171b1313eb1b1820400000000001976a91446c9a9c0e847ecc8796518dafd7631f4cf77587688aca4140000000000001600146faa3c29b025fce95fb0b20dd63232f562a0eb41f09300000000000016001499be0e4eff0dcae00053641b70e6730def0ca6454f53000000000000160014cacbf945c4779b80217b72a0a67df0a8041af2cfef8801000000000016001427bae188364ed8302ebddf88023f3a3ed26791935816000000000000160014ac147e9ae332f00ada543a20fdff07796ece91e436a90200000000001600146b734ebc9096c46afeadb017c3ee5c4171104fe5684200000000000016001425615888005dce858271c5e5fe5b4b99f1648d23f1930000000000001600142c094126564d7b17735e2cac4f1cdfa13a58fbbdd6980000000000001600145a7a17064188d2096b6ba554f3541d30753cfba392438603000000001600140cfcb2f1bed2110bf76471f682c4ebe9cb24e8c69243860300000000160014d93d910c1934f85ecb55191fe44a28f415a0925a184c010000000000160014ad6cdd217aea80ee47f012d2335604903075fa7f924386030000000016001442925a9f763b1954684b31281bc38072e62968c7f3c500000000000017a914046c2931041e168f8dc4a08b2c6db8057ab729b0871e3e0600000000001600148a988f8abe16321eeca3371e3d2118f4a1983a2af162000000000000160014bf7136ef33d07c467f4c4c248ceb41248ccf696aa4ba030000000000160014fcf27d7ed8192d9c5a4641f49720ee4e1411e735d16801000000000017a91483250653b308cd465618c9aed8991ac313f01b398702473044022010f6ad0abfd65aee8ee75d16f85d3e3398e8408db91eb76ae27d9b8444a4c854022073e3789f6d4a15d65a02bc345d623ae32c3efd4101c3f77ec8ff5c7fbb3d82c8012102da1424c12324005855833c211bd8c359e086b860954f3ed4cb7674a7cb47c78c00000000";
    std::vector<unsigned char> tx_data = ParseHex(raw_tx);
    return transaction_create(tx_data.data(), tx_data.size());
}

struct TransactionOutputRaw
{
    const CTxOut* m_txout;
    bool owned;
};

struct ScriptPubkeyRaw
{
    const CScript* m_script;
    bool owned;
};

TransactionOutputRaw* transaction_get_output_raw(Transaction* tx, int64_t i)
{
    return new TransactionOutputRaw{&tx->m_tx->vout[i], true};
}

ScriptPubkeyRaw* transaction_output_raw_get_script_pubkey_raw(TransactionOutputRaw* output)
{
    return new ScriptPubkeyRaw{&output->m_txout->scriptPubKey, true};
}

struct TransactionOutputRefCounter
{
    const CTxOut* m_txout;
    std::shared_ptr<const void>* parent;
    std::shared_ptr<const CTxOut>* ptr;
};

struct ScriptPubkeyRefCounter
{
    const CScript* m_script;
    std::shared_ptr<const void>* parent;
    std::shared_ptr<const CScript>* ptr;
};

TransactionOutputRefCounter* transaction_get_output_ref_counter(Transaction* tx, int64_t i)
{
    const auto* output{&tx->m_tx->vout[i]};
    return new TransactionOutputRefCounter{output, reinterpret_cast<std::shared_ptr<const void>*>(&tx->m_tx), nullptr};
}

void transaction_output_ref_counter_retain(TransactionOutputRefCounter* output)
{
    auto alias = std::shared_ptr<const CTxOut>(*output->parent, output->m_txout);
    output->ptr = new std::shared_ptr<const CTxOut>(std::move(alias));
}

void transaction_output_ref_counter_destroy(TransactionOutputRefCounter* output)
{
    delete output->ptr;
}

struct TransactionOutputRefCounterDeleter {
    void operator()(TransactionOutputRefCounter* ptr) const
    {
        transaction_output_ref_counter_destroy(ptr);
    }
};

ScriptPubkeyRefCounter* transaction_output_ref_counter_get_script_pubkey_ref_counter(TransactionOutputRefCounter* output)
{
    auto* pubkey{&output->m_txout->scriptPubKey};
    return new ScriptPubkeyRefCounter{pubkey, output->parent, nullptr};
}

void script_pubkey_ref_counter_destroy(ScriptPubkeyRefCounter* script_pubkey)
{
    delete script_pubkey->ptr;
}

struct ScriptPubkeyRefCounterDeleter {
    void operator()(ScriptPubkeyRefCounter* ptr) const
    {
        script_pubkey_ref_counter_destroy(ptr);
    }
};

static void ApiRefCounter(benchmark::Bench& bench)
{
    Transaction* tx = create_tx();
    bench.batch(1).unit("ApiRefCounter").run([&] {
        uint64_t counter = 0;
        size_t n_outputs = transaction_get_output_size(tx);
        for (uint64_t i = 0; i < n_outputs; ++i) {
            std::unique_ptr<TransactionOutputRefCounter, TransactionOutputRefCounterDeleter> output{transaction_get_output_ref_counter(tx, i)};
            std::unique_ptr<ScriptPubkeyRefCounter> pubkey{transaction_output_ref_counter_get_script_pubkey_ref_counter(output.get())};
            if (pubkey->m_script->IsPayToScriptHash()) {
                ++counter;
            }
        }
        assert(counter == 13);
    });
}

static void ApiRefCounterCopy(benchmark::Bench& bench)
{
    Transaction* tx = create_tx();
    bench.batch(1).unit("ApiRefCounter").run([&] {
        size_t n_outputs = transaction_get_output_size(tx);
        std::vector<CScript> scripts;
        scripts.reserve(n_outputs);
        for (uint64_t i = 0; i < n_outputs; ++i) {
            std::unique_ptr<TransactionOutputRefCounter, TransactionOutputRefCounterDeleter> output{transaction_get_output_ref_counter(tx, i)};
            std::unique_ptr<ScriptPubkeyRefCounter, ScriptPubkeyRefCounterDeleter> pubkey{transaction_output_ref_counter_get_script_pubkey_ref_counter(output.get())};
            scripts.push_back(*pubkey->m_script);
        }
        assert(scripts.size() == n_outputs);
    });
}

static void ApiSharedPtr(benchmark::Bench& bench)
{
    Transaction* tx = create_tx();
    bench.batch(1).unit("ApiSharedPtr").run([&] {
        uint64_t counter = 0;
        size_t n_outputs = transaction_get_output_size(tx);
        for (uint64_t i = 0; i < n_outputs; ++i) {
            std::unique_ptr<TransactionOutput> output{transaction_get_output(tx, i)};
            std::unique_ptr<ScriptPubkey> pubkey{transaction_output_get_script_pubkey(output.get())};
            if (pubkey->m_script->IsPayToScriptHash()) {
                ++counter;
            }
        }
        assert(counter == 13);
    });
}

static void ApiSharedPtrCopy(benchmark::Bench& bench)
{
    Transaction* tx = create_tx();
    bench.batch(1).unit("ApiSharedPtr").run([&] {
        size_t n_outputs = transaction_get_output_size(tx);
        std::vector<CScript> scripts;
        scripts.reserve(n_outputs);
        for (uint64_t i = 0; i < n_outputs; ++i) {
            std::unique_ptr<TransactionOutput> output{transaction_get_output(tx, i)};
            std::unique_ptr<ScriptPubkey> pubkey{transaction_output_get_script_pubkey(output.get())};
            scripts.push_back(*pubkey->m_script);
        }
        assert(scripts.size() == n_outputs);
    });
}

static void ApiRaw(benchmark::Bench& bench)
{
    Transaction* tx = create_tx();
    bench.batch(1).unit("ApiRaw").run([&] {
        uint64_t counter = 0;
        size_t n_outputs = transaction_get_output_size(tx);
        for (uint64_t i = 0; i < n_outputs; ++i) {
            std::unique_ptr<TransactionOutputRaw> output{transaction_get_output_raw(tx, i)};
            std::unique_ptr<ScriptPubkeyRaw> pubkey{transaction_output_raw_get_script_pubkey_raw(output.get())};
            if (pubkey->m_script->IsPayToScriptHash()) {
                ++counter;
            }
        }
        assert(counter == 13);
    });
}

static void ApiRawCopy(benchmark::Bench& bench)
{
    Transaction* tx = create_tx();
    bench.batch(1).unit("ApiRaw").run([&] {
        size_t n_outputs = transaction_get_output_size(tx);
        std::vector<CScript> scripts;
        scripts.reserve(n_outputs);
        for (uint64_t i = 0; i < n_outputs; ++i) {
            std::unique_ptr<TransactionOutputRaw> output{transaction_get_output_raw(tx, i)};
            std::unique_ptr<ScriptPubkeyRaw> pubkey{transaction_output_raw_get_script_pubkey_raw(output.get())};
            scripts.push_back(*pubkey->m_script);
        }
        assert(scripts.size() == n_outputs);
    });
}

static void ApiDirect(benchmark::Bench& bench)
{
    Transaction* tx = create_tx();
    bench.batch(1).unit("ApiDirect").run([&] {
        uint64_t counter = 0;
        for (const auto& output : tx->m_tx->vout) {
            if (output.scriptPubKey.IsPayToScriptHash()) {
                ++counter;
            }
        }
        assert(counter == 13);
    });
}

static void ApiDirectCopy(benchmark::Bench& bench)
{
    Transaction* tx = create_tx();
    bench.batch(1).unit("ApiDirect").run([&] {
        std::vector<CScript> scripts;
        scripts.reserve(tx->m_tx->vout.size());
        for (const auto& output : tx->m_tx->vout) {
            scripts.push_back(output.scriptPubKey);
        }
        assert(scripts.size() == tx->m_tx->vout.size());
    });
}

BENCHMARK(ApiSharedPtr, benchmark::PriorityLevel::HIGH);
BENCHMARK(ApiSharedPtrCopy, benchmark::PriorityLevel::HIGH);
BENCHMARK(ApiRaw, benchmark::PriorityLevel::HIGH);
BENCHMARK(ApiRawCopy, benchmark::PriorityLevel::HIGH);
BENCHMARK(ApiRefCounter, benchmark::PriorityLevel::HIGH);
BENCHMARK(ApiRefCounterCopy, benchmark::PriorityLevel::HIGH);
BENCHMARK(ApiDirect, benchmark::PriorityLevel::HIGH);
BENCHMARK(ApiDirectCopy, benchmark::PriorityLevel::HIGH);
