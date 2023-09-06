// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/context.h>

#include <crypto/sha256.h>
#include <kernel/checks.h>
#include <key.h>
#include <logging.h>
#include <random.h>
#include <util/result.h>

#include <cassert>
#include <memory>
#include <string>
#include <utility>

namespace kernel {
Context* g_context;

util::Result<std::unique_ptr<Context>> Context::MakeContext()
{
    assert(!g_context);
    auto context{std::unique_ptr<Context>(new Context())};
    g_context = context.get();
    std::string sha256_algo = SHA256AutoDetect();
    LogPrintf("Using the '%s' SHA256 implementation\n", sha256_algo);
    RandomInit();
    ECC_Start();

    if (auto res{SanityChecks(*context)}; !res) {
        return util::Error{ErrorString(res)};
    }

    return {std::move(context)};
}

Context::~Context()
{
    ECC_Stop();
    assert(g_context);
    g_context = nullptr;
}

} // namespace kernel
