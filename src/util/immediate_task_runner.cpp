// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/task_runner.h>

#include <functional>

namespace util {

void ImmediateTaskRunner::insert(std::function<void()> func)
{
    func();
}

void ImmediateTaskRunner::clear()
{
    return;
}

size_t ImmediateTaskRunner::size()
{
    return 0;
}

} // namespace util
