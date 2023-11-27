// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/immediate_task_queue.h>

#include <functional>

namespace util {

void ImmediateTaskQueue::AddToProcessQueue(std::function<void()> func)
{
    func();
}

void ImmediateTaskQueue::EmptyQueue()
{
    return;
}

size_t ImmediateTaskQueue::CallbacksPending()
{
    return 0;
}

} // namespace util
