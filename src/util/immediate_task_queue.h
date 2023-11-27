// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_IMMEDIATE_TASK_QUEUE_H
#define BITCOIN_UTIL_IMMEDIATE_TASK_QUEUE_H

#include <util/task_queue_interface.h>

#include <cstddef>
#include <functional>

namespace util {

class ImmediateTaskQueue : public TaskQueueInterface
{
public:
    void AddToProcessQueue(std::function<void()> func) override;
    void EmptyQueue() override;
    size_t CallbacksPending() override;
};

} // namespace util

#endif // BITCOIN_UTIL_IMMEDIATE_TASK_QUEUE_H
