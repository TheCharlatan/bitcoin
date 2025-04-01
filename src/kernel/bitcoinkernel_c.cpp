// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>

#include <kernel/bitcoinkernel.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>

using kernel_header::ScriptPubkey;
using kernel_header::Transaction;
using kernel_header::TransactionOutput;

namespace {

const Transaction* cast_transaction(const kernel_Transaction* transaction)
{
    assert(transaction);
    return reinterpret_cast<const Transaction*>(transaction);
}

const ScriptPubkey* cast_script_pubkey(const kernel_ScriptPubkey* script_pubkey)
{
    assert(script_pubkey);
    return reinterpret_cast<const ScriptPubkey*>(script_pubkey);
}

const TransactionOutput* cast_transaction_output(const kernel_TransactionOutput* transaction_output)
{
    assert(transaction_output);
    return reinterpret_cast<const TransactionOutput*>(transaction_output);
}
} // namespace

kernel_Transaction* kernel_transaction_create(const unsigned char* raw_transaction, size_t raw_transaction_len)
{
    try {
        return reinterpret_cast<kernel_Transaction*>(new Transaction(std::span{raw_transaction, raw_transaction_len}));
    } catch (const std::exception&) {
        return nullptr;
    }
}

void kernel_transaction_destroy(kernel_Transaction* transaction)
{
    if (transaction) {
        delete cast_transaction(transaction);
    }
}

kernel_ScriptPubkey* kernel_script_pubkey_create(const unsigned char* script_pubkey, size_t script_pubkey_len)
{
    return reinterpret_cast<kernel_ScriptPubkey*>(new ScriptPubkey(std::span{script_pubkey, script_pubkey_len}));
}

void kernel_script_pubkey_destroy(kernel_ScriptPubkey* script_pubkey)
{
    if (script_pubkey) {
        delete cast_script_pubkey(script_pubkey);
    }
}

kernel_TransactionOutput* kernel_transaction_output_create(const kernel_ScriptPubkey* script_pubkey_, int64_t amount)
{
    const auto& script_pubkey{*cast_script_pubkey(script_pubkey_)};
    return reinterpret_cast<kernel_TransactionOutput*>(new TransactionOutput{script_pubkey, amount});
}

void kernel_transaction_output_destroy(kernel_TransactionOutput* output)
{
    if (output) {
        delete cast_transaction_output(output);
    }
}

bool kernel_verify_script(const kernel_ScriptPubkey* script_pubkey_,
                          const int64_t amount,
                          const kernel_Transaction* tx_to,
                          const kernel_TransactionOutput** spent_outputs_, size_t spent_outputs_len,
                          const unsigned int input_index,
                          const unsigned int flags)
{
    const auto& script_pubkey{*cast_script_pubkey(script_pubkey_)};
    const auto& tx{*cast_transaction(tx_to)};

    std::span<const TransactionOutput> spent_outputs;
    if (spent_outputs_ != nullptr) {
        const TransactionOutput* first_output{reinterpret_cast<const TransactionOutput*>(*spent_outputs_)};
        spent_outputs = {first_output, spent_outputs_len};
    }

    return script_pubkey.VerifyScript(
        amount,
        tx,
        spent_outputs,
        input_index,
        flags);
}
