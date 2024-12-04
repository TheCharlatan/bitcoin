// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/script.h>

#include <functional>
#include <span>
#include <vector>

#ifndef BITCOIN_SCRIPT_DEBUG_H
#define BITCOIN_SCRIPT_DEBUG_H

#ifndef ENABLE_SCRIPT_DEBUG
#define DEBUG_SCRIPT(stack, script, opcode_pos, altstack) \
    DebugScript(stack, script, opcode_pos, altstack);
#define DEBUG_SCRIPT_PHASE(phase) \
    DebugScriptPhase(phase);
#else
#define DEBUG_SCRIPT(stack, script, opcode_pos, altstack)
#define DEBUG_SCRIPT_PHASE(phase)
#endif // ENABLE_SCRIPT_DEBUG

using DebugScriptCallback = std::function<void(std::span<const std::vector<unsigned char>>, const CScript&, uint32_t, std::span<const std::vector<unsigned char>>)>;
using DebugScriptPhaseCallback = std::function<void(std::string_view)>;

void DebugScript(std::span<const std::vector<unsigned char>> stack, const CScript& script, uint32_t opcode_pos, std::span<const std::vector<unsigned char>> altstack);

void DebugScriptPhase(std::string_view phase);

void RegisterDebugScriptCallback(DebugScriptCallback debug_func, DebugScriptPhaseCallback phase_func);
void DeregisterDebugScriptCallback();

#endif // BITCOIN_SCRIPT_DEBUG_H
