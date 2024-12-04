// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/debug.h>

#include <span>
#include <vector>

DebugScriptCallback g_script_debug_callback{nullptr};
DebugScriptPhaseCallback g_script_debug_phase_callback{nullptr};


void DebugScript(std::span<const std::vector<unsigned char>> stack, const CScript& script, uint32_t opcode_pos, std::span<const std::vector<unsigned char>> altstack)
{
    if (g_script_debug_callback) g_script_debug_callback(stack, script, opcode_pos, altstack);
}

void DebugScriptPhase(std::string_view phase)
{
    if (g_script_debug_phase_callback) g_script_debug_phase_callback(phase);
}

void RegisterDebugScriptCallback(DebugScriptCallback debug_func, DebugScriptPhaseCallback phase_func)
{
    g_script_debug_callback = debug_func;
    g_script_debug_phase_callback = phase_func;
}

void DeRegisterDebugScriptCallback()
{
    g_script_debug_callback = nullptr;
    g_script_debug_phase_callback = nullptr;
}

