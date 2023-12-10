// Copyright (c) 2023 Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <iostream>
#include <vector>

// Test for bitcoin-unterminated-logprintf

enum LogFlags {
    NONE
};

enum Level {
    None
};

template <typename... Args>
static inline void LogPrintf_(const std::string& logging_function, const std::string& source_file, const int source_line, const LogFlags flag, const Level level, const char* fmt, const Args&... args)
{
}

#define LogPrintLevel_(category, level, ...) LogPrintf_(__func__, __FILE__, __LINE__, category, level, __VA_ARGS__)
#define LogPrintf(...) LogPrintLevel_(LogFlags::NONE, Level::None, __VA_ARGS__)

#define LogPrint(category, ...) \
    do {                        \
        LogPrintf(__VA_ARGS__); \
    } while (0)


class CWallet
{
    std::string GetDisplayName() const
    {
        return "default wallet";
    }

public:
    template <typename... Params>
    void WalletLogPrintf(const char* fmt, Params... parameters) const
    {
        LogPrintf(("%s " + std::string{fmt}).c_str(), GetDisplayName(), parameters...);
    };
};

struct ScriptPubKeyMan
{
    std::string GetDisplayName() const
    {
        return "default wallet";
    }

    template <typename... Params>
    void WalletLogPrintf(const char* fmt, Params... parameters) const
    {
        LogPrintf(("%s " + std::string{fmt}).c_str(), GetDisplayName(), parameters...);
    };
};

void good_func()
{
    LogPrintf("hello world!\n");
}
void good_func2()
{
    CWallet wallet;
    wallet.WalletLogPrintf("hi\n");
    ScriptPubKeyMan spkm;
    spkm.WalletLogPrintf("hi\n");

    const CWallet& walletref = wallet;
    walletref.WalletLogPrintf("hi\n");

    auto* walletptr = new CWallet();
    walletptr->WalletLogPrintf("hi\n");
    delete walletptr;
}
void bad_func()
{
    LogPrintf("hello world!");
}
void bad_func2()
{
    LogPrintf("");
}
void bad_func3()
{
    // Ending in "..." has no special meaning.
    LogPrintf("hello world!...");
}
void bad_func4_ignored()
{
    LogPrintf("hello world!"); // NOLINT(bitcoin-unterminated-logprintf)
}
void bad_func5()
{
    CWallet wallet;
    wallet.WalletLogPrintf("hi");
    ScriptPubKeyMan spkm;
    spkm.WalletLogPrintf("hi");

    const CWallet& walletref = wallet;
    walletref.WalletLogPrintf("hi");

    auto* walletptr = new CWallet();
    walletptr->WalletLogPrintf("hi");
    delete walletptr;
}

// Here come the evaluation order tests

int g_testy = 0;

int get_and_increment_global_value_1() {
    g_testy += 1;
    return g_testy;
}

int get_and_increment_global_value_2() {
    g_testy = g_testy + 1;
    return g_testy;
}

int get_static_value() {
    static std::vector<int> nums = {0, 1, 2};
    int ret = nums.back();
    nums.pop_back();
    return ret;
}

int easy_val() {
    return 1;
}

int f(int a, int b, int c) {
    return a - b * c;
}

int indirect_func() {
    return get_static_value();
}

int bad_func_eval_1() {
    int val = f(get_static_value(), get_static_value(), get_static_value());
    return val;
}

int bad_func_eval_2() {
    int val = f(get_and_increment_global_value_1(), get_and_increment_global_value_1(), get_and_increment_global_value_1());
    return val;
}

int bad_func_eval_3() {
    int val = f(get_and_increment_global_value_2(), get_and_increment_global_value_2(), get_and_increment_global_value_2());
    return val;
}

int good_func_eval_1() {
    int val = f(get_static_value(), 1, 2);
    return val;
}

int good_func_eval_2() {
    int val = f(get_static_value(), easy_val(), easy_val());
    return val;
}

int bad_func_eval_4() {
    int val = f(indirect_func(), indirect_func(), indirect_func());
    return val;
}
