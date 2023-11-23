// Copyright (c) 2023-present Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "globalnaming.h"

#include <clang/AST/ASTContext.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

using clang::ast_matchers::hasName;
using clang::ast_matchers::unless;

namespace bitcoin {

void GlobalNamingCheck::registerMatchers(clang::ast_matchers::MatchFinder *finder) {
    finder->addMatcher(
        clang::ast_matchers::varDecl(
            clang::ast_matchers::hasGlobalStorage(), 
            unless(hasName("main")), unless(hasName("argc")), unless(hasName("argv")), unless(hasName("environ"))
        ).bind("globalVar"),
    this);
}

void GlobalNamingCheck::check(const clang::ast_matchers::MatchFinder::MatchResult& Result)
{
    const auto *GlobalVar = Result.Nodes.getNodeAs<clang::VarDecl>("globalVar");
    if (GlobalVar) {
        const auto VarName = GlobalVar->getName();
        if (!VarName.startswith("g_") && !(VarName == VarName.upper())) {
            // Emit a diagnostic if the global variable does not follow the naming convention.
            const auto user_diag = diag(GlobalVar->getLocation(), "Global variable '%0' should be prefixed with 'g_'") << VarName;
            user_diag << GlobalVar->getSourceRange();
        }
    }
}

} // namespace bitcoin
