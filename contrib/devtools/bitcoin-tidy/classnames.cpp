// Copyright (c) 2023-present Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "classnames.h"

#include <clang/AST/ASTContext.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include "clang/ASTMatchers/ASTMatchers.h"


namespace {
AST_MATCHER(clang::StringLiteral, unterminated)
{
    size_t len = Node.getLength();
    if (len > 0 && Node.getCodeUnit(len - 1) == '\n') {
        return false;
    }
    return true;
}
} // namespace

namespace bitcoin {

void ClassNameCheck::registerMatchers(clang::ast_matchers::MatchFinder* Finder)
{
    using namespace clang::ast_matchers;

    Finder->addMatcher(
        cxxRecordDecl(matchesName("^::C[A-Z].*")).bind("class"),
        this);
}

void ClassNameCheck::check(const clang::ast_matchers::MatchFinder::MatchResult& Result)
{
    const auto *Class = Result.Nodes.getNodeAs<clang::CXXRecordDecl>("class");
    if (Class && Class->isThisDeclarationADefinition()) {
        const auto user_diag = diag(Class->getLocation(), "Class name should not start with a 'C' prefix");
    }
}

} // namespace bitcoin
