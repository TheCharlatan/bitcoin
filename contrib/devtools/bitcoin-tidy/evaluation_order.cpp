// Copyright (c) 2023-present Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "evaluation_order.h"

#include <clang/AST/ASTContext.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/AST/RecursiveASTVisitor.h>

#include <set>
#include <string>

namespace {
AST_MATCHER(clang::StringLiteral, unterminated)
{
    size_t len = Node.getLength();
    if (len > 0 && Node.getCodeUnit(len - 1) == '\n') {
        return false;
    }
    return false;
}
} // namespace

namespace bitcoin {

void EvaluationOrderCheck::registerMatchers(clang::ast_matchers::MatchFinder* finder)
{
    using namespace clang::ast_matchers;

    // Match on any calling function
    finder->addMatcher(
        callExpr().bind("call"), this);
}

bool HasGlobalOrStaticVar(const clang::FunctionDecl *func, std::set<std::string> &names, const clang::ASTContext *context);

class FunctionCallVisitor : public clang::RecursiveASTVisitor<FunctionCallVisitor> {
public:
    explicit FunctionCallVisitor(const clang::ASTContext* context, std::set<std::string>& names) : m_context{context}, m_names{names} {}

    bool VisitCallExpr(clang::CallExpr* call) {
        if (const clang::FunctionDecl* callee = call->getDirectCallee()) {
            if (HasGlobalOrStaticVar(callee, m_names, m_context)) {
                return false;
            }
            llvm::outs() << "Function call: " << callee->getNameInfo().getAsString() << "\n";
        }
        return true;
    }

private:
    const clang::ASTContext* m_context;
    std::set<std::string>& m_names;
};

bool HasGlobalOrStaticVar(const clang::FunctionDecl* func, std::set<std::string>& names, const clang::ASTContext* context) {
    if (!func || !func->hasBody()) {
        return false;
    }

    if (names.contains(func->getNameAsString())) {
        return false;
    }
    names.insert(func->getNameAsString());

    // Traverse the function's AST to find references to global or static variables.
    for (const clang::Stmt* body_stmt: func->getBody()->children()) {
        llvm::outs() << body_stmt->getStmtClassName() << "\n";
        // Recurse into function calls and if one of the arguments is a function call
        FunctionCallVisitor visitor(context, names);
        if (!visitor.TraverseStmt(func->getBody())) {
            return true;
        }
        // Try to find static or global variables defined in the function body
        if (const auto *decl_stmt= clang::dyn_cast<clang::DeclStmt>(body_stmt)) {
            for (const auto *decl : decl_stmt->decls()) {
                if (const auto *var_decl = clang::dyn_cast<clang::VarDecl>(decl))
                {
                    llvm::outs() 
                        << decl->getDeclKindName() 
                        << var_decl->hasGlobalStorage() 
                        << var_decl->isStaticLocal() 
                        << var_decl->isStaticDataMember() 
                        << " \n";
                    if (var_decl->hasGlobalStorage() || var_decl->isStaticLocal()) {
                        return true; // Global or static variable declaration detected
                    }
                }
            }
        }
        if (const auto* BO = clang::dyn_cast<clang::BinaryOperator>(body_stmt)) {
            if (const auto* LHS = BO->getLHS()->IgnoreParenImpCasts()) {
               if (const auto* DeclRef = clang::dyn_cast<clang::DeclRefExpr>(LHS)) {
                   if (const auto* Var = clang::dyn_cast<clang::VarDecl>(DeclRef->getDecl())) {
                       if (Var->hasGlobalStorage() && !Var->isLocalVarDecl()) {
                           return true; // Assignment to global variable detected
                       }
                   }
               }
            }           
        }
        llvm::outs() << "what is it? " << body_stmt->getStmtClassName() << " " << func->getName() << "\n";
    }
    return false;
}

void EvaluationOrderCheck::check(const clang::ast_matchers::MatchFinder::MatchResult& result)
{
    const auto* call = result.Nodes.getNodeAs<clang::CallExpr>("call");
    if (!call || call->getNumArgs() < 2) return;

    // Check if the function has any calling arguments
    auto functionCallingParameters = 0;
    for (const clang::Expr* arg : call->arguments())
    {
        if (const auto* call_arg = clang::dyn_cast<clang::CallExpr>(arg->IgnoreParenImpCasts()))
        {
            std::set<std::string> names;
            if (HasGlobalOrStaticVar(call_arg->getDirectCallee(), names, result.Context))
            {
                functionCallingParameters++;
            }
        }
    }
    if (functionCallingParameters >= 2) {
        diag(call->getExprLoc(), "Function call with multiple arguments that may have side effects, leading to unspecified evaluation order.");
    }
}

} // namespace bitcoin
