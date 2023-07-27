// Copyright (c) 2023 Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "filesystem.h"

#include <clang/AST/ASTContext.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Lex/Preprocessor.h>

#include <cstdio>

namespace {
} // namespace

namespace bitcoin {

void FilesystemCheck::registerPPCallbacks(const clang::SourceManager &SM, clang::Preprocessor *PP, clang::Preprocessor* /*ModuleExpanderPP*/) {
  PP->addPPCallbacks(std::make_unique<FilesystemCheckPPCallbacks>(*this, SM));
}

FilesystemCheck::FilesystemCheckPPCallbacks::FilesystemCheckPPCallbacks(clang::tidy::ClangTidyCheck &Check, const clang::SourceManager &SM)
  : Check(Check), SM(SM) {}

void FilesystemCheck::FilesystemCheckPPCallbacks::InclusionDirective(
    clang::SourceLocation HashLoc, const clang::Token& /*IncludeTok*/, llvm::StringRef FileName, bool /*IsAngled*/,
    clang::CharSourceRange /*FilenameRange*/, const clang::FileEntry* /*File*/, llvm::StringRef /*SearchPath*/,
    llvm::StringRef /*RelativePath*/, const clang::Module* /*Imported*/, clang::SrcMgr::CharacteristicKind /*FileType*/) {

  // Check for the filesystem include
  if (FileName.equals("filesystem")) {
    Check.diag(HashLoc, "Including <filesystem> is prohibited.");
  }
}

} // namespace bitcoin
