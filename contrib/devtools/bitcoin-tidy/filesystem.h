// Copyright (c) 2023 Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FILESYSTEM_CHECK_H
#define FILESYSTEM_CHECK_H

#include <clang-tidy/ClangTidyCheck.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Lex/PPCallbacks.h>

namespace bitcoin {

class FilesystemCheck : public clang::tidy::ClangTidyCheck {
  public:
    FilesystemCheck(llvm::StringRef Name, clang::tidy::ClangTidyContext *Context)
      : clang::tidy::ClangTidyCheck(Name, Context) {}

    void registerPPCallbacks(const clang::SourceManager &SM, clang::Preprocessor *PP, clang::Preprocessor *ModuleExpanderPP) override;

  private:
    class FilesystemCheckPPCallbacks : public clang::PPCallbacks {
      public:
        FilesystemCheckPPCallbacks(clang::tidy::ClangTidyCheck &Check, const clang::SourceManager &SM);

        void InclusionDirective(clang::SourceLocation HashLoc, const clang::Token &IncludeTok, llvm::StringRef FileName,
            bool IsAngled, clang::CharSourceRange FilenameRange, const clang::FileEntry *File,
            llvm::StringRef SearchPath, llvm::StringRef RelativePath, const clang::Module *Imported,
            clang::SrcMgr::CharacteristicKind FileType);

      private:
        clang::tidy::ClangTidyCheck &Check;
        const clang::SourceManager &SM;
    };
};

} // namespace bitcoin

#endif // FILESYSTEM_CHECK_H
