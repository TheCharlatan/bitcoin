package=native_clang_headers
$(package)_version=14.0.6
$(package)_download_path=https://github.com/llvm/llvm-project/releases/download/llvmorg-$($(package)_version)
$(package)_file_name=llvm-project-$($(package)_version).src.tar.xz
$(package)_sha256_hash=8b3cfd7bc695bd6cea0f37f53f0981f34f87496e79e2529874fd03a2f9dd3a8a
$(package)_config_opts=-S llvm
$(package)_config_opts+=-DCMAKE_BUILD_TYPE=Release
$(package)_config_opts+=-DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra"
$(package)_config_opts+=-DCLANG_TIDY_ENABLE_STATIC_ANALYZER=NO
$(package)_config_opts_x86_64=-DLLVM_TARGETS_TO_BUILD=X86
$(package)_config_opts_aarch64=-DLLVM_TARGETS_TO_BUILD=AArch64
$(package)_config_opts_powerpc64=-DLLVM_TARGETS_TO_BUILD=PowerPC

define $(package)_config_cmds
  $($(package)_cmake) $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE) llvm-headers clang-headers clang-tidy-headers clang-tidy clang-resource-headers
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install-llvm-headers install-clang-headers install-clang-tidy-headers install-clang-tidy install-clang-resource-headers
endef
