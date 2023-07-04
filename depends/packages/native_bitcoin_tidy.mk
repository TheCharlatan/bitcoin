package=native_bitcoin_tidy
$(package)_version=12cd64674cb477136ea9bce9110bf98f4c688061
$(package)_download_path=https://github.com/TheCharlatan/bitcoin-tidy-experiments/archive
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=50568033ff1b1e6d7af8c899bd82e5d3dbba9cd49aab0b4dff124e1941a9385f
$(package)_dependencies=native_clang_headers
define $(package)_config_cmds
  $($(package)_cmake)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
