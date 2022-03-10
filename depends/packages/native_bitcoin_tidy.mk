package=native_bitcoin_tidy
$(package)_version=89efb2d5ba33ae201f00c89cba1abf1ee47b443b
$(package)_download_path=https://github.com/theuni/bitcoin-tidy-experiments/archive
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=9cb3de45adf3ec60344d02c3d8c69567efc098a9c0a082de2e758307fbf86ff2
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
