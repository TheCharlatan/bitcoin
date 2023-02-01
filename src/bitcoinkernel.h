#ifndef _BITCOIN_CHAINSTATE_WRAPPER
#define _BITCOIN_CHAINSTATE_WRAPPER

#ifndef __cplusplus
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#else
#include <cstddef>
#include <cstdint>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*LogCallback)(const char* message);

typedef void (*TRInsert)(void* user_data, void* event);
typedef void (*TRFlush)(void* user_data);
typedef size_t (*TRSize)(void* user_data);

struct TaskRunnerCallbacks {
    void* user_data;
    TRInsert insert;
    TRFlush flush;
    TRSize size;
};

/** Current sync state passed to tip changed callbacks. */
enum C_SynchronizationState {
    INIT_REINDEX,
    INIT_DOWNLOAD,
    POST_INIT
};

typedef void (*KNBlockTip)(void* user_data, enum C_SynchronizationState state, void* index);
typedef void (*KNHeaderTip)(void* user_data, enum C_SynchronizationState state, int64_t height, int64_t timestamp, bool presync);
typedef void (*KNProgress)(void* user_data, const char* title, int progress_percent, bool resume_possible);
typedef void (*KNWarning)(void* user_data, const char* warning);
typedef void (*KNFlushError)(void* user_data, const char* debug_message);
typedef void (*KNFatalError)(void* user_data, const char* debug_message, const char* user_message);

struct KernelNotificationInterfaceCallbacks {
    void* user_data;
    KNBlockTip block_tip;
    KNHeaderTip header_tip;
    KNProgress progress;
    KNWarning warning;
    KNFlushError flush_error;
    KNFatalError fatal_error;
};

typedef void (*VIBlockChecked)(void* user_data, void* block, void* stateIn);

struct ValidationInterfaceCallbacks {
    void* user_data;
    VIBlockChecked block_checked;
};

typedef struct {
    const char* path;
    int reindexing;
    int snapshot_active;
    int active_height;
    int active_ibd;
} C_ChainstateInfo;

typedef struct {
    const uint8_t* data;
    uint64_t len;
} ByteArray;

typedef struct {
    uint8_t hash[32];
    unsigned int n;
} C_OutPoint;

typedef struct {
    long int value;
    ByteArray script_pubkey;
} C_TxOut;

typedef struct {
    C_TxOut out;
    unsigned int is_coinbase;
    unsigned int confirmation_height;
} C_Coin;

void c_set_logging_callback_and_start_logging(LogCallback callback);
void* c_context_new(
    struct KernelNotificationInterfaceCallbacks kn_cbs,
    struct TaskRunnerCallbacks viq_cbs
);
void c_context_delete(void* context);
void c_execute_event(void* event);

void* c_create_validation_interface(struct ValidationInterfaceCallbacks vi_cbs);
void c_destroy_validation_interface(void* dummy_validation_interface_);
void c_register_validation_interface(void* context_, void* dummy_validation_interface_);
void c_unregister_validation_interface(void* context_, void* dummy_validation_interface_);

void* c_chainstate_manager_create(const char* data_dir, void* main_signals_);
C_ChainstateInfo c_get_chainstate_info(void* chainman_);
int c_chainstate_manager_validate_block(void* chainman_, void* main_signals_, const char* raw_block);
int c_chainstate_manager_delete(void* chainman_, void* main_signals_);

void* c_chainstate_coins_cursor(void* chainman_);
void c_coins_cursor_next(void* cursor_);
C_OutPoint c_coins_cursor_get_key(void* cursor_);
C_Coin c_coins_cursor_get_value(void* cursor_);
int c_coins_cursor_valid(void* cursor_);
void c_coins_cursor_delete(void* cursor_);

#ifdef __cplusplus
}
#endif

#endif // _BITCOIN_CHAINSTATE_WRAPPER
