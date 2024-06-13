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

// These are purposefully left opaque and are just used for better type safety
typedef struct C_ContextOptions C_ContextOptions;
typedef struct C_Context C_Context;
typedef struct C_ValidationInterface C_ValidationInterface;
typedef struct C_ChainstateManager C_ChainstateManager;
typedef struct C_ValidationEvent C_ValidationEvent;
typedef struct C_Block C_Block;
typedef struct C_BlockPointer C_BlockPointer;
typedef struct C_CoinsViewCursor C_CoinsViewCursor;
typedef struct C_TransactionRef C_TransactionRef;
typedef struct C_TransactionOut C_TransactionOut;
typedef struct C_TransactionIn C_TransactionIn;
typedef struct C_BlockIndex C_BlockIndex;
typedef struct C_BlockUndo C_BlockUndo;
typedef struct C_CoinOpaque C_CoinOpaque;
typedef struct C_TxUndo C_TxUndo;
typedef struct C_BlockHash C_BlockHash;
typedef struct C_MempoolAcceptResult C_MempoolAcceptResult;
typedef struct C_BlockHeader C_BlockHeader;

typedef void (*LogCallback)(const char* message);

typedef void (*TRInsert)(void* user_data, C_ValidationEvent* event);
typedef void (*TRFlush)(void* user_data);
typedef size_t (*TRSize)(void* user_data);

typedef struct {
    void* user_data;
    TRInsert insert;
    TRFlush flush;
    TRSize size;
} TaskRunnerCallbacks;

/** Current sync state passed to tip changed callbacks. */
typedef enum {
    INIT_REINDEX,
    INIT_DOWNLOAD,
    POST_INIT
} C_SynchronizationState;

typedef enum {
    kernel_MAINNET,
    kernel_TESTNET,
    kernel_SIGNET,
    kernel_REGTEST,
} C_Chain;

typedef enum {
    kernel_ERR_OK = 0,
    kernel_ERR_INVALID_POINTER,
    kernel_ERR_LOGGING_FAILED,
    kernel_ERR_UNKNOWN_OPTION,
    kernel_ERR_INVALID_CONTEXT,
    kernel_ERR_INTERNAL,
} kernel_error_code;

typedef struct {
    kernel_error_code code;
    char message[256];
} kernel_error;

typedef void (*KNBlockTip)(void* user_data, C_SynchronizationState state, void* index);
typedef void (*KNHeaderTip)(void* user_data, C_SynchronizationState state, int64_t height, int64_t timestamp, bool presync);
typedef void (*KNProgress)(void* user_data, const char* title, int progress_percent, bool resume_possible);
typedef void (*KNWarning)(void* user_data, const char* warning);
typedef void (*KNFlushError)(void* user_data, const char* message);
typedef void (*KNFatalError)(void* user_data, const char* message);

typedef struct {
    void* user_data;
    KNBlockTip block_tip;
    KNHeaderTip header_tip;
    KNProgress progress;
    KNWarning warning;
    KNFlushError flush_error;
    KNFatalError fatal_error;
} KernelNotificationInterfaceCallbacks;

typedef enum {
    BLOCK_RESULT_UNSET = 0, //!< initial value. Block has not yet been rejected
    BLOCK_CONSENSUS,        //!< invalid by consensus rules (excluding any below reasons)
    /**
     * Invalid by a change to consensus rules more recent than SegWit.
     * Currently unused as there are no such consensus rule changes, and any download
     * sources realistically need to support SegWit in order to provide useful data,
     * so differentiating between always-invalid and invalid-by-pre-SegWit-soft-fork
     * is uninteresting.
     */
    BLOCK_RECENT_CONSENSUS_CHANGE,
    BLOCK_CACHED_INVALID, //!< this block was cached as being invalid and we didn't store the reason why
    BLOCK_INVALID_HEADER, //!< invalid proof of work or time too old
    BLOCK_MUTATED,        //!< the block's data didn't match the data committed to by the PoW
    BLOCK_MISSING_PREV,   //!< We don't have the previous block the checked one is built on
    BLOCK_INVALID_PREV,   //!< A block this one builds on is invalid
    BLOCK_TIME_FUTURE,    //!< block timestamp was > 2 hours in the future (or our clock is bad)
    BLOCK_CHECKPOINT,     //!< the block failed to meet one of our checkpoints
    BLOCK_HEADER_LOW_WORK //!< the block header may be on a too-little-work chain
} C_BlockValidationResult;

typedef enum {
    M_VALID,   //!< everything ok
    M_INVALID, //!< network rule violation (DoS value may be set)
    M_ERROR,   //!< run-time error
} C_ModeState;

typedef struct {
    C_ModeState mode;
    C_BlockValidationResult result;
} C_BlockValidationState;

typedef void (*VIBlockChecked)(void* user_data, const C_BlockPointer* block_, C_BlockValidationState stateIn);

typedef struct {
    void* user_data;
    VIBlockChecked block_checked;
} ValidationInterfaceCallbacks;

typedef struct {
    uint8_t hash[32];
} BlockHash;

typedef struct {
    const uint8_t* data;
    uint64_t len;
} ByteArray;

typedef struct {
    const ByteArray* data;
    uint64_t len;
} TxInWitness;

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

typedef enum {
    KernelNotificationInterfaceCallbacksOption = 1,
    TaskRunnerCallbacksOption = 2,
    ChainTypeOption = 3,
} C_ContextOptionType;

typedef enum {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB,
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
} C_BuriedDeployment;

void c_set_logging_callback_and_start_logging(LogCallback callback, kernel_error* err);
C_ContextOptions* c_context_opt_create();
void c_context_set_opt(C_ContextOptions* context_opts_, C_ContextOptionType n_option, void* value, kernel_error* err);
void c_context_create(C_ContextOptions* context_opts_, C_Context** context, kernel_error* err);
void c_context_destroy(C_Context* context_, kernel_error* err);

void c_validation_interface_create(ValidationInterfaceCallbacks vi_cbs, C_ValidationInterface** validation_interface);
void c_validation_interface_destroy(C_ValidationInterface* validation_interface_, kernel_error* err);
void c_validation_interface_register(C_Context* context_, C_ValidationInterface* validation_interface_, kernel_error* err);
void c_validation_interface_unregister(C_Context* context_, C_ValidationInterface* validation_interface_, kernel_error* err);

void c_block_from_str(const char* block, C_Block** block_out, kernel_error* err);
BlockHash c_block_get_hash(C_Block* block_, kernel_error* err);
void c_block_get_header(C_Block* block_, C_BlockHeader** block_header_out, kernel_error* err);
void c_block_destroy(C_Block* block_);

void c_transaction_ref_from_str(const char* transaction, C_TransactionRef** transaction_out, kernel_error* err);
void c_transaction_ref_destroy(const C_TransactionRef* transaction_ref_, kernel_error* err);

void c_chainstate_manager_create(const char* data_dir, bool reindex, C_Context* context_, C_ChainstateManager** chainman, kernel_error* err);
bool c_chainstate_manager_validate_block(C_ChainstateManager* chainman_, C_Block* block_, kernel_error* err);
bool c_chainstate_manager_process_new_block_header(C_ChainstateManager* chainman_, C_BlockHeader* header_, bool min_pow_checked, kernel_error* err);
void c_process_transaction(C_ChainstateManager* chainman_, const C_TransactionRef* transaction_ref_, bool test_accept, C_MempoolAcceptResult** result_out, kernel_error* err);
void c_chainstate_manager_flush(C_ChainstateManager* chainman_, kernel_error* err);
void c_chainstate_manager_destroy(C_ChainstateManager* chainman_, C_Context* context_, kernel_error* err);
bool c_is_loading_blocks(C_ChainstateManager* chainman_, kernel_error* err);
bool c_is_initial_block_download(C_ChainstateManager* chainman_, kernel_error* err);

C_BlockIndex* c_lookup_block_index(C_ChainstateManager* chainman_, BlockHash* block_hash, kernel_error* err);
C_BlockIndex* c_get_genesis_block_index(C_ChainstateManager* chainman_, kernel_error* err);
C_BlockIndex* c_get_next_block_index(C_ChainstateManager* chainman_, kernel_error* err, C_BlockIndex* block_index_);
void c_read_block_data(C_ChainstateManager* chainman_, C_BlockIndex* block_index_, kernel_error* err, C_BlockPointer** block_data, bool read_block, C_BlockUndo** undo_data, bool read_undo);
int c_get_block_height(C_BlockIndex* block_index_, kernel_error* err);

void c_import_blocks(C_ChainstateManager* chainman_, kernel_error* err);
bool c_deployment_active_at(C_BlockIndex* prev_block_index_, C_ChainstateManager* chainman_, C_BuriedDeployment deployment, kernel_error* err);
bool c_deployment_active_after(C_BlockIndex* block_index_, C_ChainstateManager* chainman_, C_BuriedDeployment deployment, kernel_error* err);

void c_execute_event(C_ValidationEvent* event);

size_t c_number_of_txundo_in_block_undo(C_BlockUndo* undo_, kernel_error* err);
C_TxUndo* c_get_tx_undo_by_index(C_BlockUndo* undo_, kernel_error* err, uint64_t index);
size_t c_number_of_coins_in_tx_undo(C_TxUndo* undo_, kernel_error* err);
C_CoinOpaque* c_get_coin_by_index(C_TxUndo* undo_, kernel_error* err, uint64_t index);
C_TransactionOut* c_get_prevout(C_CoinOpaque* coin_, kernel_error* err);
void c_block_undo_destroy(C_BlockUndo* undo_, kernel_error* err);

void c_block_pointer_destroy(C_BlockPointer* block_, kernel_error* err);

bool c_is_block_mutated(C_BlockPointer* block_, bool check_witness_root, kernel_error* err);
size_t c_number_of_transactions_in_block(const C_BlockPointer* block_, kernel_error* err);
const C_TransactionRef* c_get_transaction_by_index(const C_BlockPointer* block_, kernel_error* err, uint64_t index);

uint32_t c_transaction_ref_get_locktime(const C_TransactionRef* transaction_ref_, kernel_error* err);
size_t c_get_transaction_output_size(const C_TransactionRef* transaction_ref_, kernel_error* err);
size_t c_get_transaction_input_size(const C_TransactionRef* transaction_ref_, kernel_error* err);
bool c_transaction_ref_is_coinbase(const C_TransactionRef* transaction_ref_, kernel_error* err);
const C_TransactionOut* c_get_output_by_index(const C_TransactionRef* transaction_ref_, kernel_error* err, uint64_t index);
const C_TransactionIn* c_get_input_by_index(const C_TransactionRef* transaction_ref_, kernel_error* err, uint64_t index);

void c_get_tx_in_witness(const C_TransactionIn* transaction_in_, TxInWitness** tx_in_witness, kernel_error* err);
void c_tx_in_witness_destroy(TxInWitness* tx_in_witness_, kernel_error* err);
void c_get_script_sig(const C_TransactionIn* transaction_in_, ByteArray** script_sig, kernel_error* err);
void c_get_prevout_hash(const C_TransactionIn* transaction_in_, ByteArray** txid, kernel_error* err);
uint32_t c_get_prevout_n(const C_TransactionIn* transaction_in_, kernel_error* err);
void c_get_script_pubkey(const C_TransactionOut* output_, ByteArray** script_pubkey, kernel_error* err);

void c_byte_array_destroy(ByteArray* data);

void c_chainstate_coins_cursor_create(C_ChainstateManager* chainman_, C_CoinsViewCursor** cursor, kernel_error* err);
void c_coins_cursor_next(C_CoinsViewCursor* cursor_, kernel_error* err);
C_OutPoint c_coins_cursor_get_key(C_CoinsViewCursor* cursor_, kernel_error* err);
C_Coin c_coins_cursor_get_value(C_CoinsViewCursor* cursor_, kernel_error* err);
bool c_coins_cursor_valid(C_CoinsViewCursor* cursor_, kernel_error* err);
void c_coins_cursor_destroy(C_CoinsViewCursor* cursor_, kernel_error* err);

#ifdef __cplusplus
}
#endif

#endif // _BITCOIN_CHAINSTATE_WRAPPER
