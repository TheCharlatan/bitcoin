# -*- coding: utf-8 -*-
#
# TARGET arch is: []
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


class AsDictMixin:
    @classmethod
    def as_dict(cls, self):
        result = {}
        if not isinstance(self, AsDictMixin):
            # not a structure, assume it's already a python object
            return self
        if not hasattr(cls, "_fields_"):
            return result
        # sys.version_info >= (3, 5)
        # for (field, *_) in cls._fields_:  # noqa
        for field_tuple in cls._fields_:  # noqa
            field = field_tuple[0]
            if field.startswith('PADDING_'):
                continue
            value = getattr(self, field)
            type_ = type(value)
            if hasattr(value, "_length_") and hasattr(value, "_type_"):
                # array
                if not hasattr(type_, "as_dict"):
                    value = [v for v in value]
                else:
                    type_ = type_._type_
                    value = [type_.as_dict(v) for v in value]
            elif hasattr(value, "contents") and hasattr(value, "_type_"):
                # pointer
                try:
                    if not hasattr(type_, "as_dict"):
                        value = value.contents
                    else:
                        type_ = type_._type_
                        value = type_.as_dict(value.contents)
                except ValueError:
                    # nullptr
                    value = None
            elif isinstance(value, AsDictMixin):
                # other structure
                value = type_.as_dict(value)
            result[field] = value
        return result


class Structure(ctypes.Structure, AsDictMixin):

    def __init__(self, *args, **kwds):
        # We don't want to use positional arguments fill PADDING_* fields

        args = dict(zip(self.__class__._field_names_(), args))
        args.update(kwds)
        super(Structure, self).__init__(**args)

    @classmethod
    def _field_names_(cls):
        if hasattr(cls, '_fields_'):
            return (f[0] for f in cls._fields_ if not f[0].startswith('PADDING'))
        else:
            return ()

    @classmethod
    def get_type(cls, field):
        for f in cls._fields_:
            if f[0] == field:
                return f[1]
        return None

    @classmethod
    def bind(cls, bound_fields):
        fields = {}
        for name, type_ in cls._fields_:
            if hasattr(type_, "restype"):
                if name in bound_fields:
                    if bound_fields[name] is None:
                        fields[name] = type_()
                    else:
                        # use a closure to capture the callback from the loop scope
                        fields[name] = (
                            type_((lambda callback: lambda *args: callback(*args))(
                                bound_fields[name]))
                        )
                    del bound_fields[name]
                else:
                    # default callback implementation (does nothing)
                    try:
                        default_ = type_(0).restype().value
                    except TypeError:
                        default_ = None
                    fields[name] = type_((
                        lambda default_: lambda *args: default_)(default_))
            else:
                # not a callback function, use default initialization
                if name in bound_fields:
                    fields[name] = bound_fields[name]
                    del bound_fields[name]
                else:
                    fields[name] = type_()
        if len(bound_fields) != 0:
            raise ValueError(
                "Cannot bind the following unknown callback(s) {}.{}".format(
                    cls.__name__, bound_fields.keys()
            ))
        return cls(**fields)


class Union(ctypes.Union, AsDictMixin):
    pass



c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*16

def string_cast(char_pointer, encoding='utf-8', errors='strict'):
    value = ctypes.cast(char_pointer, ctypes.c_char_p).value
    if value is not None and encoding is not None:
        value = value.decode(encoding, errors=errors)
    return value


def char_pointer_cast(string, encoding='utf-8'):
    if encoding is not None:
        try:
            string = string.encode(encoding)
        except AttributeError:
            # In Python3, bytes has no encode attribute
            pass
    string = ctypes.c_char_p(string)
    return ctypes.cast(string, ctypes.POINTER(ctypes.c_char))



_libraries = {}
_libraries['libbitcoinkernel.so'] = ctypes.CDLL('/home/drgrid/bitcoin/src/.libs/libbitcoinkernel.so')


class struct_C_ContextOptions(Structure):
    pass

C_ContextOptions = struct_C_ContextOptions
class struct_C_Context(Structure):
    pass

C_Context = struct_C_Context
class struct_C_ValidationInterface(Structure):
    pass

C_ValidationInterface = struct_C_ValidationInterface
class struct_C_ChainstateManager(Structure):
    pass

C_ChainstateManager = struct_C_ChainstateManager
class struct_C_ValidationEvent(Structure):
    pass

C_ValidationEvent = struct_C_ValidationEvent
class struct_C_Block(Structure):
    pass

C_Block = struct_C_Block
class struct_C_BlockPointer(Structure):
    pass

C_BlockPointer = struct_C_BlockPointer
class struct_C_CoinsViewCursor(Structure):
    pass

C_CoinsViewCursor = struct_C_CoinsViewCursor
class struct_C_TransactionRef(Structure):
    pass

C_TransactionRef = struct_C_TransactionRef
class struct_C_TransactionOut(Structure):
    pass

C_TransactionOut = struct_C_TransactionOut
class struct_C_TransactionIn(Structure):
    pass

C_TransactionIn = struct_C_TransactionIn
class struct_C_BlockIndex(Structure):
    pass

C_BlockIndex = struct_C_BlockIndex
class struct_C_BlockUndo(Structure):
    pass

C_BlockUndo = struct_C_BlockUndo
class struct_C_CoinOpaque(Structure):
    pass

C_CoinOpaque = struct_C_CoinOpaque
class struct_C_TxUndo(Structure):
    pass

C_TxUndo = struct_C_TxUndo
class struct_C_BlockHash(Structure):
    pass

C_BlockHash = struct_C_BlockHash
class struct_C_MempoolAcceptResult(Structure):
    pass

C_MempoolAcceptResult = struct_C_MempoolAcceptResult
class struct_C_BlockHeader(Structure):
    pass

C_BlockHeader = struct_C_BlockHeader
LogCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))
TRInsert = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(struct_C_ValidationEvent))
TRFlush = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
TRSize = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(None))
class struct_TaskRunnerCallbacks(Structure):
    pass

struct_TaskRunnerCallbacks._pack_ = 1 # source:False
struct_TaskRunnerCallbacks._fields_ = [
    ('user_data', ctypes.POINTER(None)),
    ('insert', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(struct_C_ValidationEvent))),
    ('flush', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('size', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(None))),
]

TaskRunnerCallbacks = struct_TaskRunnerCallbacks

# values for enumeration 'C_SynchronizationState'
C_SynchronizationState__enumvalues = {
    0: 'INIT_REINDEX',
    1: 'INIT_DOWNLOAD',
    2: 'POST_INIT',
}
INIT_REINDEX = 0
INIT_DOWNLOAD = 1
POST_INIT = 2
C_SynchronizationState = ctypes.c_uint32 # enum

# values for enumeration 'C_Chain'
C_Chain__enumvalues = {
    0: 'kernel_MAINNET',
    1: 'kernel_TESTNET',
    2: 'kernel_SIGNET',
    3: 'kernel_REGTEST',
}
kernel_MAINNET = 0
kernel_TESTNET = 1
kernel_SIGNET = 2
kernel_REGTEST = 3
C_Chain = ctypes.c_uint32 # enum

# values for enumeration 'kernel_error_code'
kernel_error_code__enumvalues = {
    0: 'kernel_ERR_OK',
    1: 'kernel_ERR_INVALID_POINTER',
    2: 'kernel_ERR_LOGGING_FAILED',
    3: 'kernel_ERR_UNKNOWN_OPTION',
    4: 'kernel_ERR_INVALID_CONTEXT',
    5: 'kernel_ERR_INTERNAL',
}
kernel_ERR_OK = 0
kernel_ERR_INVALID_POINTER = 1
kernel_ERR_LOGGING_FAILED = 2
kernel_ERR_UNKNOWN_OPTION = 3
kernel_ERR_INVALID_CONTEXT = 4
kernel_ERR_INTERNAL = 5
kernel_error_code = ctypes.c_uint32 # enum
class struct_kernel_error(Structure):
    pass

struct_kernel_error._pack_ = 1 # source:False
struct_kernel_error._fields_ = [
    ('code', kernel_error_code),
    ('message', ctypes.c_char * 256),
]

kernel_error = struct_kernel_error
KNBlockTip = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), C_SynchronizationState, ctypes.POINTER(None))
KNHeaderTip = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), C_SynchronizationState, ctypes.c_int64, ctypes.c_int64, ctypes.c_bool)
KNProgress = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool)
KNWarning = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
KNFlushError = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
KNFatalError = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
class struct_KernelNotificationInterfaceCallbacks(Structure):
    pass

struct_KernelNotificationInterfaceCallbacks._pack_ = 1 # source:False
struct_KernelNotificationInterfaceCallbacks._fields_ = [
    ('user_data', ctypes.POINTER(None)),
    ('block_tip', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), C_SynchronizationState, ctypes.POINTER(None))),
    ('header_tip', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), C_SynchronizationState, ctypes.c_int64, ctypes.c_int64, ctypes.c_bool)),
    ('progress', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool)),
    ('warning', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('flush_error', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
    ('fatal_error', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))),
]

KernelNotificationInterfaceCallbacks = struct_KernelNotificationInterfaceCallbacks

# values for enumeration 'C_BlockValidationResult'
C_BlockValidationResult__enumvalues = {
    0: 'BLOCK_RESULT_UNSET',
    1: 'BLOCK_CONSENSUS',
    2: 'BLOCK_RECENT_CONSENSUS_CHANGE',
    3: 'BLOCK_CACHED_INVALID',
    4: 'BLOCK_INVALID_HEADER',
    5: 'BLOCK_MUTATED',
    6: 'BLOCK_MISSING_PREV',
    7: 'BLOCK_INVALID_PREV',
    8: 'BLOCK_TIME_FUTURE',
    9: 'BLOCK_CHECKPOINT',
    10: 'BLOCK_HEADER_LOW_WORK',
}
BLOCK_RESULT_UNSET = 0
BLOCK_CONSENSUS = 1
BLOCK_RECENT_CONSENSUS_CHANGE = 2
BLOCK_CACHED_INVALID = 3
BLOCK_INVALID_HEADER = 4
BLOCK_MUTATED = 5
BLOCK_MISSING_PREV = 6
BLOCK_INVALID_PREV = 7
BLOCK_TIME_FUTURE = 8
BLOCK_CHECKPOINT = 9
BLOCK_HEADER_LOW_WORK = 10
C_BlockValidationResult = ctypes.c_uint32 # enum

# values for enumeration 'C_ModeState'
C_ModeState__enumvalues = {
    0: 'M_VALID',
    1: 'M_INVALID',
    2: 'M_ERROR',
}
M_VALID = 0
M_INVALID = 1
M_ERROR = 2
C_ModeState = ctypes.c_uint32 # enum
class struct_C_BlockValidationState(Structure):
    _pack_ = 1 # source:False
    _fields_ = [
    ('mode', C_ModeState),
    ('result', C_BlockValidationResult),
     ]

C_BlockValidationState = struct_C_BlockValidationState
VIBlockChecked = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(struct_C_BlockPointer), struct_C_BlockValidationState)
class struct_ValidationInterfaceCallbacks(Structure):
    pass

struct_ValidationInterfaceCallbacks._pack_ = 1 # source:False
struct_ValidationInterfaceCallbacks._fields_ = [
    ('user_data', ctypes.POINTER(None)),
    ('block_checked', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(struct_C_BlockPointer), struct_C_BlockValidationState)),
]

ValidationInterfaceCallbacks = struct_ValidationInterfaceCallbacks
class struct_BlockHash(Structure):
    pass

struct_BlockHash._pack_ = 1 # source:False
struct_BlockHash._fields_ = [
    ('hash', ctypes.c_ubyte * 32),
]

BlockHash = struct_BlockHash
class struct_ByteArray(Structure):
    pass

struct_ByteArray._pack_ = 1 # source:False
struct_ByteArray._fields_ = [
    ('data', ctypes.POINTER(ctypes.c_ubyte)),
    ('len', ctypes.c_uint64),
]

ByteArray = struct_ByteArray
class struct_TxInWitness(Structure):
    pass

struct_TxInWitness._pack_ = 1 # source:False
struct_TxInWitness._fields_ = [
    ('data', ctypes.POINTER(struct_ByteArray)),
    ('len', ctypes.c_uint64),
]

TxInWitness = struct_TxInWitness
class struct_C_OutPoint(Structure):
    pass

struct_C_OutPoint._pack_ = 1 # source:False
struct_C_OutPoint._fields_ = [
    ('hash', ctypes.c_ubyte * 32),
    ('n', ctypes.c_uint32),
]

C_OutPoint = struct_C_OutPoint
class struct_C_TxOut(Structure):
    pass

struct_C_TxOut._pack_ = 1 # source:False
struct_C_TxOut._fields_ = [
    ('value', ctypes.c_int64),
    ('script_pubkey', ByteArray),
]

C_TxOut = struct_C_TxOut
class struct_C_Coin(Structure):
    pass

struct_C_Coin._pack_ = 1 # source:False
struct_C_Coin._fields_ = [
    ('out', C_TxOut),
    ('is_coinbase', ctypes.c_uint32),
    ('confirmation_height', ctypes.c_uint32),
]

C_Coin = struct_C_Coin

# values for enumeration 'C_ContextOptionType'
C_ContextOptionType__enumvalues = {
    1: 'KernelNotificationInterfaceCallbacksOption',
    2: 'TaskRunnerCallbacksOption',
    3: 'ChainTypeOption',
}
KernelNotificationInterfaceCallbacksOption = 1
TaskRunnerCallbacksOption = 2
ChainTypeOption = 3
C_ContextOptionType = ctypes.c_uint32 # enum

# values for enumeration 'C_BuriedDeployment'
C_BuriedDeployment__enumvalues = {
    0: 'DEPLOYMENT_HEIGHTINCB',
    1: 'DEPLOYMENT_CLTV',
    2: 'DEPLOYMENT_DERSIG',
    3: 'DEPLOYMENT_CSV',
    4: 'DEPLOYMENT_SEGWIT',
}
DEPLOYMENT_HEIGHTINCB = 0
DEPLOYMENT_CLTV = 1
DEPLOYMENT_DERSIG = 2
DEPLOYMENT_CSV = 3
DEPLOYMENT_SEGWIT = 4
C_BuriedDeployment = ctypes.c_uint32 # enum
c_set_logging_callback_and_start_logging = _libraries['libbitcoinkernel.so'].c_set_logging_callback_and_start_logging
c_set_logging_callback_and_start_logging.restype = None
c_set_logging_callback_and_start_logging.argtypes = [LogCallback, ctypes.POINTER(struct_kernel_error)]
c_context_opt_create = _libraries['libbitcoinkernel.so'].c_context_opt_create
c_context_opt_create.restype = ctypes.POINTER(struct_C_ContextOptions)
c_context_opt_create.argtypes = []
c_context_set_opt = _libraries['libbitcoinkernel.so'].c_context_set_opt
c_context_set_opt.restype = None
c_context_set_opt.argtypes = [ctypes.POINTER(struct_C_ContextOptions), C_ContextOptionType, ctypes.POINTER(None), ctypes.POINTER(struct_kernel_error)]
c_context_create = _libraries['libbitcoinkernel.so'].c_context_create
c_context_create.restype = None
c_context_create.argtypes = [ctypes.POINTER(struct_C_ContextOptions), ctypes.POINTER(ctypes.POINTER(struct_C_Context)), ctypes.POINTER(struct_kernel_error)]
c_context_destroy = _libraries['libbitcoinkernel.so'].c_context_destroy
c_context_destroy.restype = None
c_context_destroy.argtypes = [ctypes.POINTER(struct_C_Context), ctypes.POINTER(struct_kernel_error)]
c_validation_interface_create = _libraries['libbitcoinkernel.so'].c_validation_interface_create
c_validation_interface_create.restype = None
c_validation_interface_create.argtypes = [ValidationInterfaceCallbacks, ctypes.POINTER(ctypes.POINTER(struct_C_ValidationInterface))]
c_validation_interface_destroy = _libraries['libbitcoinkernel.so'].c_validation_interface_destroy
c_validation_interface_destroy.restype = None
c_validation_interface_destroy.argtypes = [ctypes.POINTER(struct_C_ValidationInterface), ctypes.POINTER(struct_kernel_error)]
c_validation_interface_register = _libraries['libbitcoinkernel.so'].c_validation_interface_register
c_validation_interface_register.restype = None
c_validation_interface_register.argtypes = [ctypes.POINTER(struct_C_Context), ctypes.POINTER(struct_C_ValidationInterface), ctypes.POINTER(struct_kernel_error)]
c_validation_interface_unregister = _libraries['libbitcoinkernel.so'].c_validation_interface_unregister
c_validation_interface_unregister.restype = None
c_validation_interface_unregister.argtypes = [ctypes.POINTER(struct_C_Context), ctypes.POINTER(struct_C_ValidationInterface), ctypes.POINTER(struct_kernel_error)]
c_block_from_str = _libraries['libbitcoinkernel.so'].c_block_from_str
c_block_from_str.restype = None
c_block_from_str.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(struct_C_Block)), ctypes.POINTER(struct_kernel_error)]
c_block_get_hash = _libraries['libbitcoinkernel.so'].c_block_get_hash
c_block_get_hash.restype = BlockHash
c_block_get_hash.argtypes = [ctypes.POINTER(struct_C_Block), ctypes.POINTER(struct_kernel_error)]
c_block_get_header = _libraries['libbitcoinkernel.so'].c_block_get_header
c_block_get_header.restype = None
c_block_get_header.argtypes = [ctypes.POINTER(struct_C_Block), ctypes.POINTER(ctypes.POINTER(struct_C_BlockHeader)), ctypes.POINTER(struct_kernel_error)]
c_block_destroy = _libraries['libbitcoinkernel.so'].c_block_destroy
c_block_destroy.restype = None
c_block_destroy.argtypes = [ctypes.POINTER(struct_C_Block)]
c_transaction_ref_from_str = _libraries['libbitcoinkernel.so'].c_transaction_ref_from_str
c_transaction_ref_from_str.restype = None
c_transaction_ref_from_str.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.POINTER(struct_C_TransactionRef)), ctypes.POINTER(struct_kernel_error)]
c_transaction_ref_destroy = _libraries['libbitcoinkernel.so'].c_transaction_ref_destroy
c_transaction_ref_destroy.restype = None
c_transaction_ref_destroy.argtypes = [ctypes.POINTER(struct_C_TransactionRef), ctypes.POINTER(struct_kernel_error)]
c_chainstate_manager_create = _libraries['libbitcoinkernel.so'].c_chainstate_manager_create
c_chainstate_manager_create.restype = None
c_chainstate_manager_create.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_bool, ctypes.POINTER(struct_C_Context), ctypes.POINTER(ctypes.POINTER(struct_C_ChainstateManager)), ctypes.POINTER(struct_kernel_error)]
c_chainstate_manager_validate_block = _libraries['libbitcoinkernel.so'].c_chainstate_manager_validate_block
c_chainstate_manager_validate_block.restype = ctypes.c_bool
c_chainstate_manager_validate_block.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_C_Block), ctypes.POINTER(struct_kernel_error)]
c_chainstate_manager_process_new_block_header = _libraries['libbitcoinkernel.so'].c_chainstate_manager_process_new_block_header
c_chainstate_manager_process_new_block_header.restype = ctypes.c_bool
c_chainstate_manager_process_new_block_header.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_C_BlockHeader), ctypes.c_bool, ctypes.POINTER(struct_kernel_error)]
c_process_transaction = _libraries['libbitcoinkernel.so'].c_process_transaction
c_process_transaction.restype = None
c_process_transaction.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_C_TransactionRef), ctypes.c_bool, ctypes.POINTER(ctypes.POINTER(struct_C_MempoolAcceptResult)), ctypes.POINTER(struct_kernel_error)]
c_chainstate_manager_flush = _libraries['libbitcoinkernel.so'].c_chainstate_manager_flush
c_chainstate_manager_flush.restype = None
c_chainstate_manager_flush.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_kernel_error)]
c_chainstate_manager_destroy = _libraries['libbitcoinkernel.so'].c_chainstate_manager_destroy
c_chainstate_manager_destroy.restype = None
c_chainstate_manager_destroy.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_C_Context), ctypes.POINTER(struct_kernel_error)]
c_is_loading_blocks = _libraries['libbitcoinkernel.so'].c_is_loading_blocks
c_is_loading_blocks.restype = ctypes.c_bool
c_is_loading_blocks.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_kernel_error)]
c_is_initial_block_download = _libraries['libbitcoinkernel.so'].c_is_initial_block_download
c_is_initial_block_download.restype = ctypes.c_bool
c_is_initial_block_download.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_kernel_error)]
c_lookup_block_index = _libraries['libbitcoinkernel.so'].c_lookup_block_index
c_lookup_block_index.restype = ctypes.POINTER(struct_C_BlockIndex)
c_lookup_block_index.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_BlockHash), ctypes.POINTER(struct_kernel_error)]
c_get_genesis_block_index = _libraries['libbitcoinkernel.so'].c_get_genesis_block_index
c_get_genesis_block_index.restype = ctypes.POINTER(struct_C_BlockIndex)
c_get_genesis_block_index.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_kernel_error)]
c_get_next_block_index = _libraries['libbitcoinkernel.so'].c_get_next_block_index
c_get_next_block_index.restype = ctypes.POINTER(struct_C_BlockIndex)
c_get_next_block_index.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_kernel_error), ctypes.POINTER(struct_C_BlockIndex)]
c_read_block_data = _libraries['libbitcoinkernel.so'].c_read_block_data
c_read_block_data.restype = None
c_read_block_data.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_C_BlockIndex), ctypes.POINTER(struct_kernel_error), ctypes.POINTER(ctypes.POINTER(struct_C_BlockPointer)), ctypes.c_bool, ctypes.POINTER(ctypes.POINTER(struct_C_BlockUndo)), ctypes.c_bool]
c_get_block_height = _libraries['libbitcoinkernel.so'].c_get_block_height
c_get_block_height.restype = ctypes.c_int32
c_get_block_height.argtypes = [ctypes.POINTER(struct_C_BlockIndex), ctypes.POINTER(struct_kernel_error)]
c_import_blocks = _libraries['libbitcoinkernel.so'].c_import_blocks
c_import_blocks.restype = None
c_import_blocks.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(struct_kernel_error)]
c_deployment_active_at = _libraries['libbitcoinkernel.so'].c_deployment_active_at
c_deployment_active_at.restype = ctypes.c_bool
c_deployment_active_at.argtypes = [ctypes.POINTER(struct_C_BlockIndex), ctypes.POINTER(struct_C_ChainstateManager), C_BuriedDeployment, ctypes.POINTER(struct_kernel_error)]
c_deployment_active_after = _libraries['libbitcoinkernel.so'].c_deployment_active_after
c_deployment_active_after.restype = ctypes.c_bool
c_deployment_active_after.argtypes = [ctypes.POINTER(struct_C_BlockIndex), ctypes.POINTER(struct_C_ChainstateManager), C_BuriedDeployment, ctypes.POINTER(struct_kernel_error)]
c_execute_event = _libraries['libbitcoinkernel.so'].c_execute_event
c_execute_event.restype = None
c_execute_event.argtypes = [ctypes.POINTER(struct_C_ValidationEvent)]
size_t = ctypes.c_uint64
c_number_of_txundo_in_block_undo = _libraries['libbitcoinkernel.so'].c_number_of_txundo_in_block_undo
c_number_of_txundo_in_block_undo.restype = size_t
c_number_of_txundo_in_block_undo.argtypes = [ctypes.POINTER(struct_C_BlockUndo), ctypes.POINTER(struct_kernel_error)]
uint64_t = ctypes.c_uint64
c_get_tx_undo_by_index = _libraries['libbitcoinkernel.so'].c_get_tx_undo_by_index
c_get_tx_undo_by_index.restype = ctypes.POINTER(struct_C_TxUndo)
c_get_tx_undo_by_index.argtypes = [ctypes.POINTER(struct_C_BlockUndo), ctypes.POINTER(struct_kernel_error), uint64_t]
c_number_of_coins_in_tx_undo = _libraries['libbitcoinkernel.so'].c_number_of_coins_in_tx_undo
c_number_of_coins_in_tx_undo.restype = size_t
c_number_of_coins_in_tx_undo.argtypes = [ctypes.POINTER(struct_C_TxUndo), ctypes.POINTER(struct_kernel_error)]
c_get_coin_by_index = _libraries['libbitcoinkernel.so'].c_get_coin_by_index
c_get_coin_by_index.restype = ctypes.POINTER(struct_C_CoinOpaque)
c_get_coin_by_index.argtypes = [ctypes.POINTER(struct_C_TxUndo), ctypes.POINTER(struct_kernel_error), uint64_t]
c_get_prevout = _libraries['libbitcoinkernel.so'].c_get_prevout
c_get_prevout.restype = ctypes.POINTER(struct_C_TransactionOut)
c_get_prevout.argtypes = [ctypes.POINTER(struct_C_CoinOpaque), ctypes.POINTER(struct_kernel_error)]
c_block_undo_destroy = _libraries['libbitcoinkernel.so'].c_block_undo_destroy
c_block_undo_destroy.restype = None
c_block_undo_destroy.argtypes = [ctypes.POINTER(struct_C_BlockUndo), ctypes.POINTER(struct_kernel_error)]
c_block_pointer_destroy = _libraries['libbitcoinkernel.so'].c_block_pointer_destroy
c_block_pointer_destroy.restype = None
c_block_pointer_destroy.argtypes = [ctypes.POINTER(struct_C_BlockPointer), ctypes.POINTER(struct_kernel_error)]
c_is_block_mutated = _libraries['libbitcoinkernel.so'].c_is_block_mutated
c_is_block_mutated.restype = ctypes.c_bool
c_is_block_mutated.argtypes = [ctypes.POINTER(struct_C_BlockPointer), ctypes.c_bool, ctypes.POINTER(struct_kernel_error)]
c_number_of_transactions_in_block = _libraries['libbitcoinkernel.so'].c_number_of_transactions_in_block
c_number_of_transactions_in_block.restype = size_t
c_number_of_transactions_in_block.argtypes = [ctypes.POINTER(struct_C_BlockPointer), ctypes.POINTER(struct_kernel_error)]
c_get_transaction_by_index = _libraries['libbitcoinkernel.so'].c_get_transaction_by_index
c_get_transaction_by_index.restype = ctypes.POINTER(struct_C_TransactionRef)
c_get_transaction_by_index.argtypes = [ctypes.POINTER(struct_C_BlockPointer), ctypes.POINTER(struct_kernel_error), uint64_t]
uint32_t = ctypes.c_uint32
c_transaction_ref_get_locktime = _libraries['libbitcoinkernel.so'].c_transaction_ref_get_locktime
c_transaction_ref_get_locktime.restype = uint32_t
c_transaction_ref_get_locktime.argtypes = [ctypes.POINTER(struct_C_TransactionRef), ctypes.POINTER(struct_kernel_error)]
c_get_transaction_output_size = _libraries['libbitcoinkernel.so'].c_get_transaction_output_size
c_get_transaction_output_size.restype = size_t
c_get_transaction_output_size.argtypes = [ctypes.POINTER(struct_C_TransactionRef), ctypes.POINTER(struct_kernel_error)]
c_get_transaction_input_size = _libraries['libbitcoinkernel.so'].c_get_transaction_input_size
c_get_transaction_input_size.restype = size_t
c_get_transaction_input_size.argtypes = [ctypes.POINTER(struct_C_TransactionRef), ctypes.POINTER(struct_kernel_error)]
c_transaction_ref_is_coinbase = _libraries['libbitcoinkernel.so'].c_transaction_ref_is_coinbase
c_transaction_ref_is_coinbase.restype = ctypes.c_bool
c_transaction_ref_is_coinbase.argtypes = [ctypes.POINTER(struct_C_TransactionRef), ctypes.POINTER(struct_kernel_error)]
c_get_output_by_index = _libraries['libbitcoinkernel.so'].c_get_output_by_index
c_get_output_by_index.restype = ctypes.POINTER(struct_C_TransactionOut)
c_get_output_by_index.argtypes = [ctypes.POINTER(struct_C_TransactionRef), ctypes.POINTER(struct_kernel_error), uint64_t]
c_get_input_by_index = _libraries['libbitcoinkernel.so'].c_get_input_by_index
c_get_input_by_index.restype = ctypes.POINTER(struct_C_TransactionIn)
c_get_input_by_index.argtypes = [ctypes.POINTER(struct_C_TransactionRef), ctypes.POINTER(struct_kernel_error), uint64_t]
c_get_tx_in_witness = _libraries['libbitcoinkernel.so'].c_get_tx_in_witness
c_get_tx_in_witness.restype = None
c_get_tx_in_witness.argtypes = [ctypes.POINTER(struct_C_TransactionIn), ctypes.POINTER(ctypes.POINTER(struct_TxInWitness)), ctypes.POINTER(struct_kernel_error)]
c_tx_in_witness_destroy = _libraries['libbitcoinkernel.so'].c_tx_in_witness_destroy
c_tx_in_witness_destroy.restype = None
c_tx_in_witness_destroy.argtypes = [ctypes.POINTER(struct_TxInWitness), ctypes.POINTER(struct_kernel_error)]
c_get_script_sig = _libraries['libbitcoinkernel.so'].c_get_script_sig
c_get_script_sig.restype = None
c_get_script_sig.argtypes = [ctypes.POINTER(struct_C_TransactionIn), ctypes.POINTER(ctypes.POINTER(struct_ByteArray)), ctypes.POINTER(struct_kernel_error)]
c_get_prevout_hash = _libraries['libbitcoinkernel.so'].c_get_prevout_hash
c_get_prevout_hash.restype = None
c_get_prevout_hash.argtypes = [ctypes.POINTER(struct_C_TransactionIn), ctypes.POINTER(ctypes.POINTER(struct_ByteArray)), ctypes.POINTER(struct_kernel_error)]
c_get_prevout_n = _libraries['libbitcoinkernel.so'].c_get_prevout_n
c_get_prevout_n.restype = uint32_t
c_get_prevout_n.argtypes = [ctypes.POINTER(struct_C_TransactionIn), ctypes.POINTER(struct_kernel_error)]
c_get_script_pubkey = _libraries['libbitcoinkernel.so'].c_get_script_pubkey
c_get_script_pubkey.restype = None
c_get_script_pubkey.argtypes = [ctypes.POINTER(struct_C_TransactionOut), ctypes.POINTER(ctypes.POINTER(struct_ByteArray)), ctypes.POINTER(struct_kernel_error)]
c_byte_array_destroy = _libraries['libbitcoinkernel.so'].c_byte_array_destroy
c_byte_array_destroy.restype = None
c_byte_array_destroy.argtypes = [ctypes.POINTER(struct_ByteArray)]
c_chainstate_coins_cursor_create = _libraries['libbitcoinkernel.so'].c_chainstate_coins_cursor_create
c_chainstate_coins_cursor_create.restype = None
c_chainstate_coins_cursor_create.argtypes = [ctypes.POINTER(struct_C_ChainstateManager), ctypes.POINTER(ctypes.POINTER(struct_C_CoinsViewCursor)), ctypes.POINTER(struct_kernel_error)]
c_coins_cursor_next = _libraries['libbitcoinkernel.so'].c_coins_cursor_next
c_coins_cursor_next.restype = None
c_coins_cursor_next.argtypes = [ctypes.POINTER(struct_C_CoinsViewCursor), ctypes.POINTER(struct_kernel_error)]
c_coins_cursor_get_key = _libraries['libbitcoinkernel.so'].c_coins_cursor_get_key
c_coins_cursor_get_key.restype = C_OutPoint
c_coins_cursor_get_key.argtypes = [ctypes.POINTER(struct_C_CoinsViewCursor), ctypes.POINTER(struct_kernel_error)]
c_coins_cursor_get_value = _libraries['libbitcoinkernel.so'].c_coins_cursor_get_value
c_coins_cursor_get_value.restype = C_Coin
c_coins_cursor_get_value.argtypes = [ctypes.POINTER(struct_C_CoinsViewCursor), ctypes.POINTER(struct_kernel_error)]
c_coins_cursor_valid = _libraries['libbitcoinkernel.so'].c_coins_cursor_valid
c_coins_cursor_valid.restype = ctypes.c_bool
c_coins_cursor_valid.argtypes = [ctypes.POINTER(struct_C_CoinsViewCursor), ctypes.POINTER(struct_kernel_error)]
c_coins_cursor_destroy = _libraries['libbitcoinkernel.so'].c_coins_cursor_destroy
c_coins_cursor_destroy.restype = None
c_coins_cursor_destroy.argtypes = [ctypes.POINTER(struct_C_CoinsViewCursor), ctypes.POINTER(struct_kernel_error)]
__all__ = \
    ['BLOCK_CACHED_INVALID', 'BLOCK_CHECKPOINT', 'BLOCK_CONSENSUS',
    'BLOCK_HEADER_LOW_WORK', 'BLOCK_INVALID_HEADER',
    'BLOCK_INVALID_PREV', 'BLOCK_MISSING_PREV', 'BLOCK_MUTATED',
    'BLOCK_RECENT_CONSENSUS_CHANGE', 'BLOCK_RESULT_UNSET',
    'BLOCK_TIME_FUTURE', 'BlockHash', 'ByteArray', 'C_Block',
    'C_BlockHash', 'C_BlockHeader', 'C_BlockIndex', 'C_BlockPointer',
    'C_BlockUndo', 'C_BlockValidationResult',
    'C_BlockValidationState', 'C_BuriedDeployment', 'C_Chain',
    'C_ChainstateManager', 'C_Coin', 'C_CoinOpaque',
    'C_CoinsViewCursor', 'C_Context', 'C_ContextOptionType',
    'C_ContextOptions', 'C_MempoolAcceptResult', 'C_ModeState',
    'C_OutPoint', 'C_SynchronizationState', 'C_TransactionIn',
    'C_TransactionOut', 'C_TransactionRef', 'C_TxOut', 'C_TxUndo',
    'C_ValidationEvent', 'C_ValidationInterface', 'ChainTypeOption',
    'DEPLOYMENT_CLTV', 'DEPLOYMENT_CSV', 'DEPLOYMENT_DERSIG',
    'DEPLOYMENT_HEIGHTINCB', 'DEPLOYMENT_SEGWIT', 'INIT_DOWNLOAD',
    'INIT_REINDEX', 'KNBlockTip', 'KNFatalError', 'KNFlushError',
    'KNHeaderTip', 'KNProgress', 'KNWarning',
    'KernelNotificationInterfaceCallbacks',
    'KernelNotificationInterfaceCallbacksOption', 'LogCallback',
    'M_ERROR', 'M_INVALID', 'M_VALID', 'POST_INIT', 'TRFlush',
    'TRInsert', 'TRSize', 'TaskRunnerCallbacks',
    'TaskRunnerCallbacksOption', 'TxInWitness', 'VIBlockChecked',
    'ValidationInterfaceCallbacks', 'c_block_destroy',
    'c_block_from_str', 'c_block_get_hash', 'c_block_get_header',
    'c_block_pointer_destroy', 'c_block_undo_destroy',
    'c_byte_array_destroy', 'c_chainstate_coins_cursor_create',
    'c_chainstate_manager_create', 'c_chainstate_manager_destroy',
    'c_chainstate_manager_flush',
    'c_chainstate_manager_process_new_block_header',
    'c_chainstate_manager_validate_block', 'c_coins_cursor_destroy',
    'c_coins_cursor_get_key', 'c_coins_cursor_get_value',
    'c_coins_cursor_next', 'c_coins_cursor_valid', 'c_context_create',
    'c_context_destroy', 'c_context_opt_create', 'c_context_set_opt',
    'c_deployment_active_after', 'c_deployment_active_at',
    'c_execute_event', 'c_get_block_height', 'c_get_coin_by_index',
    'c_get_genesis_block_index', 'c_get_input_by_index',
    'c_get_next_block_index', 'c_get_output_by_index',
    'c_get_prevout', 'c_get_prevout_hash', 'c_get_prevout_n',
    'c_get_script_pubkey', 'c_get_script_sig',
    'c_get_transaction_by_index', 'c_get_transaction_input_size',
    'c_get_transaction_output_size', 'c_get_tx_in_witness',
    'c_get_tx_undo_by_index', 'c_import_blocks', 'c_is_block_mutated',
    'c_is_initial_block_download', 'c_is_loading_blocks',
    'c_lookup_block_index', 'c_number_of_coins_in_tx_undo',
    'c_number_of_transactions_in_block',
    'c_number_of_txundo_in_block_undo', 'c_process_transaction',
    'c_read_block_data', 'c_set_logging_callback_and_start_logging',
    'c_transaction_ref_destroy', 'c_transaction_ref_from_str',
    'c_transaction_ref_get_locktime', 'c_transaction_ref_is_coinbase',
    'c_tx_in_witness_destroy', 'c_validation_interface_create',
    'c_validation_interface_destroy',
    'c_validation_interface_register',
    'c_validation_interface_unregister', 'kernel_ERR_INTERNAL',
    'kernel_ERR_INVALID_CONTEXT', 'kernel_ERR_INVALID_POINTER',
    'kernel_ERR_LOGGING_FAILED', 'kernel_ERR_OK',
    'kernel_ERR_UNKNOWN_OPTION', 'kernel_MAINNET', 'kernel_REGTEST',
    'kernel_SIGNET', 'kernel_TESTNET', 'kernel_error',
    'kernel_error_code', 'size_t', 'struct_BlockHash',
    'struct_ByteArray', 'struct_C_Block', 'struct_C_BlockHash',
    'struct_C_BlockHeader', 'struct_C_BlockIndex',
    'struct_C_BlockPointer', 'struct_C_BlockUndo',
    'struct_C_BlockValidationState', 'struct_C_ChainstateManager',
    'struct_C_Coin', 'struct_C_CoinOpaque',
    'struct_C_CoinsViewCursor', 'struct_C_Context',
    'struct_C_ContextOptions', 'struct_C_MempoolAcceptResult',
    'struct_C_OutPoint', 'struct_C_TransactionIn',
    'struct_C_TransactionOut', 'struct_C_TransactionRef',
    'struct_C_TxOut', 'struct_C_TxUndo', 'struct_C_ValidationEvent',
    'struct_C_ValidationInterface',
    'struct_KernelNotificationInterfaceCallbacks',
    'struct_TaskRunnerCallbacks', 'struct_TxInWitness',
    'struct_ValidationInterfaceCallbacks', 'struct_kernel_error',
    'uint32_t', 'uint64_t']
