# -*- coding: utf-8 -*-
#
# TARGET arch is: []
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


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



_libraries = {}
_libraries['libbitcoinkernel.so'] = ctypes.CDLL('/home/drgrid/bitcoin/src/.libs/libbitcoinkernel.so')


LogCallback = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_char))
TRInsert = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))
TRFlush = ctypes.CFUNCTYPE(None, ctypes.POINTER(None))
TRSize = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(None))
class struct_TaskRunnerCallbacks(Structure):
    pass

struct_TaskRunnerCallbacks._pack_ = 1 # source:False
struct_TaskRunnerCallbacks._fields_ = [
    ('user_data', ctypes.POINTER(None)),
    ('insert', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None))),
    ('flush', ctypes.CFUNCTYPE(None, ctypes.POINTER(None))),
    ('size', ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(None))),
]


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
KNBlockTip = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), C_SynchronizationState, ctypes.POINTER(None))
KNHeaderTip = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), C_SynchronizationState, ctypes.c_int64, ctypes.c_int64, ctypes.c_bool)
KNProgress = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.c_int32, ctypes.c_bool)
KNWarning = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
KNFlushError = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char))
KNFatalError = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))
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
    ('fatal_error', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char))),
]

VIBlockChecked = ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None))
class struct_ValidationInterfaceCallbacks(Structure):
    pass

struct_ValidationInterfaceCallbacks._pack_ = 1 # source:False
struct_ValidationInterfaceCallbacks._fields_ = [
    ('user_data', ctypes.POINTER(None)),
    ('block_checked', ctypes.CFUNCTYPE(None, ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(None))),
]

class struct_C_ChainstateInfo(Structure):
    pass

struct_C_ChainstateInfo._pack_ = 1 # source:False
struct_C_ChainstateInfo._fields_ = [
    ('path', ctypes.POINTER(ctypes.c_char)),
    ('reindexing', ctypes.c_int32),
    ('snapshot_active', ctypes.c_int32),
    ('active_height', ctypes.c_int32),
    ('active_ibd', ctypes.c_int32),
]

C_ChainstateInfo = struct_C_ChainstateInfo
class struct_ByteArray(Structure):
    pass

struct_ByteArray._pack_ = 1 # source:False
struct_ByteArray._fields_ = [
    ('data', ctypes.POINTER(ctypes.c_ubyte)),
    ('len', ctypes.c_uint64),
]

ByteArray = struct_ByteArray
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
c_set_logging_callback_and_start_logging = _libraries['libbitcoinkernel.so'].c_set_logging_callback_and_start_logging
c_set_logging_callback_and_start_logging.restype = None
c_set_logging_callback_and_start_logging.argtypes = [LogCallback]
c_context_new = _libraries['libbitcoinkernel.so'].c_context_new
c_context_new.restype = ctypes.POINTER(None)
c_context_new.argtypes = [struct_KernelNotificationInterfaceCallbacks, struct_TaskRunnerCallbacks]
c_context_delete = _libraries['libbitcoinkernel.so'].c_context_delete
c_context_delete.restype = None
c_context_delete.argtypes = [ctypes.POINTER(None)]
c_execute_event = _libraries['libbitcoinkernel.so'].c_execute_event
c_execute_event.restype = None
c_execute_event.argtypes = [ctypes.POINTER(None)]
c_create_validation_interface = _libraries['libbitcoinkernel.so'].c_create_validation_interface
c_create_validation_interface.restype = ctypes.POINTER(None)
c_create_validation_interface.argtypes = [struct_ValidationInterfaceCallbacks]
c_destroy_validation_interface = _libraries['libbitcoinkernel.so'].c_destroy_validation_interface
c_destroy_validation_interface.restype = None
c_destroy_validation_interface.argtypes = [ctypes.POINTER(None)]
c_register_validation_interface = _libraries['libbitcoinkernel.so'].c_register_validation_interface
c_register_validation_interface.restype = None
c_register_validation_interface.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None)]
c_unregister_validation_interface = _libraries['libbitcoinkernel.so'].c_unregister_validation_interface
c_unregister_validation_interface.restype = None
c_unregister_validation_interface.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None)]
c_chainstate_manager_create = _libraries['libbitcoinkernel.so'].c_chainstate_manager_create
c_chainstate_manager_create.restype = ctypes.POINTER(None)
c_chainstate_manager_create.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(None)]
c_get_chainstate_info = _libraries['libbitcoinkernel.so'].c_get_chainstate_info
c_get_chainstate_info.restype = C_ChainstateInfo
c_get_chainstate_info.argtypes = [ctypes.POINTER(None)]
c_chainstate_manager_validate_block = _libraries['libbitcoinkernel.so'].c_chainstate_manager_validate_block
c_chainstate_manager_validate_block.restype = ctypes.c_int32
c_chainstate_manager_validate_block.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None), ctypes.POINTER(ctypes.c_char)]
c_chainstate_manager_delete = _libraries['libbitcoinkernel.so'].c_chainstate_manager_delete
c_chainstate_manager_delete.restype = ctypes.c_int32
c_chainstate_manager_delete.argtypes = [ctypes.POINTER(None), ctypes.POINTER(None)]
c_chainstate_coins_cursor = _libraries['libbitcoinkernel.so'].c_chainstate_coins_cursor
c_chainstate_coins_cursor.restype = ctypes.POINTER(None)
c_chainstate_coins_cursor.argtypes = [ctypes.POINTER(None)]
c_coins_cursor_next = _libraries['libbitcoinkernel.so'].c_coins_cursor_next
c_coins_cursor_next.restype = None
c_coins_cursor_next.argtypes = [ctypes.POINTER(None)]
c_coins_cursor_get_key = _libraries['libbitcoinkernel.so'].c_coins_cursor_get_key
c_coins_cursor_get_key.restype = C_OutPoint
c_coins_cursor_get_key.argtypes = [ctypes.POINTER(None)]
c_coins_cursor_get_value = _libraries['libbitcoinkernel.so'].c_coins_cursor_get_value
c_coins_cursor_get_value.restype = C_Coin
c_coins_cursor_get_value.argtypes = [ctypes.POINTER(None)]
c_coins_cursor_valid = _libraries['libbitcoinkernel.so'].c_coins_cursor_valid
c_coins_cursor_valid.restype = ctypes.c_int32
c_coins_cursor_valid.argtypes = [ctypes.POINTER(None)]
c_coins_cursor_delete = _libraries['libbitcoinkernel.so'].c_coins_cursor_delete
c_coins_cursor_delete.restype = None
c_coins_cursor_delete.argtypes = [ctypes.POINTER(None)]
__all__ = \
    ['ByteArray', 'C_ChainstateInfo', 'C_Coin', 'C_OutPoint',
    'C_SynchronizationState', 'C_TxOut', 'INIT_DOWNLOAD',
    'INIT_REINDEX', 'KNBlockTip', 'KNFatalError', 'KNFlushError',
    'KNHeaderTip', 'KNProgress', 'KNWarning', 'LogCallback',
    'POST_INIT', 'TRFlush', 'TRInsert', 'TRSize', 'VIBlockChecked',
    'c_chainstate_coins_cursor', 'c_chainstate_manager_create',
    'c_chainstate_manager_delete',
    'c_chainstate_manager_validate_block', 'c_coins_cursor_delete',
    'c_coins_cursor_get_key', 'c_coins_cursor_get_value',
    'c_coins_cursor_next', 'c_coins_cursor_valid', 'c_context_delete',
    'c_context_new', 'c_create_validation_interface',
    'c_destroy_validation_interface', 'c_execute_event',
    'c_get_chainstate_info', 'c_register_validation_interface',
    'c_set_logging_callback_and_start_logging',
    'c_unregister_validation_interface', 'struct_ByteArray',
    'struct_C_ChainstateInfo', 'struct_C_Coin', 'struct_C_OutPoint',
    'struct_C_TxOut', 'struct_KernelNotificationInterfaceCallbacks',
    'struct_TaskRunnerCallbacks',
    'struct_ValidationInterfaceCallbacks']
