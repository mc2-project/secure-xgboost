from numproto import ndarray_to_proto, proto_to_ndarray
import numpy as np
import ctypes

def ctypes2numpy(cptr, length, dtype):
    """Convert a ctypes pointer array to a numpy array.
    """
    NUMPY_TO_CTYPES_MAPPING = {
            np.float32: ctypes.c_float,
            np.uint32: ctypes.c_uint,
            np.uint8: ctypes.c_uint8
            }
    if dtype not in NUMPY_TO_CTYPES_MAPPING:
        raise RuntimeError('Supported types: {}'.format(NUMPY_TO_CTYPES_MAPPING.keys()))
    ctype = NUMPY_TO_CTYPES_MAPPING[dtype]
    if not isinstance(cptr, ctypes.POINTER(ctype)):
        raise RuntimeError('expected {} pointer'.format(ctype))
    res = np.zeros(length, dtype=dtype)
    if not ctypes.memmove(res.ctypes.data, cptr, length * res.strides[0]):
        raise RuntimeError('memmove failed')
    return res

def pointer_to_proto(pointer, pointer_len, nptype=np.uint8):
    """
    Convert C u_int or float pointer to proto for RPC serialization

    Parameters
    ----------
    pointer : ctypes.POINTER
    pointer_len : length of pointer
    nptype : np type to cast to
        if pointer is of type ctypes.c_uint, nptype should be np.uint32
        if pointer is of type ctypes.c_float, nptype should be np.float32
        if pointer is of type ctypes.c_uint8, nptype should be np.uint8

    Returns:
        proto : proto.NDArray
    """
    ndarray = ctypes2numpy(pointer, pointer_len, nptype)
    proto = ndarray_to_proto(ndarray)
    return proto

def proto_to_pointer(proto):
    """
    Convert a serialized NDArray to a C pointer

    Parameters
    ----------
    proto : proto.NDArray

    Returns:
        pointer :  ctypes.POINTER(ctypes.u_int8)
    """
    ndarray = proto_to_ndarray(proto)
    # FIXME make the ctype POINTER type configurable
    pointer = ndarray.ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
    return pointer
