# coding: utf-8
# pylint: disable=too-many-arguments, too-many-branches, invalid-name
# pylint: disable=too-many-branches, too-many-lines, too-many-locals
"""Core XGBoost Library."""
from __future__ import absolute_import
import collections
# pylint: disable=no-name-in-module,import-error
try:
    from collections.abc import Mapping  # Python 3
except ImportError:
    from collections import Mapping  # Python 2
# pylint: enable=no-name-in-module,import-error
import ctypes
import os
import re
import sys
import warnings
import configparser

import grpc
from .rpc import remote_pb2
from .rpc import remote_pb2_grpc
from rpc_utils import CIPHER_IV_SIZE, CIPHER_TAG_SIZE, CIPHER_NONCE_SIZE

import numpy as np
from numproto import ndarray_to_proto, proto_to_ndarray
import scipy.sparse

from .compat import (STRING_TYPES, PY3, DataFrame, MultiIndex, py_str,
                     PANDAS_INSTALLED, DataTable)
from .libpath import find_lib_path

# c_bst_ulong corresponds to bst_ulong defined in xgboost/c_api.h
c_bst_ulong = ctypes.c_uint64



class XGBoostError(Exception):
    """Error thrown by xgboost trainer."""


class EarlyStopException(Exception):
    """Exception to signal early stopping.

    Parameters
    ----------
    best_iteration : int
        The best iteration stopped.
    """
    def __init__(self, best_iteration):
        super(EarlyStopException, self).__init__()
        self.best_iteration = best_iteration


# Callback environment used by callbacks
CallbackEnv = collections.namedtuple(
    "XGBoostCallbackEnv",
    ["model",
     "cvfolds",
     "iteration",
     "begin_iteration",
     "end_iteration",
     "rank",
     "evaluation_result_list"])


def from_pystr_to_cstr(data):
    """Convert a list of Python str to C pointer

    Parameters
    ----------
    data : list
        list of str
    """

    if not isinstance(data, list):
        raise NotImplementedError
    pointers = (ctypes.c_char_p * len(data))()
    if PY3:
        data = [bytes(d, 'utf-8') for d in data]
    else:
        data = [d.encode('utf-8') if isinstance(d, unicode) else d  # pylint: disable=undefined-variable
                for d in data]
    pointers[:] = data
    return pointers


def from_cstr_to_pystr(data, length):
    """Revert C pointer to Python str

    Parameters
    ----------
    data : ctypes pointer
        pointer to data
    length : ctypes pointer
        pointer to length of data
    """
    if PY3:
        res = []
        for i in range(length.value):
            try:
                res.append(str(data[i].decode('ascii')))
            except UnicodeDecodeError:
                res.append(str(data[i].decode('utf-8')))
    else:
        res = []
        for i in range(length.value):
            try:
                res.append(str(data[i].decode('ascii')))
            except UnicodeDecodeError:
                # pylint: disable=undefined-variable
                res.append(unicode(data[i].decode('utf-8')))
    return res


def _log_callback(msg):
    """Redirect logs from native library into Python console"""
    print("{0:s}".format(py_str(msg)))


def _get_log_callback_func():
    """Wrap log_callback() method in ctypes callback type"""
    # pylint: disable=invalid-name
    CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
    return CALLBACK(_log_callback)


def _load_lib():
    """Load xgboost Library."""
    lib_paths = find_lib_path()
    if not lib_paths:
        return None
    try:
        pathBackup = os.environ['PATH'].split(os.pathsep)
    except KeyError:
        pathBackup = []
    lib_success = False
    os_error_list = []
    for lib_path in lib_paths:
        try:
            # needed when the lib is linked with non-system-available dependencies
            os.environ['PATH'] = os.pathsep.join(pathBackup + [os.path.dirname(lib_path)])
            lib = ctypes.cdll.LoadLibrary(lib_path)
            lib_success = True
        except OSError as e:
            os_error_list.append(str(e))
            continue
        finally:
            os.environ['PATH'] = os.pathsep.join(pathBackup)
    if not lib_success:
        libname = os.path.basename(lib_paths[0])
        raise XGBoostError(
            'XGBoost Library ({}) could not be loaded.\n'.format(libname) +
            'Likely causes:\n' +
            # '  * OpenMP runtime is not installed ' +
            # '(vcomp140.dll or libgomp-1.dll for Windows, ' +
            # 'libgomp.so for UNIX-like OSes)\n' +
            '  * You are running 32-bit Python on a 64-bit OS\n' +
            'Error message(s): {}\n'.format(os_error_list))
    lib.XGBGetLastError.restype = ctypes.c_char_p
    lib.callback = _get_log_callback_func()
    if lib.XGBRegisterLogCallback(lib.callback) != 0:
        raise XGBoostError(lib.XGBGetLastError())
    return lib


# load the XGBoost library globally
_LIB = _load_lib()

# user and enclave configuration information
_CONF = {}

def _check_remote_call(ret):
    """check the return value of c api call

    this function will raise exception when error occurs.
    wrap every api call with this function

    parameters
    ----------
    ret : proto
        return value from remote api calls
    """
    channel_addr = _CONF["remote_addr"]
    if channel_addr:
        if ret.status.status != 0:
            raise XGBoostError(ret.status.exception)
        else:
            return ret

def _check_call(ret):
    """Check the return value of C API call

    This function will raise exception when error occurs.
    Wrap every API call with this function

    Parameters
    ----------
    ret : int
        return value from API calls
    """
    if ret != 0:
        raise XGBoostError(py_str(_LIB.XGBGetLastError()))

def ctypes2numpy(cptr, length, dtype):
    """Convert a ctypes pointer array to a numpy array.
    """
    NUMPY_TO_CTYPES_MAPPING = {
        np.float32: ctypes.c_float,
        np.uint32: ctypes.c_uint,
        np.uint8: ctypes.c_uint8,
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


def ctypes2buffer(cptr, length):
    """Convert ctypes pointer to buffer type."""
    if not isinstance(cptr, ctypes.POINTER(ctypes.c_char)):
        raise RuntimeError('expected char pointer')
    res = bytearray(length)
    rptr = (ctypes.c_char * length).from_buffer(res)
    if not ctypes.memmove(rptr, cptr, length):
        raise RuntimeError('memmove failed')
    return res


def c_str(string):
    """Convert a python string to cstring."""
    return ctypes.c_char_p(string.encode('utf-8'))


def c_array(ctype, values):
    """Convert a python string to c array."""
    if isinstance(values, np.ndarray) and values.dtype.itemsize == ctypes.sizeof(ctype):
        return (ctype * len(values)).from_buffer_copy(values)
    return (ctype * len(values))(*values)


def py2c_sigs(signatures, sig_lengths):
    num = len(signatures)
    c_signatures = (ctypes.POINTER(ctypes.c_uint8) * num)()
    c_lengths = (ctypes.c_size_t * num)()

    c_signatures[:] = [proto_to_pointer(signatures[i], ctypes.c_uint8) for i in range(num)]
    c_lengths[:] = [ctypes.c_size_t(sig_lengths[i]) for i in range(num)]
    return c_signatures, c_lengths


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

    Returns:
        proto : proto.NDArray
    """
    ndarray = ctypes2numpy(pointer, pointer_len, nptype)
    proto = ndarray_to_proto(ndarray)
    return proto

def proto_to_pointer(proto, ctype=ctypes.c_uint8):
    """
    Convert a serialized NDArray to a C pointer

    Parameters
    ----------
    proto : proto.NDArray

    Returns:
        pointer :  ctypes.POINTER(ctypes.u_int)
    """

    ndarray = proto_to_ndarray(proto)
    # FIXME make the ctype POINTER type configurable
    pointer = ndarray.ctypes.data_as(ctypes.POINTER(ctype))
    return pointer

# PANDAS_DTYPE_MAPPER = {'int8': 'int', 'int16': 'int', 'int32': 'int', 'int64': 'int',
#                        'uint8': 'int', 'uint16': 'int', 'uint32': 'int', 'uint64': 'int',
#                        'float16': 'float', 'float32': 'float', 'float64': 'float',
#                        'bool': 'i'}
# 
# 
# def _maybe_pandas_data(data, feature_names, feature_types):
#     """ Extract internal data from pd.DataFrame for DMatrix data """
# 
#     if not isinstance(data, DataFrame):
#         return data, feature_names, feature_types
# 
#     data_dtypes = data.dtypes
#     if not all(dtype.name in PANDAS_DTYPE_MAPPER for dtype in data_dtypes):
#         bad_fields = [data.columns[i] for i, dtype in
#                       enumerate(data_dtypes) if dtype.name not in PANDAS_DTYPE_MAPPER]
# 
#         msg = """DataFrame.dtypes for data must be int, float or bool.
#                 Did not expect the data types in fields """
#         raise ValueError(msg + ', '.join(bad_fields))
# 
#     if feature_names is None:
#         if isinstance(data.columns, MultiIndex):
#             feature_names = [
#                 ' '.join([str(x) for x in i])
#                 for i in data.columns
#             ]
#         else:
#             feature_names = data.columns.format()
# 
#     if feature_types is None:
#         feature_types = [PANDAS_DTYPE_MAPPER[dtype.name] for dtype in data_dtypes]
# 
#     data = data.values.astype('float')
# 
#     return data, feature_names, feature_types
# 
# 
# def _maybe_pandas_label(label):
#     """ Extract internal data from pd.DataFrame for DMatrix label """
# 
#     if isinstance(label, DataFrame):
#         if len(label.columns) > 1:
#             raise ValueError('DataFrame for label cannot have multiple columns')
# 
#         label_dtypes = label.dtypes
#         if not all(dtype.name in PANDAS_DTYPE_MAPPER for dtype in label_dtypes):
#             raise ValueError('DataFrame.dtypes for label must be int, float or bool')
#         label = label.values.astype('float')
#     # pd.Series can be passed to xgb as it is
# 
#     return label
# 
# 
# DT_TYPE_MAPPER = {'bool': 'bool', 'int': 'int', 'real': 'float'}
# 
# DT_TYPE_MAPPER2 = {'bool': 'i', 'int': 'int', 'real': 'float'}
# 
# 
# def _maybe_dt_data(data, feature_names, feature_types):
#     """
#     Validate feature names and types if data table
#     """
#     if not isinstance(data, DataTable):
#         return data, feature_names, feature_types
# 
#     data_types_names = tuple(lt.name for lt in data.ltypes)
#     bad_fields = [data.names[i]
#                   for i, type_name in enumerate(data_types_names)
#                   if type_name not in DT_TYPE_MAPPER]
#     if bad_fields:
#         msg = """DataFrame.types for data must be int, float or bool.
#                 Did not expect the data types in fields """
#         raise ValueError(msg + ', '.join(bad_fields))
# 
#     if feature_names is None:
#         feature_names = data.names
# 
#         # always return stypes for dt ingestion
#         if feature_types is not None:
#             raise ValueError('DataTable has own feature types, cannot pass them in')
#         feature_types = np.vectorize(DT_TYPE_MAPPER2.get)(data_types_names)
# 
#     return data, feature_names, feature_types
# 
# 
# def _maybe_dt_array(array):
#     """ Extract numpy array from single column data table """
#     if not isinstance(array, DataTable) or array is None:
#         return array
# 
#     if array.shape[1] > 1:
#         raise ValueError('DataTable for label or weight cannot have multiple columns')
# 
#     # below requires new dt version
#     # extract first column
#     array = array.to_numpy()[:, 0].astype('float')
# 
#     return array

def add_to_sig_data(arr, pos=0, data=None, data_size=0):
    if isinstance(data, str):
        ctypes.memmove(ctypes.byref(arr, pos), c_str(data), len(data))
    else:
        ctypes.memmove(ctypes.byref(arr, pos), data, data_size)
    return arr

def add_nonce_to_sig_data(arr, pos=0):
    ctypes.memmove(ctypes.byref(arr, pos), _CONF["nonce"], 12)
    ctypes.memmove(ctypes.byref(arr, pos + 12), _CONF["nonce_ctr"].to_bytes(4, 'big'), 4)
    return arr

def get_seq_num_proto():
    return remote_pb2.SequenceNumber(
                            nonce=pointer_to_proto(_CONF["nonce"], _CONF["nonce_size"].value),
                            nonce_size=_CONF["nonce_size"].value,
                            nonce_ctr=_CONF["nonce_ctr"])


class DMatrix(object):
    """Data Matrix used in Secure XGBoost.

    DMatrix is a internal data structure that used by XGBoost
    which is optimized for both memory efficiency and training speed.

    You can load a DMatrix from one ore more encrypted files at the enclave server, where
    each file is encrypted with a particular user's symmetric key.
    Each DMatrix in Secure XGBoost is thus associated with one or more data owners.
    """

    _feature_names = None  # for previous version's pickle
    _feature_types = None

    # TODO(rishabh): Enable disabled arguments: `label`, `weight`
    def __init__(self, data_dict, encrypted=True, silent=False,
            feature_names=None, feature_types=None): 
        """
        Parameters
        ----------
        data_dict : dict, {str: str}
            The keys are usernames. The values are absolute paths to the training data of the corresponding user in the cloud.
        encrypted : bool, optional
            Whether data is encrypted
        silent : bool, optional
            Whether to print messages during construction
        feature_names : list, optional
            Set names for features.
        feature_types : list, optional
            Set types for features.
        """

    # def __init__(self, data_dict, encrypted=True, label=None, missing=None,
    #              weight=None, silent=False,
    #              feature_names=None, feature_types=None,
    #              nthread=None): 
    #     """
    #     Load a DMatrix from encrypted files at the enclave server, where
    #     each file is encrypted with a particular user's symmetric key.
    # 
    #     Parameters
    #     ----------
    #     data_dict : dictionary 
    #         Keys: Usernames
    #         Values: Path to training data of corresponding user
    #     label : list or numpy 1-D array, optional
    #         Label of the training data.
    #     missing : float, optional
    #         Value in the data which needs to be present as a missing value. If
    #         None, defaults to np.nan.
    #     weight : list or numpy 1-D array , optional
    #         Weight for each instance.
    # 
    #         .. note:: For ranking task, weights are per-group.
    # 
    #             In ranking task, one weight is assigned to each group (not each data
    #             point). This is because we only care about the relative ordering of
    #             data points within each group, so it doesn't make sense to assign
    #             weights to individual data points.
    # 
    #     silent : boolean, optional
    #         Whether print messages during construction
    #     feature_names : list, optional
    #         Set names for features.
    #     feature_types : list, optional
    #         Set types for features.
    #     nthread : integer, optional
    #         Number of threads to use for loading data from numpy array. If -1,
    #         uses maximum threads available on the system.
    #     """
        usernames, data = [], []

        for user, path in data_dict.items():
            usernames.append(user)
            data.append("/home/mc2/skycamp/mc2/tutorial/central/" + path)
        # Sort by username
        usernames, data = (list(x) for x in zip(*sorted(zip(usernames, data), key=lambda pair: pair[0])))

        # force into void_p, mac need to pass things in as void_p
        # if data is None:
        #     self.handle = None
        # 
        #     if feature_names is not None:
        #         self._feature_names = feature_names
        #     if feature_types is not None:
        #         self._feature_types = feature_types
        #     return

        # data, feature_names, feature_types = _maybe_pandas_data(data,
        #                                                         feature_names,
        #                                                         feature_types)
        #
        # data, feature_names, feature_types = _maybe_dt_data(data,
        #                                                     feature_names,
        #                                                     feature_types)
        # label = _maybe_pandas_label(label)
        # label = _maybe_dt_array(label)
        # weight = _maybe_dt_array(weight)

        # if isinstance(data, list):
        #     warnings.warn('Initializing DMatrix from List is deprecated.',
        #                   DeprecationWarning)

        if isinstance(data, list):

            # Normalize file paths (otherwise signatures might differ)
            data = [os.path.normpath(path) for path in data]

            handle = ctypes.c_char_p()
            if encrypted:

                args = "XGDMatrixCreateFromEncryptedFile"
                for username, filename in zip(usernames, data):
                    args = args + " username {} filename {}".format(username, filename)
                args = args + " silent {}".format(int(silent))
                sig, sig_len = create_client_signature(args)

                out_sig = ctypes.POINTER(ctypes.c_uint8)()
                out_sig_length = c_bst_ulong()

                channel_addr = _CONF["remote_addr"]
                if channel_addr:
                    with grpc.insecure_channel(channel_addr) as channel:
                        stub = remote_pb2_grpc.RemoteStub(channel)
                        dmatrix_attrs = remote_pb2.DMatrixAttrs(
                            filenames=data,
                            usernames=usernames,
                            silent=silent)
                        seq_num = get_seq_num_proto() 
                        response = _check_remote_call(stub.rpc_XGDMatrixCreateFromEncryptedFile(remote_pb2.DMatrixAttrsRequest(params=dmatrix_attrs,
                                                                                                                                seq_num=seq_num,
                                                                                                                                username=_CONF["current_user"],
                                                                                                                                signature=sig,
                                                                                                                                sig_len=sig_len)))
                        handle = c_str(response.name)
                        out_sig = proto_to_pointer(response.signature)
                        out_sig_length = c_bst_ulong(response.sig_len)
                else:
                    c_signatures, c_lengths = py2c_sigs([sig], [sig_len])
                    signers = from_pystr_to_cstr([_CONF["current_user"]])

                    filenames = from_pystr_to_cstr(data)
                    usrs = from_pystr_to_cstr(usernames)
                    nonce = _CONF["nonce"]
                    nonce_size = _CONF["nonce_size"]
                    nonce_ctr = _CONF["nonce_ctr"]
                    _check_call(_LIB.XGDMatrixCreateFromEncryptedFile(filenames,
                        usrs,
                        c_bst_ulong(len(data)),
                        ctypes.c_int(silent),
                        nonce,
                        nonce_size,
                        ctypes.c_uint32(nonce_ctr),
                        ctypes.byref(handle),
                        ctypes.byref(out_sig),
                        ctypes.byref(out_sig_length),
                        signers,
                        c_signatures,
                        c_lengths))

                args = "handle {}".format(handle.value.decode('utf-8')) 
                verify_enclave_signature(args, len(args), out_sig, out_sig_length)

            else:
                raise NotImplementedError("Loading from unencrypted files not supported.")
                # FIXME implement RPC for this
                # FIXME handle multiparty case
                # _check_call(_LIB.XGDMatrixCreateFromFile(c_str(data),
                #     ctypes.c_int(silent),
                #     ctypes.byref(handle)))
            self.handle = handle
        # elif isinstance(data, scipy.sparse.csr_matrix):
        #     self._init_from_csr(data)
        # elif isinstance(data, scipy.sparse.csc_matrix):
        #     self._init_from_csc(data)
        # elif isinstance(data, np.ndarray):
        #     self._init_from_npy2d(data, missing, nthread)
        # elif isinstance(data, DataTable):
        #     self._init_from_dt(data, nthread)
        # else:
        #     try:
        #         csr = scipy.sparse.csr_matrix(data)
        #         self._init_from_csr(csr)
        #     except:
        #         raise TypeError('can not initialize DMatrix from'
        #                         ' {}'.format(type(data).__name__))

        # TODO(rishabh): Enable this
        # if label is not None:
        #     if isinstance(label, np.ndarray):
        #         self.set_label_npy2d(label)
        #     else:
        #         self.set_label(label)
        # if weight is not None:
        #     if isinstance(weight, np.ndarray):
        #         self.set_weight_npy2d(weight)
        #     else:
        #         self.set_weight(weight)

        self.feature_names = feature_names
        self.feature_types = feature_types

        print("Loaded data")

    # def _init_from_csr(self, csr):
    #     """
    #     Initialize data from a CSR matrix.
    #     """
    #     if len(csr.indices) != len(csr.data):
    #         raise ValueError('length mismatch: {} vs {}'.format(len(csr.indices), len(csr.data)))
    #     handle = ctypes.c_char_p()
    #     _check_call(_LIB.XGDMatrixCreateFromCSREx(c_array(ctypes.c_size_t, csr.indptr),
    #                                               c_array(ctypes.c_uint, csr.indices),
    #                                               c_array(ctypes.c_float, csr.data),
    #                                               ctypes.c_size_t(len(csr.indptr)),
    #                                               ctypes.c_size_t(len(csr.data)),
    #                                               ctypes.c_size_t(csr.shape[1]),
    #                                               ctypes.byref(handle)))
    #     self.handle = handle

    # def _init_from_csc(self, csc):
    #     """
    #     Initialize data from a CSC matrix.
    #     """
    #     if len(csc.indices) != len(csc.data):
    #         raise ValueError('length mismatch: {} vs {}'.format(len(csc.indices), len(csc.data)))
    #     handle = ctypes.c_char_p()
    #     _check_call(_LIB.XGDMatrixCreateFromCSCEx(c_array(ctypes.c_size_t, csc.indptr),
    #                                               c_array(ctypes.c_uint, csc.indices),
    #                                               c_array(ctypes.c_float, csc.data),
    #                                               ctypes.c_size_t(len(csc.indptr)),
    #                                               ctypes.c_size_t(len(csc.data)),
    #                                               ctypes.c_size_t(csc.shape[0]),
    #                                               ctypes.byref(handle)))
    #     self.handle = handle

    # def _init_from_npy2d(self, mat, missing, nthread):
    #     """
    #     Initialize data from a 2-D numpy matrix.
    # 
    #     If ``mat`` does not have ``order='C'`` (aka row-major) or is not contiguous,
    #     a temporary copy will be made.
    # 
    #     If ``mat`` does not have ``dtype=numpy.float32``, a temporary copy will be made.
    # 
    #     So there could be as many as two temporary data copies; be mindful of input layout
    #     and type if memory use is a concern.
    #     """
    #     if len(mat.shape) != 2:
    #         raise ValueError('Input numpy.ndarray must be 2 dimensional')
    #     # flatten the array by rows and ensure it is float32.
    #     # we try to avoid data copies if possible (reshape returns a view when possible
    #     # and we explicitly tell np.array to try and avoid copying)
    #     data = np.array(mat.reshape(mat.size), copy=False, dtype=np.float32)
    #     handle = ctypes.c_char_p()
    #     missing = missing if missing is not None else np.nan
    #     if nthread is None:
    #         _check_call(_LIB.XGDMatrixCreateFromMat(
    #             data.ctypes.data_as(ctypes.POINTER(ctypes.c_float)),
    #             c_bst_ulong(mat.shape[0]),
    #             c_bst_ulong(mat.shape[1]),
    #             ctypes.c_float(missing),
    #             ctypes.byref(handle)))
    #     else:
    #         _check_call(_LIB.XGDMatrixCreateFromMat_omp(
    #             data.ctypes.data_as(ctypes.POINTER(ctypes.c_float)),
    #             c_bst_ulong(mat.shape[0]),
    #             c_bst_ulong(mat.shape[1]),
    #             ctypes.c_float(missing),
    #             ctypes.byref(handle),
    #             nthread))
    #     self.handle = handle

    # def _init_from_dt(self, data, nthread):
    #     """
    #     Initialize data from a datatable Frame.
    #     """
    #     ptrs = (ctypes.c_char_p * data.ncols)()
    #     if hasattr(data, "internal") and hasattr(data.internal, "column"):
    #         # datatable>0.8.0
    #         for icol in range(data.ncols):
    #             col = data.internal.column(icol)
    #             ptr = col.data_pointer
    #             ptrs[icol] = ctypes.c_char_p(ptr)
    #     else:
    #         # datatable<=0.8.0
    #         from datatable.internal import frame_column_data_r  # pylint: disable=no-name-in-module,import-error
    #         for icol in range(data.ncols):
    #             ptrs[icol] = frame_column_data_r(data, icol)
    # 
    #     # always return stypes for dt ingestion
    #     feature_type_strings = (ctypes.c_char_p * data.ncols)()
    #     for icol in range(data.ncols):
    #         feature_type_strings[icol] = ctypes.c_char_p(data.stypes[icol].name.encode('utf-8'))
    # 
    #     handle = ctypes.c_char_p()
    #     _check_call(_LIB.XGDMatrixCreateFromDT(
    #         ptrs, feature_type_strings,
    #         c_bst_ulong(data.shape[0]),
    #         c_bst_ulong(data.shape[1]),
    #         ctypes.byref(handle),
    #         nthread))
    #     self.handle = handle

    def __del__(self):
        if hasattr(self, "handle") and self.handle is not None:
            # FIXME free matrix after use using RPC
            # _check_call(_LIB.XGDMatrixFree(self.handle))
            self.handle = None

    # TODO(rishabh): Enable this API with encryption
    # def get_float_info(self, field):
    #     """Get float property from the DMatrix.
    # 
    #     Parameters
    #     ----------
    #     field: str
    #         The field name of the information
    # 
    #     Returns
    #     -------
    #     info : array
    #         a numpy array of float information of the data
    #     """
    #     length = c_bst_ulong()
    #     ret = ctypes.POINTER(ctypes.c_float)()
    #     _check_call(_LIB.XGDMatrixGetFloatInfo(self.handle,
    #                                            c_str(field),
    #                                            ctypes.byref(length),
    #                                            ctypes.byref(ret)))
    # 
    #     return ctypes2numpy(ret, length.value, np.float32)

    # TODO(rishabh): Enable this API with encryption
    # def get_uint_info(self, field):
    #     """Get unsigned integer property from the DMatrix.
    # 
    #     Parameters
    #     ----------
    #     field: str
    #         The field name of the information
    # 
    #     Returns
    #     -------
    #     info : array
    #         a numpy array of unsigned integer information of the data
    #     """
    #     length = c_bst_ulong()
    #     ret = ctypes.POINTER(ctypes.c_uint)()
    #     _check_call(_LIB.XGDMatrixGetUIntInfo(self.handle,
    #                                           c_str(field),
    #                                           ctypes.byref(length),
    #                                           ctypes.byref(ret)))
    #     return ctypes2numpy(ret, length.value, np.uint32)

    # TODO(rishabh): Enable this API with encryption
    # def set_float_info(self, field, data):
    #     """Set float type property into the DMatrix.
    # 
    #     Parameters
    #     ----------
    #     field: str
    #         The field name of the information
    # 
    #     data: numpy array
    #         The array of data to be set
    #     """
    #     if getattr(data, 'base', None) is not None and \
    #        data.base is not None and isinstance(data, np.ndarray) \
    #        and isinstance(data.base, np.ndarray) and (not data.flags.c_contiguous):
    #         self.set_float_info_npy2d(field, data)
    #         return
    #     c_data = c_array(ctypes.c_float, data)
    #     _check_call(_LIB.XGDMatrixSetFloatInfo(self.handle,
    #                                            c_str(field),
    #                                            c_data,
    #                                            c_bst_ulong(len(data))))

    # TODO(rishabh): Enable this API with encryption
    # def set_float_info_npy2d(self, field, data):
    #     """Set float type property into the DMatrix
    #        for numpy 2d array input
    # 
    #     Parameters
    #     ----------
    #     field: str
    #         The field name of the information
    # 
    #     data: numpy array
    #         The array of data to be set
    #     """
    #     if getattr(data, 'base', None) is not None and \
    #        data.base is not None and isinstance(data, np.ndarray) \
    #        and isinstance(data.base, np.ndarray) and (not data.flags.c_contiguous):
    #         warnings.warn("Use subset (sliced data) of np.ndarray is not recommended " +
    #                       "because it will generate extra copies and increase memory consumption")
    #         data = np.array(data, copy=True, dtype=np.float32)
    #     else:
    #         data = np.array(data, copy=False, dtype=np.float32)
    #     c_data = data.ctypes.data_as(ctypes.POINTER(ctypes.c_float))
    #     _check_call(_LIB.XGDMatrixSetFloatInfo(self.handle,
    #                                            c_str(field),
    #                                            c_data,
    #                                            c_bst_ulong(len(data))))

    # TODO(rishabh): Enable this API with encryption
    # def set_uint_info(self, field, data):
    #     """Set uint type property into the DMatrix.
    # 
    #     Parameters
    #     ----------
    #     field: str
    #         The field name of the information
    # 
    #     data: numpy array
    #         The array of data to be set
    #     """
    #     if getattr(data, 'base', None) is not None and \
    #        data.base is not None and isinstance(data, np.ndarray) \
    #        and isinstance(data.base, np.ndarray) and (not data.flags.c_contiguous):
    #         warnings.warn("Use subset (sliced data) of np.ndarray is not recommended " +
    #                       "because it will generate extra copies and increase memory consumption")
    #         data = np.array(data, copy=True, dtype=ctypes.c_uint)
    #     else:
    #         data = np.array(data, copy=False, dtype=ctypes.c_uint)
    #     _check_call(_LIB.XGDMatrixSetUIntInfo(self.handle,
    #                                           c_str(field),
    #                                           c_array(ctypes.c_uint, data),
    #                                           c_bst_ulong(len(data))))

    # def save_binary(self, fname, silent=True):
    #     """Save DMatrix to an XGBoost buffer.  Saved binary can be later loaded
    #     by providing the path to :py:func:`xgboost.DMatrix` as input.
    # 
    #     Parameters
    #     ----------
    #     fname : str
    #         Name of the output buffer file.
    #     silent : bool (optional; default: True)
    #         If set, the output is suppressed.
    #     """
    #     _check_call(_LIB.XGDMatrixSaveBinary(self.handle,
    #                                          c_str(fname),
    #                                          ctypes.c_int(silent)))

    # TODO(rishabh): Enable this API with encryption
    # def set_label(self, label):
    #     """Set label of dmatrix
    # 
    #     Parameters
    #     ----------
    #     label: array like
    #         The label information to be set into DMatrix
    #     """
    #     self.set_float_info('label', label)

    # TODO(rishabh): Enable this API with encryption
    # def set_label_npy2d(self, label):
    #     """Set label of dmatrix
    # 
    #     Parameters
    #     ----------
    #     label: array like
    #         The label information to be set into DMatrix
    #         from numpy 2D array
    #     """
    #     self.set_float_info_npy2d('label', label)

    # TODO(rishabh): Enable this API with encryption
    # def set_weight(self, weight):
    #     """ Set weight of each instance.
    # 
    #     Parameters
    #     ----------
    #     weight : array like
    #         Weight for each data point
    # 
    #         .. note:: For ranking task, weights are per-group.
    # 
    #             In ranking task, one weight is assigned to each group (not each data
    #             point). This is because we only care about the relative ordering of
    #             data points within each group, so it doesn't make sense to assign
    #             weights to individual data points.
    #     """
    #     self.set_float_info('weight', weight)

    # TODO(rishabh): Enable this API with encryption
    # def set_weight_npy2d(self, weight):
    #     """ Set weight of each instance
    #         for numpy 2D array
    # 
    #     Parameters
    #     ----------
    #     weight : array like
    #         Weight for each data point in numpy 2D array
    # 
    #         .. note:: For ranking task, weights are per-group.
    # 
    #             In ranking task, one weight is assigned to each group (not each data
    #             point). This is because we only care about the relative ordering of
    #             data points within each group, so it doesn't make sense to assign
    #             weights to individual data points.
    #     """
    #     self.set_float_info_npy2d('weight', weight)

    # TODO(rishabh): Enable this API with encryption
    # def set_base_margin(self, margin):
    #     """ Set base margin of booster to start from.
    # 
    #     This can be used to specify a prediction value of
    #     existing model to be base_margin
    #     However, remember margin is needed, instead of transformed prediction
    #     e.g. for logistic regression: need to put in value before logistic transformation
    #     see also example/demo.py
    # 
    #     Parameters
    #     ----------
    #     margin: array like
    #         Prediction margin of each datapoint
    #     """
    #     self.set_float_info('base_margin', margin)

    # TODO(rishabh): Enable this API with encryption
    # def set_group(self, group):
    #     """Set group size of DMatrix (used for ranking).
    # 
    #     Parameters
    #     ----------
    #     group : array like
    #         Group size of each group
    #     """
    #     _check_call(_LIB.XGDMatrixSetGroup(self.handle,
    #                                        c_array(ctypes.c_uint, group),
    #                                        c_bst_ulong(len(group))))

    # TODO(rishabh): Enable this API with encryption
    # def get_label(self):
    #     """Get the label of the DMatrix.
    # 
    #     Returns
    #     -------
    #     label : array
    #     """
    #     return self.get_float_info('label')

    # TODO(rishabh): Enable this API with encryption
    # def get_weight(self):
    #     """Get the weight of the DMatrix.
    # 
    #     Returns
    #     -------
    #     weight : array
    #     """
    #     return self.get_float_info('weight')

    # TODO(rishabh): Enable this API with encryption
    # def get_base_margin(self):
    #     """Get the base margin of the DMatrix.
    # 
    #     Returns
    #     -------
    #     base_margin : float
    #     """
    #     return self.get_float_info('base_margin')

    def num_row(self):
        """Get the number of rows in the DMatrix.

        Returns
        -------
        number of rows : int
        """
        channel_addr = _CONF["remote_addr"]
        args = "XGDMatrixNumRow " + self.handle.value.decode('utf-8')
        sig, sig_len = create_client_signature(args)

        ret = c_bst_ulong()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_length = c_bst_ulong()

        if channel_addr:
            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                name_proto = remote_pb2.NameRequestParams(name=self.handle.value)
                seq_num = get_seq_num_proto() 
                response = _check_remote_call(stub.rpc_XGDMatrixNumRow(remote_pb2.NumRowRequest(params=name_proto, seq_num=seq_num, username=_CONF["current_user"],
                                                                                                signature=sig, sig_len=sig_len)))
                out_sig = proto_to_pointer(response.signature)
                out_sig_length = c_bst_ulong(response.sig_len)
                ret = response.value
        else:
            c_signatures, c_lengths = py2c_sigs([sig], [sig_len])
            signers = from_pystr_to_cstr([_CONF["current_user"]])
            _check_call(_LIB.XGDMatrixNumRow(self.handle,
                                             _CONF["nonce"],
                                             _CONF["nonce_size"],
                                             ctypes.c_uint32(_CONF["nonce_ctr"]),
                                             ctypes.byref(ret),
                                             ctypes.byref(out_sig),
                                             ctypes.byref(out_sig_length),
                                             signers,
                                             c_signatures,
                                             c_lengths))
            ret = ret.value

        args = "{}".format(ret) 
        verify_enclave_signature(args, len(args), out_sig, out_sig_length)

        return ret

    def num_col(self):
        """Get the number of columns (features) in the DMatrix.

        Returns
        -------
        number of columns : int
        """
        args = "XGDMatrixNumCol " + self.handle.value.decode('utf-8')
        sig, sig_len = create_client_signature(args)

        ret = c_bst_ulong()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_length = c_bst_ulong()

        channel_addr = _CONF["remote_addr"]
        if channel_addr:
            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                name_proto = remote_pb2.NameRequestParams(name=self.handle.value)
                seq_num = get_seq_num_proto() 
                response = _check_remote_call(stub.rpc_XGDMatrixNumCol(remote_pb2.NumColRequest(params=name_proto, seq_num=seq_num, username=_CONF["current_user"],
                                                                                                signature=sig, sig_len=sig_len)))
                out_sig = proto_to_pointer(response.signature)
                out_sig_length = c_bst_ulong(response.sig_len)
                ret = response.value
        else:
            c_signatures, c_lengths = py2c_sigs([sig], [sig_len])
            signers = from_pystr_to_cstr([_CONF["current_user"]])
            ret = c_bst_ulong()
            _check_call(_LIB.XGDMatrixNumCol(self.handle,
                                             _CONF["nonce"],
                                             _CONF["nonce_size"],
                                             ctypes.c_uint32(_CONF["nonce_ctr"]),
                                             ctypes.byref(ret),
                                             ctypes.byref(out_sig),
                                             ctypes.byref(out_sig_length),
                                             signers,
                                             c_signatures,
                                             c_lengths))
            ret = ret.value

        args = "{}".format(ret) 
        verify_enclave_signature(args, len(args), out_sig, out_sig_length)
        return ret

    # def slice(self, rindex):
    #     """Slice the DMatrix and return a new DMatrix that only contains `rindex`.
    # 
    #     Parameters
    #     ----------
    #     rindex : list
    #         List of indices to be selected.
    # 
    #     Returns
    #     -------
    #     res : DMatrix
    #         A new DMatrix containing only selected indices.
    #     """
    #     res = DMatrix(None, feature_names=self.feature_names,
    #                   feature_types=self.feature_types)
    #     res.handle = ctypes.c_char_p()
    #     _check_call(_LIB.XGDMatrixSliceDMatrix(self.handle,
    #                                            c_array(ctypes.c_int, rindex),
    #                                            c_bst_ulong(len(rindex)),
    #                                            ctypes.byref(res.handle)))
    #     return res

    @property
    def feature_names(self):
        """Get feature names (column labels).

        Returns
        -------
        feature_names : list or None
        """
        if self._feature_names is None:
            self._feature_names = ['f{0}'.format(i) for i in range(self.num_col())]
        return self._feature_names

    @property
    def feature_types(self):
        """Get feature types (column types).

        Returns
        -------
        feature_types : list or None
        """
        return self._feature_types

    @feature_names.setter
    def feature_names(self, feature_names):
        """Set feature names (column labels).

        Parameters
        ----------
        feature_names : list or None
            Labels for features. None will reset existing feature names
        """
        if feature_names is not None:
            # validate feature name
            try:
                if not isinstance(feature_names, str):
                    feature_names = [n for n in iter(feature_names)]
                else:
                    feature_names = [feature_names]
            except TypeError:
                feature_names = [feature_names]

            if len(feature_names) != len(set(feature_names)):
                raise ValueError('feature_names must be unique')
            if len(feature_names) != self.num_col():
                msg = 'feature_names must have the same length as data'
                raise ValueError(msg)
            # prohibit to use symbols may affect to parse. e.g. []<
            if not all(isinstance(f, STRING_TYPES) and
                       not any(x in f for x in set(('[', ']', '<')))
                       for f in feature_names):
                raise ValueError('feature_names may not contain [, ] or <')
        else:
            # reset feature_types also
            self.feature_types = None
        self._feature_names = feature_names

    @feature_types.setter
    def feature_types(self, feature_types):
        """Set feature types (column types).

        This is for displaying the results and unrelated
        to the learning process.

        Parameters
        ----------
        feature_types : list or None
            Labels for features. None will reset existing feature names
        """
        if feature_types is not None:
            if self._feature_names is None:
                msg = 'Unable to set feature types before setting names'
                raise ValueError(msg)

            if isinstance(feature_types, STRING_TYPES):
                # single string will be applied to all columns
                feature_types = [feature_types] * self.num_col()

            try:
                if not isinstance(feature_types, str):
                    feature_types = [n for n in iter(feature_types)]
                else:
                    feature_types = [feature_types]
            except TypeError:
                feature_types = [feature_types]

            if len(feature_types) != self.num_col():
                msg = 'feature_types must have the same length as data'
                raise ValueError(msg)

            valid = ('int', 'float', 'i', 'q')
            if not all(isinstance(f, STRING_TYPES) and f in valid
                       for f in feature_types):
                raise ValueError('All feature_names must be {int, float, i, q}')
        self._feature_types = feature_types


class Booster(object):
    # pylint: disable=too-many-public-methods
    """A Booster of Secure XGBoost.

    Booster is the model of Secure XGBoost, that contains low level routines for
    training, prediction and evaluation.
    """

    feature_names = None

    def __init__(self, params=None, cache=(), model_file=None):
        # pylint: disable=invalid-name
        """
        Parameters
        ----------
        params : dict
            Parameters for boosters.
        cache : list
            List of cache items.
        model_file : str
            Path to the model file.
        """
        for d in cache:
            if not isinstance(d, DMatrix):
                raise TypeError('invalid cache item: {}'.format(type(d).__name__))
            self._validate_features(d)

        args = "XGBoosterCreate"
        sig, sig_len = create_client_signature(args)

        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_length = c_bst_ulong()

        channel_addr = _CONF["remote_addr"]
        if channel_addr:
            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                cache_handles = [d.handle.value for d in cache]
                booster_attrs = remote_pb2.BoosterAttrs(
                    cache=cache_handles,
                    length=len(cache))
                seq_num = get_seq_num_proto()
                response = _check_remote_call(stub.rpc_XGBoosterCreate(remote_pb2.BoosterAttrsRequest(params=booster_attrs, seq_num=seq_num, username=_CONF["current_user"],
                                                                                                      signature=sig, sig_len=sig_len)))
            self.handle = c_str(response.name)
            out_sig = proto_to_pointer(response.signature)
            out_sig_length = c_bst_ulong(response.sig_len)
        else:
            c_signatures, c_lengths = py2c_sigs([sig], [sig_len])
            signers = from_pystr_to_cstr([_CONF["current_user"]])
            dmats = c_array(ctypes.c_char_p, [d.handle for d in cache])
            self.handle = ctypes.c_char_p()
            _check_call(_LIB.XGBoosterCreate(dmats, c_bst_ulong(len(cache)),
                                             _CONF["nonce"], _CONF["nonce_size"], ctypes.c_uint32(_CONF["nonce_ctr"]),
                                             ctypes.byref(self.handle),
                                             ctypes.byref(out_sig),
                                             ctypes.byref(out_sig_length),
                                             signers,
                                             c_signatures,
                                             c_lengths))

        args = "handle {}".format(self.handle.value.decode('utf-8')) 
        verify_enclave_signature(args, len(args), out_sig, out_sig_length)

        self.set_param({'seed': 0})
        self.set_param(params or {})
        if (params is not None) and ('booster' in params):
            self.booster = params['booster']
        else:
            self.booster = 'gbtree'
        if model_file is not None:
            self.load_model(model_file)

    def __del__(self):
        if hasattr(self, "handle") and self.handle is not None:
            # FIXME free booster after use using RPC
            # _check_call(_LIB.XGBoosterFree(self.handle))
            self.handle = None

    # TODO(rishabh): Add pickling support (two methods below)
    # def __getstate__(self):
    #     # can't pickle ctypes pointers
    #     # put model content in bytearray
    #     this = self.__dict__.copy()
    #     handle = this['handle']
    #     if handle is not None:
    #         raw = self.save_raw()
    #         this["handle"] = raw
    #     return this
    # 
    # def __setstate__(self, state):
    #     # reconstruct handle from raw data
    #     handle = state['handle']
    #     if handle is not None:
    #         buf = handle
    #         dmats = c_array(ctypes.c_char_p, [])
    #         handle = ctypes.c_char_p()
    #         _check_call(_LIB.XGBoosterCreate(dmats, c_bst_ulong(0), ctypes.byref(handle)))
    #         length = c_bst_ulong(len(buf))
    #         ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
    #         _check_call(_LIB.XGBoosterLoadModelFromBuffer(handle, ptr, length))
    #         state['handle'] = handle
    #     self.__dict__.update(state)
    #     self.set_param({'seed': 0})

    def __copy__(self):
        return self.__deepcopy__(None)

    def __deepcopy__(self, _):
        return Booster(model_file=self.save_raw())

    def copy(self):
        """Copy the booster object.

        Returns
        -------
        booster: `Booster`
            a copied booster model
        """
        return self.__copy__()

    # def load_rabit_checkpoint(self):
    #     """Initialize the model by load from rabit checkpoint.
    # 
    #     Returns
    #     -------
    #     version: integer
    #         The version number of the model.
    #     """
    #     version = ctypes.c_int()
    #     _check_call(_LIB.XGBoosterLoadRabitCheckpoint(
    #         self.handle, ctypes.byref(version)))
    #     return version.value
    #  
    # def save_rabit_checkpoint(self):
    #     """Save the current booster to rabit checkpoint."""
    #     _check_call(_LIB.XGBoosterSaveRabitCheckpoint(self.handle))

    # TODO(rishabh): Enable these functions
    # def attr(self, key):
    #     """Get attribute string from the Booster.
    # 
    #     Parameters
    #     ----------
    #     key : str
    #         The key to get attribute from.
    # 
    #     Returns
    #     -------
    #     value : str
    #         The attribute value of the key, returns None if attribute do not exist.
    #     """
    #     ret = ctypes.c_char_p()
    #     success = ctypes.c_int()
    #     _check_call(_LIB.XGBoosterGetAttr(
    #         self.handle, c_str(key), ctypes.byref(ret), ctypes.byref(success)))
    #     if success.value != 0:
    #         return py_str(ret.value)
    #     return None

    # def attributes(self):
    #     """Get attributes stored in the Booster as a dictionary.
    # 
    #     Returns
    #     -------
    #     result : dictionary of  attribute_name: attribute_value pairs of strings.
    #         Returns an empty dict if there's no attributes.
    #     """
    #     # FIXME: this function most likely has a bug
    #     length = c_bst_ulong()
    #     sarr = ctypes.POINTER(ctypes.c_char_p)()
    #     _check_call(_LIB.XGBoosterGetAttrNames(self.handle,
    #                                            ctypes.byref(length),
    #                                            ctypes.byref(sarr)))
    #     attr_names = from_cstr_to_pystr(sarr, length)
    #     return {n: self.attr(n) for n in attr_names}
    # 
    # def set_attr(self, **kwargs):
    #     """Set the attribute of the Booster.
    # 
    #     Parameters
    #     ----------
    #     **kwargs
    #         The attributes to set. Setting a value to None deletes an attribute.
    #     """
    #     for key, value in kwargs.items():
    #         if value is not None:
    #             if not isinstance(value, STRING_TYPES):
    #                 raise ValueError("Set Attr only accepts string values")
    #             value = c_str(str(value))
    #         _check_call(_LIB.XGBoosterSetAttr(
    #             self.handle, c_str(key), value))

    def set_param(self, params, value=None):
        """Set parameters into the Booster.

        Parameters
        ----------
        params: dict/list/str
           list of key,value pairs, dict of key to value or simply str key
        value: optional
           value of the specified parameter, when params is str key
        """
        if isinstance(params, Mapping):
            params = params.items()
        elif isinstance(params, STRING_TYPES) and value is not None:
            params = [(params, value)]

        if "current_user" in _CONF:
            user = _CONF["current_user"]
        else:
            raise ValueError("Please set your user with init_user() function")

        for key, val in params:
            args = "XGBoosterSetParam " + self.handle.value.decode('utf-8') + " " + key + "," + str(val)
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            if channel_addr:
                with grpc.insecure_channel(channel_addr) as channel:
                    stub = remote_pb2_grpc.RemoteStub(channel)
                    booster_param = remote_pb2.BoosterParam(booster_handle=self.handle.value, key=key, value=str(val)) 
                    seq_num = get_seq_num_proto() 
                    response = _check_remote_call(stub.rpc_XGBoosterSetParam(remote_pb2.BoosterParamRequest(params=booster_param, seq_num=seq_num, username=_CONF["current_user"],
                                                                                                            signature=sig, sig_len=sig_len)))
                    out_sig = proto_to_pointer(response.signature)
                    out_sig_length = c_bst_ulong(response.sig_len)
            else:
                c_signatures, c_sig_lengths = py2c_sigs([sig], [sig_len])
                signers = from_pystr_to_cstr([_CONF["current_user"]])
                _check_call(_LIB.XGBoosterSetParam(self.handle, c_str(key), c_str(str(val)), 
                                                    _CONF["nonce"], _CONF["nonce_size"], ctypes.c_uint32(_CONF["nonce_ctr"]), 
                                                    ctypes.byref(out_sig),
                                                    ctypes.byref(out_sig_length),
                                                    signers, c_signatures, c_sig_lengths))

            verify_enclave_signature("", 0, out_sig, out_sig_length)

    def update(self, dtrain, iteration, fobj=None):
        """Update for one iteration, with objective function calculated
        internally.  This function should not be called directly by users.

        Parameters
        ----------
        dtrain : DMatrix
            Training data.
        iteration : int
            Current iteration number.
        fobj : function
            Customized objective function.

        """
        if not isinstance(dtrain, DMatrix):
            raise TypeError('invalid training matrix: {}'.format(type(dtrain).__name__))
        self._validate_features(dtrain)
        
        if fobj is None:
            args = "XGBoosterUpdateOneIter booster_handle {} iteration {} train_data_handle {}".format(self.handle.value.decode('utf-8'), int(iteration), dtrain.handle.value.decode('utf-8'))
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            if channel_addr:
                with grpc.insecure_channel(channel_addr) as channel:
                    stub = remote_pb2_grpc.RemoteStub(channel)
                    booster_update_params = remote_pb2.BoosterUpdateParams(booster_handle=self.handle.value,
                                                                           dtrain_handle=dtrain.handle.value,
                                                                           iteration=iteration)
                    seq_num = get_seq_num_proto() 
                    response = _check_remote_call(stub.rpc_XGBoosterUpdateOneIter(remote_pb2.BoosterUpdateParamsRequest(params=booster_update_params, seq_num=seq_num, username=_CONF["current_user"],
                                                                                                                        signature=sig, sig_len=sig_len)))
                    out_sig = proto_to_pointer(response.signature)
                    out_sig_length = c_bst_ulong(response.sig_len)
            else:
                c_signatures, c_lengths = py2c_sigs([sig], [sig_len])
                signers = from_pystr_to_cstr([_CONF["current_user"]])
                _check_call(_LIB.XGBoosterUpdateOneIter(self.handle, ctypes.c_int(iteration), dtrain.handle, 
                                                        _CONF["nonce"], _CONF["nonce_size"], ctypes.c_uint32(_CONF["nonce_ctr"]),
                                                        
                                                        ctypes.byref(out_sig),
                                                        ctypes.byref(out_sig_length),
                                                        signers, c_signatures, c_lengths))

            verify_enclave_signature("", 0, out_sig, out_sig_length)
        else:
            raise NotImplementedError("Custom objective functions not supported")
            # TODO(rishabh): We do not support custom objectives currently
            # pred = self.predict(dtrain)
            # grad, hess = fobj(pred, dtrain)
            # self.boost(dtrain, grad, hess)

    # def boost(self, dtrain, grad, hess):
    #     """Boost the booster for one iteration, with customized gradient
    #     statistics.  Like :func:`xgboost.core.Booster.update`, this
    #     function should not be called directly by users.
    # 
    #     Parameters
    #     ----------
    #     dtrain : DMatrix
    #         The training DMatrix.
    #     grad : list
    #         The first order of gradient.
    #     hess : list
    #         The second order of gradient.
    # 
    #     """
    #     if len(grad) != len(hess):
    #         raise ValueError('grad / hess length mismatch: {} / {}'.format(len(grad), len(hess)))
    #     if not isinstance(dtrain, DMatrix):
    #         raise TypeError('invalid training matrix: {}'.format(type(dtrain).__name__))
    #     self._validate_features(dtrain)
    # 
    #     _check_call(_LIB.XGBoosterBoostOneIter(self.handle, dtrain.handle,
    #                                            c_array(ctypes.c_float, grad),
    #                                            c_array(ctypes.c_float, hess),
    #                                            c_bst_ulong(len(grad))))

    # TODO(rishabh): Enable these functions
    # def eval_set(self, evals, iteration=0, feval=None):
    #     # pylint: disable=invalid-name
    #     """Evaluate a set of data.
    # 
    #     Parameters
    #     ----------
    #     evals : list of tuples (DMatrix, string)
    #         List of items to be evaluated.
    #     iteration : int
    #         Current iteration.
    #     feval : function
    #         Custom evaluation function.
    # 
    #     Returns
    #     -------
    #     result: str
    #         Evaluation result string.
    #     """
    #     for d in evals:
    #         if not isinstance(d[0], DMatrix):
    #             raise TypeError('expected DMatrix, got {}'.format(type(d[0]).__name__))
    #         if not isinstance(d[1], STRING_TYPES):
    #             raise TypeError('expected string, got {}'.format(type(d[1]).__name__))
    #         self._validate_features(d[0])
    # 
    #     dmats = c_array(ctypes.c_char_p, [d[0].handle for d in evals])
    #     evnames = c_array(ctypes.c_char_p, [c_str(d[1]) for d in evals])
    #     msg = ctypes.c_char_p()
    #     _check_call(_LIB.XGBoosterEvalOneIter(self.handle, ctypes.c_int(iteration),
    #                                           dmats, evnames,
    #                                           c_bst_ulong(len(evals)),
    #                                           ctypes.byref(msg)))
    # 
    #     res = msg.value.decode()
    #     if feval is not None:
    #         for dmat, evname in evals:
    #             feval_ret = feval(self.predict(dmat), dmat)
    #             if isinstance(feval_ret, list):
    #                 for name, val in feval_ret:
    #                     res += '\t%s-%s:%f' % (evname, name, val)
    #             else:
    #                 name, val = feval_ret
    #                 res += '\t%s-%s:%f' % (evname, name, val)
    #     return res
    # 
    # def eval(self, data, name='eval', iteration=0):
    #     """Evaluate the model on mat.
    # 
    #     Parameters
    #     ----------
    #     data : DMatrix
    #         The dmatrix storing the input.
    # 
    #     name : str, optional
    #         The name of the dataset.
    # 
    #     iteration : int, optional
    #         The current iteration number.
    # 
    #     Returns
    #     -------
    #     result: str
    #         Evaluation result string.
    #     """
    #     self._validate_features(data)
    #     return self.eval_set([(data, name)], iteration)

    def predict(self, data, output_margin=False, ntree_limit=0, pred_leaf=False,
                pred_contribs=False, approx_contribs=False, pred_interactions=False,
                validate_features=True, training=False, decrypt=False):
        """
        Predict with data.

        .. note:: This function is not thread safe.

          For each booster object, predict can only be called from one thread.
          If you want to run prediction using multiple thread, call ``bst.copy()`` to make copies
          of model object and then call ``predict()``.

        .. note:: Using ``predict()`` with DART booster

          If the booster object is DART type, ``predict()`` will perform dropouts, i.e. only
          some of the trees will be evaluated. This will produce incorrect results if ``data`` is
          not the training data. To obtain correct results on test sets, set ``ntree_limit`` to
          a nonzero value, e.g.

          .. code-block:: python

            preds = bst.predict(dtest, ntree_limit=num_round)

        Parameters
        ----------
        data : DMatrix
            The dmatrix storing the input.

        output_margin : bool
            Whether to output the raw untransformed margin value.

        ntree_limit : int
            Limit number of trees in the prediction; defaults to 0 (use all trees).

        pred_leaf : bool
            When this option is on, the output will be a matrix of (nsample, ntrees)
            with each record indicating the predicted leaf index of each sample in each tree.
            Note that the leaf index of a tree is unique per tree, so you may find leaf 1
            in both tree 1 and tree 0.

        pred_contribs : bool
            When this is True the output will be a matrix of size (nsample, nfeats + 1)
            with each record indicating the feature contributions (SHAP values) for that
            prediction. The sum of all feature contributions is equal to the raw untransformed
            margin value of the prediction. Note the final column is the bias term.

        approx_contribs : bool
            Approximate the contributions of each feature

        pred_interactions : bool
            When this is True the output will be a matrix of size (nsample, nfeats + 1, nfeats + 1)
            indicating the SHAP interaction values for each pair of features. The sum of each
            row (or column) of the interaction values equals the corresponding SHAP value (from
            pred_contribs), and the sum of the entire matrix equals the raw untransformed margin
            value of the prediction. Note the last row and column correspond to the bias term.

        training : bool
            Whether the prediction value is used for training.  This can effect
            `dart` booster, which performs dropouts during training iterations.

        .. note:: Using ``predict()`` with DART booster

          If the booster object is DART type, ``predict()`` will not perform
          dropouts, i.e. all the trees will be evaluated.  If you want to
          obtain result with dropouts, provide `training=True`.

        validate_features : bool
            When this is True, validate that the Booster's and data's feature_names are identical.
            Otherwise, it is assumed that the feature_names are the same.

        decrypt: bool
            When this is True, the predictions received from the enclave are decrypted using the user's symmetric key

        Returns
        -------
        prediction : list
            List of predictions. Each element in the list is a set of predictions from a different node in the cloud.
        num_preds: list
            Number of predictions in each element in `prediction`
        """
        # check the global variable for current_user
        if "current_user" in _CONF:
            username = _CONF["current_user"]
        else:
            raise ValueError("Please set your username with the init_user() function")
        option_mask = 0x00
        if output_margin:
            option_mask |= 0x01
        if pred_leaf:
            option_mask |= 0x02
        if pred_contribs:
            option_mask |= 0x04
        if approx_contribs:
            option_mask |= 0x08
        if pred_interactions:
            option_mask |= 0x10

        if validate_features:
            self._validate_features(data)

        length = c_bst_ulong()
        preds = ctypes.POINTER(ctypes.c_uint8)()

        args = "XGBoosterPredict booster_handle {} data_handle {} option_mask {} ntree_limit {}".format(self.handle.value.decode('utf-8'), data.handle.value.decode('utf-8'), int(option_mask), int(ntree_limit))
        sig, sig_len = create_client_signature(args)

        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_length = c_bst_ulong()

        channel_addr = _CONF["remote_addr"]
        if channel_addr:
            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                predict_params = remote_pb2.PredictParams(booster_handle=self.handle.value,
                    dmatrix_handle=data.handle.value,
                    option_mask=option_mask,
                    ntree_limit=ntree_limit,
                    training=training)
                seq_num = get_seq_num_proto() 
                response = _check_remote_call(stub.rpc_XGBoosterPredict(remote_pb2.PredictParamsRequest(params=predict_params, seq_num=seq_num, username=_CONF["current_user"],
                                                                                                        signature=sig, sig_len=sig_len)))
                # List of list of predictions
                enc_preds_serialized_list = response.predictions
                length_list = list(response.num_preds)

                # List of signatures
                out_sigs_serialized_list = response.signatures
                out_sig_length_list = list(response.sig_lens)
                
                preds_list = [proto_to_pointer(enc_preds_serialized) for enc_preds_serialized in enc_preds_serialized_list]
                out_sigs = [proto_to_pointer(out_sig_serialized) for out_sig_serialized in out_sigs_serialized_list]
                out_sig_lengths_ulong = [c_bst_ulong(length) for length in out_sig_length_list]

                # Verify signatures
                for i in range(len(preds_list)):
                    preds = preds_list[i]
                    enc_preds_length = length_list[i]
                    size = enc_preds_length * ctypes.sizeof(ctypes.c_float) + CIPHER_IV_SIZE + CIPHER_TAG_SIZE

                    out_sig = out_sigs[i]
                    out_sig_length = out_sig_lengths_ulong[i]
                    
                    if i != len(preds_list) - 1:
                        verify_enclave_signature(preds, size, out_sig, out_sig_length, increment_nonce=False)
                    else:
                        verify_enclave_signature(preds, size, out_sig, out_sig_length, increment_nonce=True)

                if decrypt:
                    preds = self.decrypt_predictions(preds_list, length_list)
                    return preds, sum(length_list)

                return preds_list, length_list
        else:
            nonce = _CONF["nonce"]
            nonce_size = _CONF["nonce_size"]
            nonce_ctr = _CONF["nonce_ctr"]
            c_signatures, c_lengths = py2c_sigs([sig], [sig_len])
            signers = from_pystr_to_cstr([_CONF["current_user"]])
            _check_call(_LIB.XGBoosterPredict(self.handle,
                                              data.handle,
                                              ctypes.c_int(option_mask),
                                              ctypes.c_uint(ntree_limit),
                                              ctypes.c_int(training),
                                              nonce,
                                              nonce_size,
                                              ctypes.c_uint32(nonce_ctr),
                                              ctypes.byref(length),
                                              ctypes.byref(preds),
                                              ctypes.byref(out_sig),
                                              ctypes.byref(out_sig_length),
                                              signers,
                                              c_signatures,
                                              c_lengths))

            size = length.value * ctypes.sizeof(ctypes.c_float) + CIPHER_IV_SIZE + CIPHER_TAG_SIZE
            verify_enclave_signature(preds, size, out_sig, out_sig_length)

            # TODO(rishabh): implement this in decrypt_predictions
            #  preds = ctypes2numpy(preds, length.value, np.float32)
            #  if pred_leaf:
            #      preds = preds.astype(np.int32)
            #
            #  nrow = data.num_row()
            #  if preds.size != nrow and preds.size % nrow == 0:
            #      chunk_size = int(preds.size / nrow)
            #
            #      if pred_interactions:
            #          ngroup = int(chunk_size / ((data.num_col() + 1) * (data.num_col() + 1)))
            #          if ngroup == 1:
            #              preds = preds.reshape(nrow, data.num_col() + 1, data.num_col() + 1)
            #          else:
            #              preds = preds.reshape(nrow, ngroup, data.num_col() + 1, data.num_col() + 1)
            #      elif pred_contribs:
            #          ngroup = int(chunk_size / (data.num_col() + 1))
            #          if ngroup == 1:
            #              preds = preds.reshape(nrow, data.num_col() + 1)
            #          else:
            #              preds = preds.reshape(nrow, ngroup, data.num_col() + 1)
            #      else:
            #          preds = preds.reshape(nrow, chunk_size)
            if decrypt:
                preds = self.decrypt_predictions(preds, length.value)
            return preds, length.value

    # TODO(rishabh): change encrypted_preds to Python type from ctype
    def decrypt_predictions(self, encrypted_preds, num_preds):
        """
        Decrypt encrypted predictions

        Parameters
        ----------
        key : byte array
            key used to encrypt client files
        encrypted_preds : c_char_p
            encrypted predictions
        num_preds : int
            number of predictions

        Returns
        -------
        preds : numpy array 
            plaintext predictions
        """
        try:
            sym_key = _CONF["current_user_sym_key"]
        except:
            raise ValueError("User not found. Please set your username, symmetric key, and public key using `init_user()`")

        # Cast arguments to proper ctypes
        c_char_p_key = ctypes.c_char_p(sym_key)

        if not isinstance(encrypted_preds, list):
            size_t_num_preds = ctypes.c_size_t(num_preds)

            preds = ctypes.POINTER(ctypes.c_float)()

            _check_call(_LIB.decrypt_predictions(c_char_p_key, encrypted_preds, size_t_num_preds, ctypes.byref(preds)))

            # Convert c pointer to numpy array
            preds = ctypes2numpy(preds, num_preds, np.float32)
            return preds
        else:
            preds_list = []
            for i in range(len(encrypted_preds)):
                size_t_num_preds = ctypes.c_size_t(num_preds[i])
                preds = ctypes.POINTER(ctypes.c_float)()

                _check_call(_LIB.decrypt_predictions(c_char_p_key, encrypted_preds[i], size_t_num_preds, ctypes.byref(preds)))

                # Convert c pointer to numpy array
                preds = ctypes2numpy(preds, num_preds[i], np.float32)
                preds_list.append(preds)

            concatenated_preds = np.concatenate(preds_list)
            return concatenated_preds

    def save_model(self, fname):
        """
        Save the model to an encrypted file at the server.
        The file is encrypted with the user's symmetric key.

        The model is saved in an XGBoost internal binary format which is
        universal among the various XGBoost interfaces. Auxiliary attributes of
        the Python Booster object (such as feature_names) will not be saved.
        To preserve all attributes, pickle the Booster object.

        Parameters
        ----------
        fname : str
            Absolute path to save the model to
        """
        # check the global variable for current_user
        if "current_user" in _CONF:
            username = _CONF["current_user"]
        else:
            raise ValueError("Please set your username with the init_user() function")
        if isinstance(fname, STRING_TYPES):  # assume file name

            # Normalize file paths (otherwise signatures might differ)
            fname = os.path.normpath(fname)

            args = "XGBoosterSaveModel handle {} filename {}".format(self.handle.value.decode('utf-8'), fname)
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            if channel_addr:
                with grpc.insecure_channel(channel_addr) as channel:
                    stub = remote_pb2_grpc.RemoteStub(channel)
                    save_model_params = remote_pb2.SaveModelParams(
                        booster_handle=self.handle.value,
                        filename=fname)
                    seq_num = get_seq_num_proto() 
                    response = _check_remote_call(stub.rpc_XGBoosterSaveModel(remote_pb2.SaveModelParamsRequest(params=save_model_params, seq_num=seq_num, username=_CONF["current_user"],
                                                                                                                signature=sig, sig_len=sig_len)))
                    out_sig = proto_to_pointer(response.signature)
                    out_sig_length = c_bst_ulong(response.sig_len)
            else:
                nonce = _CONF["nonce"]
                nonce_size = _CONF["nonce_size"]
                nonce_ctr = _CONF["nonce_ctr"]
                c_signatures, c_sig_lengths = py2c_sigs([sig], [sig_len])
                signers = from_pystr_to_cstr([_CONF["current_user"]])
                _check_call(_LIB.XGBoosterSaveModel(self.handle, c_str(fname),
                                                    nonce, nonce_size, ctypes.c_uint32(nonce_ctr),
                                                    ctypes.byref(out_sig),
                                                    ctypes.byref(out_sig_length),
                                                    signers, c_signatures, c_sig_lengths))
            verify_enclave_signature("", 0, out_sig, out_sig_length)
        else:
            raise TypeError("fname must be a string")


    # FIXME Should we decrypt the raw model?
    def save_raw(self):
        """
        Save the model to a in memory buffer representation.
        The model is encrypted with the user's symmetric key.

        Returns
        -------
        a in memory buffer representation of the model
        """
        # check the global variable for current_user
        if "current_user" in _CONF:
            username = _CONF["current_user"]
        else:
            raise ValueError("Please set your username with the init_user() function")
        length = c_bst_ulong()
        cptr = ctypes.POINTER(ctypes.c_char)()

        args = "XGBoosterGetModelRaw handle {}".format(self.handle.value.decode('utf-8'))
        sig, sig_len = create_client_signature(args)

        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_length = c_bst_ulong()

        channel_addr = _CONF["remote_addr"]
        if channel_addr:
            with grpc.insecure_channel(channel_addr) as channel:
                stub = remote_pb2_grpc.RemoteStub(channel)
                model_raw_params = remote_pb2.ModelRawParams(booster_handle=self.handle.value)
                seq_num = get_seq_num_proto() 
                response = _check_remote_call(stub.rpc_XGBoosterGetModelRawParams(params=model_raw_params, seq_num=seq_num, username=username,
                                                                                  signature=sig, sig_len=sig_len))
                cptr = from_pystr_to_cstr(list(response.sarr))
                length = c_bst_ulong(response.length)
                out_sig = proto_to_pointer(response.signature)
                out_sig_length = c_bst_ulong(response.sig_len)
        else:
            c_signatures, c_lengths = py2c_sigs([sig], [sig_len])
            signers = from_pystr_to_cstr([_CONF["current_user"]])
            _check_call(_LIB.XGBoosterGetModelRaw(self.handle,
                                                  _CONF["nonce"],
                                                  _CONF["nonce_size"],
                                                  ctypes.c_uint32(_CONF["nonce_ctr"]),
                                                  ctypes.byref(length),
                                                  ctypes.byref(cptr),
                                                  ctypes.byref(out_sig),
                                                  ctypes.byref(out_sig_length),
                                                  signers,
                                                  c_signatures,
                                                  c_lengths))
        verify_enclave_signature(cptr, length.value, out_sig, out_sig_length)
        return ctypes2buffer(cptr, length.value)


    def load_model(self, fname):
        """
        Load the model from a file.
    
        The model is loaded from an XGBoost internal binary format which is
        universal among the various XGBoost interfaces. Auxiliary attributes of
        the Python Booster object (such as feature_names) will not be loaded.
        To preserve all attributes, pickle the Booster object.
    
        Parameters
        ----------
        fname : str or a memory buffer
            Input file name or memory buffer(see also save_raw)
        """
        # check the global variable for current_user
        if "current_user" in _CONF:
            username = _CONF["current_user"]
        else:
            raise ValueError("Please set your username with the init_user() function")
        if isinstance(fname, STRING_TYPES):

            # Normalize file paths (otherwise signatures might differ)
            fname = os.path.normpath(fname)

            # assume file name, cannot use os.path.exist to check, file can be from URL.
            args = "XGBoosterLoadModel handle {} filename {}".format(self.handle.value.decode('utf-8'), fname)
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            if channel_addr:
                with grpc.insecure_channel(channel_addr) as channel:
                    stub = remote_pb2_grpc.RemoteStub(channel)
                    load_model_params = remote_pb2.LoadModelParams(
                        booster_handle=self.handle.value,
                        filename=fname)
                    seq_num = get_seq_num_proto() 
                    response = _check_remote_call(stub.rpc_XGBoosterLoadModel(remote_pb2.LoadModelParamsRequest(params=load_model_params,
                                                                                                                seq_num=seq_num,
                                                                                                                username=_CONF["current_user"],
                                                                                                                signature=sig,
                                                                                                                sig_len=sig_len)))
                    out_sig = proto_to_pointer(response.signature)
                    out_sig_length = c_bst_ulong(response.sig_len)
            else:
                c_signatures, c_lengths = py2c_sigs([sig], [sig_len])
                signers = from_pystr_to_cstr([_CONF["current_user"]])
                nonce = _CONF["nonce"]
                nonce_size = _CONF["nonce_size"]
                nonce_ctr = ctypes.c_uint32(_CONF["nonce_ctr"])
                _check_call(_LIB.XGBoosterLoadModel(self.handle, c_str(fname), nonce, nonce_size, nonce_ctr, ctypes.byref(out_sig), ctypes.byref(out_sig_length), signers, c_signatures, c_lengths))

            verify_enclave_signature("", 0, out_sig, out_sig_length)
        else:
            # FIXME: Remote execution for non-file type
            raise "NotImplementedError"
            # buf = fname
            # length = c_bst_ulong(len(buf))
            # ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            # _check_call(_LIB.XGBoosterLoadModelFromBuffer(self.handle, ptr, length, c_str(username)))


    def dump_model(self, fout, fmap='', with_stats=False, dump_format="text"):
        """
        Dump model into a text or JSON file.

        Parameters
        ----------
        fout : str
            Output file name.
        fmap : str, optional
            Name of the file containing feature map names.
        with_stats : bool, optional
            Controls whether the split statistics are output.
        dump_format : str, optional
            Format of model dump file. Can be 'text' or 'json'.
        """
        if isinstance(fout, STRING_TYPES):
            fout = open(fout, 'w')
            need_close = True
        else:
            need_close = False
        ret = self.get_dump(fmap, with_stats, dump_format)
        if dump_format == 'json':
            fout.write('[\n')
            for i, _ in enumerate(ret):
                fout.write(ret[i])
                if i < len(ret) - 1:
                    fout.write(",\n")
            fout.write('\n]')
        else:
            for i, _ in enumerate(ret):
                fout.write('booster[{}]:\n'.format(i))
                fout.write(ret[i])
        if need_close:
            fout.close()

    def get_dump(self, fmap='', with_stats=False, dump_format="text", decrypt=True):
        """
        Returns the (encrypted) model dump as a list of strings.
        The model is encrypted with the user's symmetric key.
        If `decrypt` is True, then the dump is decrypted by the client.

        Parameters
        ----------
        fmap : str, optional
            Name of the file containing feature map names.
        with_stats : bool, optional
            Controls whether the split statistics are output.
        dump_format : str, optional
            Format of model dump. Can be 'text' or 'json'.
        decrypt: bool
            When this is True, the model dump received from the enclave is decrypted using the user's symmetric key

        Returns
        -------
        res : str
            A string representation of the model dump
        """
        length = c_bst_ulong()
        sarr = ctypes.POINTER(ctypes.c_char_p)()
        if self.feature_names is not None and fmap == '':
            flen = len(self.feature_names)

            fname = self.feature_names
            if self.feature_types is None:
                # use quantitative as default
                # {'q': quantitative, 'i': indicator}
                ftype = ['q'] * flen
            else:
                ftype = self.feature_types

            args = "XGBoosterDumpModelExWithFeatures booster_handle {} flen {} with_stats {} dump_format {}".format(self.handle.value.decode('utf-8'), flen, int(with_stats), dump_format)
            for i in range(flen):
                args = args +  " fname {} ftype {}".format(fname[i], ftype[i])
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            if channel_addr:
                with grpc.insecure_channel(channel_addr) as channel:
                    stub = remote_pb2_grpc.RemoteStub(channel)
                    dump_model_with_features_params = remote_pb2.DumpModelWithFeaturesParams(
                        booster_handle=self.handle.value,
                        flen=flen,
                        fname=fname,
                        ftype=ftype,
                        with_stats=with_stats,
                        dump_format=dump_format)
                    seq_num = get_seq_num_proto()
                    response = _check_remote_call(stub.rpc_XGBoosterDumpModelExWithFeatures(remote_pb2.DumpModelWithFeaturesParamsRequest(
                        params=dump_model_with_features_params, seq_num=seq_num, username=_CONF["current_user"],
                        signature=sig, sig_len=sig_len)))
                    sarr = from_pystr_to_cstr(list(response.sarr))
                    length = c_bst_ulong(response.length)
                    out_sig = proto_to_pointer(response.signature)
                    out_sig_length = c_bst_ulong(response.sig_len)
            else:
                nonce = _CONF["nonce"]
                nonce_size = _CONF["nonce_size"]
                nonce_ctr = _CONF["nonce_ctr"]
                c_signatures, c_lengths = py2c_sigs([sig], [sig_len])
                signers = from_pystr_to_cstr([_CONF["current_user"]])
                _check_call(_LIB.XGBoosterDumpModelExWithFeatures(
                    self.handle,
                    ctypes.c_int(flen),
                    from_pystr_to_cstr(fname),
                    from_pystr_to_cstr(ftype),
                    ctypes.c_int(with_stats),
                    c_str(dump_format),
                    nonce,
                    nonce_size,
                    ctypes.c_uint32(nonce_ctr),
                    ctypes.byref(length),
                    ctypes.byref(sarr),
                    ctypes.byref(out_sig),
                    ctypes.byref(out_sig_length),
                    signers,
                    c_signatures,
                    c_lengths))

        else:
            if fmap != '' and not os.path.exists(fmap):
                raise ValueError("No such file: {0}".format(fmap))

            args = "XGBoosterDumpModelEx booster_handle {} fmap {} with_stats {} dump_format {}".format(self.handle.value.decode('utf-8'), fmap, int(with_stats), dump_format)
            sig, sig_len = create_client_signature(args)

            out_sig = ctypes.POINTER(ctypes.c_uint8)()
            out_sig_length = c_bst_ulong()

            channel_addr = _CONF["remote_addr"]
            if channel_addr:
                with grpc.insecure_channel(channel_addr) as channel:
                    stub = remote_pb2_grpc.RemoteStub(channel)
                    dump_model_params = remote_pb2.DumpModelParams(
                        booster_handle=self.handle.value,
                        fmap=fmap,
                        with_stats=with_stats,
                        dump_format=dump_format)
                    seq_num = get_seq_num_proto() 
                    response = _check_remote_call(stub.rpc_XGBoosterDumpModelEx(remote_pb2.DumpModelParamsRequest(params=dump_model_params, seq_num=seq_num, username=_CONF["current_user"],
                                                                                                                  signature=sig, sig_len=sig_len)))
                    sarr = from_pystr_to_cstr(list(response.sarr))
                    length = c_bst_ulong(response.length)
                    out_sig = proto_to_pointer(response.signature)
                    out_sig_length = c_bst_ulong(response.sig_len)
            else:
                nonce = _CONF["nonce"]
                nonce_size = _CONF["nonce_size"]
                nonce_ctr = _CONF["nonce_ctr"]
                c_signatures, c_lengths = py2c_sigs([sig], [sig_len])
                signers = from_pystr_to_cstr([_CONF["current_user"]])
                _check_call(_LIB.XGBoosterDumpModelEx(self.handle,
                                                      c_str(fmap),
                                                      ctypes.c_int(with_stats),
                                                      c_str(dump_format),
                                                      nonce,
                                                      nonce_size,
                                                      ctypes.c_uint32(nonce_ctr),
                                                      ctypes.byref(length),
                                                      ctypes.byref(sarr),
                                                      ctypes.byref(out_sig),
                                                      ctypes.byref(out_sig_length),
                                                      signers,
                                                      c_signatures,
                                                      c_lengths))
        py_sarr = from_cstr_to_pystr(sarr, length)
        data = ''.join(py_sarr)
        verify_enclave_signature(data, len(data), out_sig, out_sig_length)

        if decrypt:
            self.decrypt_dump(sarr, length)
        res = from_cstr_to_pystr(sarr, length)
        return res

    def decrypt_dump(self, sarr, length):
        """ 
        Decrypt the models obtained from get_dump()
        
        Parameters
        ----------
        sarr: str
            Encrypted string representation of the model obtained from get_dump()
        length : int
           length of sarr 
        """ 
        try:
            sym_key = _CONF["enclave_sym_key"]
        except:
            raise ValueError("Please set your username with the init_user() function")
        _check_call(_LIB.decrypt_dump(sym_key, sarr, length))


    def get_fscore(self, fmap=''):
        """Get feature importance of each feature.

        .. note:: Feature importance is defined only for tree boosters

        Feature importance is only defined when the decision tree model is chosen as base
        learner (`booster=gbtree`). It is not defined for other base learner types, such
        as linear learners (`booster=gblinear`).

        .. note:: Zero-importance features will not be included

        Keep in mind that this function does not include zero-importance feature, i.e.
        those features that have not been used in any split conditions.

        Parameters
        ----------
        fmap: str (optional)
            The name of feature map file
        """

        return self.get_score(fmap, importance_type='weight')

    def get_score(self, fmap='', importance_type='weight'):
        """Get feature importance of each feature.
        Importance type can be defined as:

        * 'weight': the number of times a feature is used to split the data across all trees.
        * 'gain': the average gain across all splits the feature is used in.
        * 'cover': the average coverage across all splits the feature is used in.
        * 'total_gain': the total gain across all splits the feature is used in.
        * 'total_cover': the total coverage across all splits the feature is used in.

        .. note:: Feature importance is defined only for tree boosters

            Feature importance is only defined when the decision tree model is chosen as base
            learner (`booster=gbtree`). It is not defined for other base learner types, such
            as linear learners (`booster=gblinear`).

        Parameters
        ----------
        fmap: str (optional)
           The name of feature map file.
        importance_type: str, default 'weight'
            One of the importance types defined above.
        """
        if getattr(self, 'booster', None) is not None and self.booster not in {'gbtree', 'dart'}:
            raise ValueError('Feature importance is not defined for Booster type {}'
                             .format(self.booster))

        allowed_importance_types = ['weight', 'gain', 'cover', 'total_gain', 'total_cover']
        if importance_type not in allowed_importance_types:
            msg = ("importance_type mismatch, got '{}', expected one of " +
                   repr(allowed_importance_types))
            raise ValueError(msg.format(importance_type))

        # if it's weight, then omap stores the number of missing values
        if importance_type == 'weight':
            # do a simpler tree dump to save time
            trees = self.get_dump(fmap, with_stats=False)

            fmap = {}
            for tree in trees:
                for line in tree.split('\n'):
                    # look for the opening square bracket
                    arr = line.split('[')
                    # if no opening bracket (leaf node), ignore this line
                    if len(arr) == 1:
                        continue

                    # extract feature name from string between []
                    fid = arr[1].split(']')[0].split('<')[0]

                    if fid not in fmap:
                        # if the feature hasn't been seen yet
                        fmap[fid] = 1
                    else:
                        fmap[fid] += 1

            return fmap

        average_over_splits = True
        if importance_type == 'total_gain':
            importance_type = 'gain'
            average_over_splits = False
        elif importance_type == 'total_cover':
            importance_type = 'cover'
            average_over_splits = False

        trees = self.get_dump(fmap, with_stats=True)

        importance_type += '='
        fmap = {}
        gmap = {}
        for tree in trees:
            for line in tree.split('\n'):
                # look for the opening square bracket
                arr = line.split('[')
                # if no opening bracket (leaf node), ignore this line
                if len(arr) == 1:
                    continue

                # look for the closing bracket, extract only info within that bracket
                fid = arr[1].split(']')

                # extract gain or cover from string after closing bracket
                g = float(fid[1].split(importance_type)[1].split(',')[0])

                # extract feature name from string before closing bracket
                fid = fid[0].split('<')[0]

                if fid not in fmap:
                    # if the feature hasn't been seen yet
                    fmap[fid] = 1
                    gmap[fid] = g
                else:
                    fmap[fid] += 1
                    gmap[fid] += g

        # calculate average value (gain/cover) for each feature
        if average_over_splits:
            for fid in gmap:
                gmap[fid] = gmap[fid] / fmap[fid]

        return gmap

    def trees_to_dataframe(self, fmap=''):
        """Parse a boosted tree model text dump into a pandas DataFrame structure.

        This feature is only defined when the decision tree model is chosen as base
        learner (`booster in {gbtree, dart}`). It is not defined for other base learner
        types, such as linear learners (`booster=gblinear`).

        Parameters
        ----------
        fmap: str (optional)
           The name of feature map file.
        """
        # pylint: disable=too-many-locals
        if not PANDAS_INSTALLED:
            raise Exception(('pandas must be available to use this method.'
                             'Install pandas before calling again.'))

        if getattr(self, 'booster', None) is not None and self.booster not in {'gbtree', 'dart'}:
            raise ValueError('This method is not defined for Booster type {}'
                             .format(self.booster))

        tree_ids = []
        node_ids = []
        fids = []
        splits = []
        y_directs = []
        n_directs = []
        missings = []
        gains = []
        covers = []

        trees = self.get_dump(key, fmap, with_stats=True)
        for i, tree in enumerate(trees):
            for line in tree.split('\n'):
                arr = line.split('[')
                # Leaf node
                if len(arr) == 1:
                    # Last element of line.split is an empy string
                    if arr == ['']:
                        continue
                    # parse string
                    parse = arr[0].split(':')
                    stats = re.split('=|,', parse[1])

                    # append to lists
                    tree_ids.append(i)
                    node_ids.append(int(re.findall(r'\b\d+\b', parse[0])[0]))
                    fids.append('Leaf')
                    splits.append(float('NAN'))
                    y_directs.append(float('NAN'))
                    n_directs.append(float('NAN'))
                    missings.append(float('NAN'))
                    gains.append(float(stats[1]))
                    covers.append(float(stats[3]))
                # Not a Leaf Node
                else:
                    # parse string
                    fid = arr[1].split(']')
                    parse = fid[0].split('<')
                    stats = re.split('=|,', fid[1])

                    # append to lists
                    tree_ids.append(i)
                    node_ids.append(int(re.findall(r'\b\d+\b', arr[0])[0]))
                    fids.append(parse[0])
                    splits.append(float(parse[1]))
                    str_i = str(i)
                    y_directs.append(str_i + '-' + stats[1])
                    n_directs.append(str_i + '-' + stats[3])
                    missings.append(str_i + '-' + stats[5])
                    gains.append(float(stats[7]))
                    covers.append(float(stats[9]))

        ids = [str(t_id) + '-' + str(n_id) for t_id, n_id in zip(tree_ids, node_ids)]
        df = DataFrame({'Tree': tree_ids, 'Node': node_ids, 'ID': ids,
                        'Feature': fids, 'Split': splits, 'Yes': y_directs,
                        'No': n_directs, 'Missing': missings, 'Gain': gains,
                        'Cover': covers})

        if callable(getattr(df, 'sort_values', None)):
            # pylint: disable=no-member
            return df.sort_values(['Tree', 'Node']).reset_index(drop=True)
        # pylint: disable=no-member
        return df.sort(['Tree', 'Node']).reset_index(drop=True)

    def _validate_features(self, data):
        """
        Validate Booster and data's feature_names are identical.
        Set feature_names and feature_types from DMatrix
        """
        if self.feature_names is None:
            self.feature_names = data.feature_names
            self.feature_types = data.feature_types
        else:
            # Booster can't accept data with different feature names
            if self.feature_names != data.feature_names:
                dat_missing = set(self.feature_names) - set(data.feature_names)
                my_missing = set(data.feature_names) - set(self.feature_names)

                msg = 'feature_names mismatch: {0} {1}'

                if dat_missing:
                    msg += ('\nexpected ' + ', '.join(str(s) for s in dat_missing) +
                            ' in input data')

                if my_missing:
                    msg += ('\ntraining data did not have the following fields: ' +
                            ', '.join(str(s) for s in my_missing))

                raise ValueError(msg.format(self.feature_names,
                                            data.feature_names))

    def get_split_value_histogram(self, feature, fmap='', bins=None, as_pandas=True):
        """Get split value histogram of a feature

        Parameters
        ----------
        feature: str
            The name of the feature.
        fmap: str (optional)
            The name of feature map file.
        bin: int, default None
            The maximum number of bins.
            Number of bins equals number of unique split values n_unique,
            if bins == None or bins > n_unique.
        as_pandas: bool, default True
            Return pd.DataFrame when pandas is installed.
            If False or pandas is not installed, return numpy ndarray.

        Returns
        -------
        a histogram of used splitting values for the specified feature
        either as numpy array or pandas DataFrame.
        """
        xgdump = self.get_dump(fmap=fmap)
        values = []
        regexp = re.compile(r"\[{0}<([\d.Ee+-]+)\]".format(feature))
        for i, _ in enumerate(xgdump):
            m = re.findall(regexp, xgdump[i])
            values.extend([float(x) for x in m])

        n_unique = len(np.unique(values))
        bins = max(min(n_unique, bins) if bins is not None else n_unique, 1)

        nph = np.histogram(values, bins=bins)
        nph = np.column_stack((nph[1][1:], nph[0]))
        nph = nph[nph[:, 1] > 0]

        if as_pandas and PANDAS_INSTALLED:
            return DataFrame(nph, columns=['SplitValue', 'Count'])
        if as_pandas and not PANDAS_INSTALLED:
            sys.stderr.write(
                "Returning histogram as ndarray (as_pandas == True, but pandas is not installed).")
        return nph

##########################################
# Enclave init and attestation APIs
##########################################

def init_config(config):
    """
    Initialize the client. Set up the client's keys, and specify the IP address of the enclave server.

    Parameters
    ----------
    config: file
        Configuration file containing the following parameters:
        remote_addr: IP address of remote server running the enclave
        user_name : Current user's username
        client_list : List of usernames for all clients in the collaboration
        sym_key_file : Path to file containing user's symmetric key used for encrypting data
        priv_key_file : Path to file containing user's private key used for signing data
        cert_file : Path to file containing user's public key certificate
    """
    conf = configparser.ConfigParser()
    conf.read(config)
    if len(conf) == 0:
        raise ValueError("Failed to open config file")

    # TODO(rishabh): Verify parameters

    try:
        if conf.has_option('default','remote_addr'):
            _CONF["remote_addr"] = conf['default']['remote_addr']
        else:
            _CONF["remote_addr"] = None

        user_name = conf['default']['user_name']
        _CONF["current_user"] = user_name

        if conf.has_option('default','client_list'):
            client_list = conf['default']['client_list'].split(',')
        else:
            client_list = []
        for i, s in enumerate(client_list):
            client_list[i] = s.strip()
        client_set = set(client_list)
        client_set.add(user_name)
        _CONF["client_list"] = list(sorted(client_set))

        sym_key_file = conf['default']['sym_key_file']
        if sym_key_file is not None:
            with open(sym_key_file, "rb") as keyfile:
                _CONF["current_user_sym_key"] = keyfile.read()
                # TODO(rishabh): Save buffer instead of file
                # with open(priv_key_file, "r") as keyfile:
                #     priv_key = keyfile.read()

        priv_key_file = conf['default']['priv_key_file']
        _CONF["current_user_priv_key"] = priv_key_file

        cert_file = conf['default']['cert_file']
        if cert_file is not None:
            with open(cert_file, "r") as cert_file:
                _CONF["current_user_cert"] = cert_file.read()

        _CONF["nonce_ctr"] = 0
    except KeyError as e:
        print("Please add the required fields to your config file")
        raise e


def init_client(config=None, remote_addr=None, user_name=None, client_list=[],
        sym_key_file=None, priv_key_file=None, cert_file=None):
    """
    Initialize the client. Set up the client's keys, and specify the IP address of the enclave server.

    Parameters
    ----------
    config: file
        Configuration file containing the client parameters. If this is provided, the other arguments are ignored.
    remote_addr: str
        IP address of remote server running the enclave
    user_name : str
        Current user's username
    client_list : list
        List of usernames for all clients in the collaboration
    sym_key_file : str
        Path to file containing user's symmetric key used for encrypting data
    priv_key_file : str
        Path to file containing user's private key used for signing data
    cert_file : str
        Path to file containing user's public key certificate
    """
    if config is not None:
        init_config(config)
        return

    _CONF["remote_addr"] = remote_addr;
    _CONF["current_user"] = user_name
    _clients = set(client_list)
    _clients.add(user_name)
    _CONF["client_list"] = list(sorted(_clients))

    if sym_key_file is not None:
        with open(sym_key_file, "rb") as keyfile:
            _CONF["current_user_sym_key"] = keyfile.read()
            # TODO(rishabh): Save buffer instead of file
            # with open(priv_key_file, "r") as keyfile:
            #     priv_key = keyfile.read()

    _CONF["current_user_priv_key"] = priv_key_file

    if cert_file is not None:
        with open(cert_file, "r") as cert_file:
            _CONF["current_user_cert"] = cert_file.read()

    _CONF["nonce_ctr"] = 0 


def init_server(enclave_image=None, client_list=[], log_verbosity=0):
    """
    Launch the enclave from an image. This API should be invoked only by the servers and not the clients.

    Parameters
    ----------
    enclave_image: str
        Path to enclave binary
    client_list: list
        List of usernames (strings) of clients in the collaboration allowed to use the enclaves
    log_verbosity: int, optional
        Verbosity level for enclave (for enclaves in debug mode)
    """
    _check_call(_LIB.XGBCreateEnclave(c_str(enclave_image), from_pystr_to_cstr(client_list), len(client_list), log_verbosity))
    print("Launched enclave")


def attest(verify=False):
    # TODO(rishabh): user-defined mrsigner/mrenclave for verification
    # TODO(rishabh): Handle verification failures
    """
    Verify remote attestation report of enclave and get its public key.
    The report and public key are saved as instance attributes.


    Parameters
    ----------
    verify: bool
        If true, the client verifies the enclave report 

        .. warning:: ``verify`` should be set to ``False`` only for development and testing in simulation mode
    """

    pem_key = ctypes.POINTER(ctypes.c_uint8)()
    pem_key_size = ctypes.c_size_t()
    nonce = ctypes.POINTER(ctypes.c_uint8)()
    nonce_size = ctypes.c_size_t()
    client_list = ctypes.POINTER(ctypes.c_char_p)()
    client_list_size = ctypes.c_size_t()
    remote_report = ctypes.POINTER(ctypes.c_uint8)()
    remote_report_size = ctypes.c_size_t()

    # Get attestation report
    channel_addr = _CONF["remote_addr"]
    if channel_addr:
        with grpc.insecure_channel(channel_addr) as channel:
            stub = remote_pb2_grpc.RemoteStub(channel)
            response = _check_remote_call(stub.rpc_get_remote_report_with_pubkey_and_nonce(remote_pb2.Status(status=1)))

        pem_key = proto_to_ndarray(response.pem_key).ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
        pem_key_size = ctypes.c_size_t(response.pem_key_size)
        nonce = proto_to_ndarray(response.nonce).ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
        nonce_size = ctypes.c_size_t(response.nonce_size)
        client_list = from_pystr_to_cstr(list(response.client_list))
        client_list_size = ctypes.c_size_t(response.client_list_size)
        remote_report = proto_to_ndarray(response.remote_report).ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
        remote_report_size = ctypes.c_size_t(response.remote_report_size)

    else:
        _check_call(_LIB.get_remote_report_with_pubkey_and_nonce(
            ctypes.byref(pem_key), ctypes.byref(pem_key_size),
            ctypes.byref(nonce), ctypes.byref(nonce_size),
            ctypes.byref(client_list), ctypes.byref(client_list_size),
            ctypes.byref(remote_report), ctypes.byref(remote_report_size)))

    # Verify attestation report
    if (verify):
        _check_call(_LIB.verify_remote_report_and_set_pubkey_and_nonce(
            pem_key, pem_key_size,
            nonce, nonce_size,
            from_pystr_to_cstr(_CONF["client_list"]), len(_CONF["client_list"]),
            remote_report, remote_report_size))
    # Verify client names match
    else:
        enclave_client_list = sorted(from_cstr_to_pystr(client_list, client_list_size))
        if enclave_client_list != _CONF["client_list"]:
            raise XGBoostError("Client list doesn't match")

    _CONF["enclave_pk"] = pem_key
    _CONF["enclave_pk_size"] = pem_key_size
    _CONF["nonce"] = nonce
    _CONF["nonce_size"] = nonce_size

    _add_client_key()
    _get_enclave_symm_key()

    print("Remote attestation succeeded")


def _add_client_key():
    """
    Add private (symmetric) key to enclave.
    This function encrypts the user's symmetric key using the enclave's public key, and signs the ciphertext with the user's private key.
    The signed message is sent to the enclave.
    """
    # Convert key to serialized numpy array
    pem_key_size = _CONF["enclave_pk_size"].value
    pem_key = ctypes2numpy(_CONF["enclave_pk"], pem_key_size, np.uint8)
    pem_key = ndarray_to_proto(pem_key)

    # Convert nonce to serialized numpy array
    nonce_size = _CONF["nonce_size"].value
    nonce = ctypes2numpy(_CONF["nonce"], nonce_size, np.uint8)
    nonce = ndarray_to_proto(nonce)

    try:
        sym_key = _CONF["current_user_sym_key"]
        priv_key = _CONF["current_user_priv_key"]
        cert = _CONF["current_user_cert"]
    except:
        raise ValueError("Please set your username with the init_user() function")
    enc_sym_key, enc_sym_key_size = encrypt_data_with_pk(sym_key, len(sym_key), pem_key, pem_key_size)

    # Sign the encrypted symmetric key
    sig, sig_size = sign_data(priv_key, enc_sym_key, enc_sym_key_size)

    # Send the encrypted key to the enclave
    channel_addr = _CONF["remote_addr"]
    if channel_addr:
        with grpc.insecure_channel(channel_addr) as channel:
            stub = remote_pb2_grpc.RemoteStub(channel)
            response = _check_remote_call(stub.rpc_add_client_key_with_certificate(remote_pb2.DataMetadata(
                certificate=cert,
                enc_sym_key=enc_sym_key,
                key_size=enc_sym_key_size,
                signature=sig,
                sig_len=sig_size)))
    else:
        cert_len = len(cert) + 1
        cert = ctypes.c_char_p(str.encode(cert))
        enc_sym_key = proto_to_pointer(enc_sym_key)
        enc_sym_key_size = ctypes.c_size_t(enc_sym_key_size)
        sig = proto_to_pointer(sig)
        sig_size = ctypes.c_size_t(sig_size)

        _check_call(_LIB.add_client_key_with_certificate(cert, cert_len, enc_sym_key, enc_sym_key_size, sig, sig_size))


def _get_enclave_symm_key():
    """
    Get enclave's symmetric key used to encrypt output common to all clients
    """

    if "current_user" in _CONF:
        username = _CONF["current_user"]
    else:
        raise ValueError("Please set your username with the init_user() function")
    channel_addr = _CONF["remote_addr"]
    if channel_addr:
        with grpc.insecure_channel(channel_addr) as channel:
            stub = remote_pb2_grpc.RemoteStub(channel)
            response = _check_remote_call(stub.rpc_get_enclave_symm_key(remote_pb2.Name(
                username=username)))

            enc_key_serialized = response.key
            enc_key_size = ctypes.c_size_t(response.size)
            enc_key = proto_to_pointer(enc_key_serialized)
    else:
        enc_key = ctypes.POINTER(ctypes.c_uint8)()
        enc_key_size = ctypes.c_size_t()
        _check_call(_LIB.get_enclave_symm_key(
            c_str(username),
            ctypes.byref(enc_key),
            ctypes.byref(enc_key_size)))


    # Decrypt the key and save it
    try:
        sym_key = _CONF["current_user_sym_key"]
    except:
        raise ValueError("User not found. Please set your username, symmetric key, and public key using `init_user()`")
    c_char_p_key = ctypes.c_char_p(sym_key)
    enclave_symm_key = ctypes.POINTER(ctypes.c_uint8)()

    _check_call(_LIB.decrypt_enclave_key(c_char_p_key, enc_key, enc_key_size, ctypes.byref(enclave_symm_key)))
    _CONF["enclave_sym_key"] = enclave_symm_key


##########################################
# APIs invoked by RPC server
##########################################

class RemoteAPI:
    def get_enclave_symm_key(request):
        enc_key = ctypes.POINTER(ctypes.c_uint8)()
        enc_key_size = ctypes.c_size_t()
        _check_call(_LIB.get_enclave_symm_key(
            c_str(request.username),
            ctypes.byref(enc_key),
            ctypes.byref(enc_key_size)))
        return enc_key, enc_key_size.value

    def get_remote_report_with_pubkey_and_nonce(request):
        pem_key = ctypes.POINTER(ctypes.c_uint)()
        key_size = ctypes.c_size_t()
        remote_report = ctypes.POINTER(ctypes.c_uint)()
        remote_report_size = ctypes.c_size_t()
        nonce = ctypes.POINTER(ctypes.c_uint)()
        nonce_size = ctypes.c_size_t()
        client_list = ctypes.POINTER(ctypes.c_char_p)()
        client_list_size = ctypes.c_size_t()
        _check_call(_LIB.get_remote_report_with_pubkey_and_nonce(
            ctypes.byref(pem_key),
            ctypes.byref(key_size),
            ctypes.byref(nonce),
            ctypes.byref(nonce_size),
            ctypes.byref(client_list),
            ctypes.byref(client_list_size),
            ctypes.byref(remote_report),
            ctypes.byref(remote_report_size)))

        key_size = key_size.value
        nonce_size = nonce_size.value
        remote_report_size = remote_report_size.value
        client_list = from_cstr_to_pystr(client_list, client_list_size)
        client_list_size = client_list_size.value


        pem_key = ctypes2numpy(pem_key, key_size, np.uint32)
        pem_key = ndarray_to_proto(pem_key)
        nonce = ctypes2numpy(nonce, nonce_size, np.uint32)
        nonce = ndarray_to_proto(nonce)
        remote_report = ctypes2numpy(remote_report, remote_report_size, np.uint32)
        remote_report = ndarray_to_proto(remote_report)

        return pem_key, key_size, nonce, nonce_size, client_list, client_list_size, remote_report, remote_report_size


    def add_client_key_with_certificate(request):
        cert_len = len(request.certificate) + 1
        cert = ctypes.c_char_p(str.encode(request.certificate))
        enc_sym_key = proto_to_pointer(request.enc_sym_key)
        enc_sym_key_size = ctypes.c_size_t(request.key_size)
        sig = proto_to_pointer(request.signature)
        sig_size = ctypes.c_size_t(request.sig_len)

        _check_call(_LIB.add_client_key_with_certificate(cert, cert_len, enc_sym_key, enc_sym_key_size, sig, sig_size))


    def XGBoosterPredict(request, signers, signatures, sig_lengths):
        booster_handle = request.params.booster_handle
        dmatrix_handle = request.params.dmatrix_handle
        option_mask = request.params.option_mask
        ntree_limit = request.params.ntree_limit
        training = request.params.training
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)
        
        length = c_bst_ulong()
        preds = ctypes.POINTER(ctypes.c_uint8)()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGBoosterPredict(
            c_str(booster_handle),
            c_str(dmatrix_handle),
            ctypes.c_int(option_mask),
            ctypes.c_uint(ntree_limit),
            ctypes.c_int(training),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(length),
            ctypes.byref(preds),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return preds, length.value, out_sig, out_sig_len.value
        
    def XGBoosterUpdateOneIter(request, signers, signatures, sig_lengths):
        booster_handle = request.params.booster_handle
        dtrain_handle = request.params.dtrain_handle
        iteration = request.params.iteration
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)

        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGBoosterUpdateOneIter(
            c_str(booster_handle),
            ctypes.c_int(iteration),
            c_str(dtrain_handle),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return out_sig, out_sig_len.value

    def XGBoosterCreate(request, signers, signatures, sig_lengths):
        cache = list(request.params.cache)
        length = request.params.length
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths) 

        bst_handle = ctypes.c_char_p()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGBoosterCreate(
            from_pystr_to_cstr(cache),
            c_bst_ulong(length),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(bst_handle),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return bst_handle.value.decode('utf-8'), out_sig, out_sig_len.value


    def XGBoosterSetParam(request, signers, signatures, sig_lengths):
        booster_handle = request.params.booster_handle
        key = request.params.key
        value = request.params.value
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)
        bst_handle = c_str(booster_handle)
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGBoosterSetParam(
            c_str(booster_handle),
            c_str(key),
            c_str(value),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return out_sig, out_sig_len.value

    def XGDMatrixCreateFromEncryptedFile(request, signers, signatures, sig_lengths):
        filenames = list(request.params.filenames)
        usernames = list(request.params.usernames)
        silent = request.params.silent
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)

        dmat_handle = ctypes.c_char_p()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGDMatrixCreateFromEncryptedFile(
            from_pystr_to_cstr(filenames),
            from_pystr_to_cstr(usernames),
            c_bst_ulong(len(filenames)),
            ctypes.c_int(silent),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(dmat_handle),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return dmat_handle.value.decode('utf-8'), out_sig, out_sig_len.value


    def XGBoosterSaveModel(request, signers, signatures, sig_lengths):
        booster_handle = request.params.booster_handle
        filename = request.params.filename
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)

        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGBoosterSaveModel(
            c_str(booster_handle),
            c_str(filename),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return out_sig, out_sig_len.value

    def XGBoosterLoadModel(request, signers, signatures, sig_lengths):
        booster_handle = request.params.booster_handle
        filename = request.params.filename
        username = request.username
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)

        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGBoosterLoadModel(
            c_str(booster_handle),
            c_str(filename),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return out_sig, out_sig_len.value

    # TODO test this
    def XGBoosterDumpModelEx(request, signers, signatures, sig_lengths):
        booster_handle = request.params.booster_handle
        fmap = request.params.fmap
        with_stats = request.params.with_stats
        dump_format = request.params.dump_format
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)
        length = c_bst_ulong()
        sarr = ctypes.POINTER(ctypes.c_char_p)()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGBoosterDumpModelEx(
            c_str(booster_handle),
            c_str(fmap),
            ctypes.c_int(with_stats),
            c_str(dump_format),
            nonce,
            ctypes.c_size_t(nonce_size),
            c_types.c_uint32(nonce_ctr),
            ctypes.byref(length),
            ctypes.byref(sarr),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return length.value, from_cstr_to_pystr(sarr, length), out_sig, out_sig_len.value

    def XGBoosterDumpModelExWithFeatures(request, signers, signatures, sig_lengths):
        booster_handle = request.params.booster_handle
        flen = request.params.flen
        fname = request.params.fname
        ftype = request.params.ftype
        with_stats = request.params.with_stats
        dump_format = request.params.dump_format
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)

        length = c_bst_ulong()
        sarr = ctypes.POINTER(ctypes.c_char_p)()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGBoosterDumpModelExWithFeatures(
            c_str(booster_handle),
            ctypes.c_int(flen),
            from_pystr_to_cstr(list(fname)),
            from_pystr_to_cstr(list(ftype)),
            ctypes.c_int(with_stats),
            c_str(dump_format),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(length),
            ctypes.byref(sarr),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return length.value, from_cstr_to_pystr(sarr, length), out_sig, out_sig_len.value

    # TODO test this
    def XGBoosterGetModelRaw(request, signers, signatures, sig_lengths):
        booster_handle = request.params.booster_handle
        username = request.username
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)

        length = c_bst_ulong()
        sarr = ctypes.POINTER(ctypes.c_char_p)()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGBoosterGetModelRaw(
            c_str(booster_handle),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(length),
            ctypes.byref(sarr),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return length.value, from_cstr_to_pystr(sarr, length), out_sig, out_sig_len.value

    def XGDMatrixNumCol(request, signers, signatures, sig_lengths):
        dmatrix_handle = request.params.name
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)

        ret = c_bst_ulong()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGDMatrixNumCol(
            c_str(dmatrix_handle),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(ret),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            from_pystr_to_cstr(signers),
            c_signatures,
            c_sig_lengths))
        return ret.value, out_sig, out_sig_len.value

    def XGDMatrixNumRow(request, signers, signatures, sig_lengths):
        dmatrix_handle = request.params.name
        nonce = proto_to_pointer(request.seq_num.nonce)
        nonce_size = request.seq_num.nonce_size
        nonce_ctr = request.seq_num.nonce_ctr        
        c_signatures, c_sig_lengths = py2c_sigs(signatures, sig_lengths)

        ret = c_bst_ulong()
        out_sig = ctypes.POINTER(ctypes.c_uint8)()
        out_sig_len = c_bst_ulong()
        _check_call(_LIB.XGDMatrixNumRow(
            c_str(dmatrix_handle),
            nonce,
            ctypes.c_size_t(nonce_size),
            ctypes.c_uint32(nonce_ctr),
            ctypes.byref(ret),
            ctypes.byref(out_sig),
            ctypes.byref(out_sig_len),
            c_signatures,
            c_sig_lengths))
        return ret.value, out_sig, out_sig_len.value


##########################################
# Crypto APIs
##########################################


def generate_client_key(keyfile):
    """
    Generate a new key and save it to ``keyfile``

    Parameters
    ----------
    keyfile : str
        path to which key will be saved
    """
    KEY_BYTES = 32

    key = os.urandom(KEY_BYTES)
    with open(keyfile, "wb") as _keyfile:
        _keyfile.write(key)

def encrypt_file(input_file, output_file, key_file):
    """
    Encrypt a file

    Parameters
    ----------
    input_file : str
        path to file to be encrypted
    output_file : str
        path to which encrypted file will be saved
    key_file : str
        path to key used to encrypt file
    """
    if not os.path.exists(input_file):
        print("Error: File {} does not exist".format(input_file))
        return

    input_file_bytes = input_file.encode('utf-8')
    output_file_bytes = output_file.encode('utf-8')
    key_file_bytes = key_file.encode('utf-8')

    # Convert to proper ctypes
    input_path = ctypes.c_char_p(input_file_bytes)
    output_path = ctypes.c_char_p(output_file_bytes)
    key_path = ctypes.c_char_p(key_file_bytes)

    _check_call(_LIB.encrypt_file(input_path, output_path, key_path))

def encrypt_data_with_pk(data, data_len, pem_key, key_size):
    """
    Parameters
    ----------
    data : byte array
    data_len : int
    pem_key : proto
    key_size : int

    Returns
    -------
    encrypted_data : proto.NDArray
    encrypted_data_size_as_int : int
    """
    # Cast data to char*
    data = ctypes.c_char_p(data)
    data_len = ctypes.c_size_t(data_len)

    # Cast proto to pointer to pass into C++ encrypt_data_with_pk()
    pem_key = proto_to_pointer(pem_key)
    pem_key_len = ctypes.c_size_t(key_size)

    # Allocate memory that will be used to store the encrypted_data and encrypted_data_size
    encrypted_data = np.zeros(1024).ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
    encrypted_data_size = ctypes.c_size_t(1024)

    # Encrypt the data with pk pem_key
    _check_call(_LIB.encrypt_data_with_pk(data, data_len, pem_key, key_size, encrypted_data, ctypes.byref(encrypted_data_size)))

    # Cast the encrypted data back to a proto.NDArray (for RPC purposes) and return it
    encrypted_data_size_as_int = encrypted_data_size.value
    encrypted_data = pointer_to_proto(encrypted_data, encrypted_data_size_as_int)

    return encrypted_data, encrypted_data_size_as_int

def sign_data(key, data, data_size):
    """
    Parameters
    ----------
    keyfile : str
    data : proto.NDArray or str
    data_size : int

    Returns
    -------
    signature : proto.NDArray
    sig_len_as_int : int
    """
    # Cast the keyfile to a char*
    keyfile = ctypes.c_char_p(str.encode(key))

    # Cast data : proto.NDArray to pointer to pass into C++ sign_data() function
    if isinstance(data, str):
        data = c_str(data)
    elif isinstance(data, ctypes.Array) and (data._type_ is ctypes.c_char):
        pass
    else:
        # FIXME error handling for other types
        data = proto_to_pointer(data)

    data_size = ctypes.c_size_t(data_size)

    # Allocate memory to store the signature and sig_len
    signature = np.zeros(1024).ctypes.data_as(ctypes.POINTER(ctypes.c_uint8))
    sig_len = ctypes.c_size_t(1024)

    # Sign data with key keyfile
    _check_call(_LIB.sign_data_with_keyfile(keyfile, data, data_size, signature, ctypes.byref(sig_len)))

    # Cast the signature and sig_len back to a gRPC serializable format
    sig_len_as_int = sig_len.value
    signature = pointer_to_proto(signature, sig_len_as_int, nptype=np.uint8)

    return signature, sig_len_as_int

def verify_enclave_signature(data, size, sig, sig_len, increment_nonce=True):
    """
    Verify the signature returned by the enclave with nonce
    """
    arr = (ctypes.c_char * (size + CIPHER_NONCE_SIZE))()
    add_to_sig_data(arr, data=data, data_size=size)
    add_nonce_to_sig_data(arr, pos=size)
    size = ctypes.c_size_t(len(arr))

    pem_key = _CONF["enclave_pk"]
    pem_key_len = _CONF["enclave_pk_size"]
    # Verify signature
    _check_call(_LIB.verify_signature(pem_key, pem_key_len, arr, size, sig, sig_len))

    if increment_nonce:
        _CONF["nonce_ctr"] += 1


def create_client_signature(args):
    """
    Sign the data for the enclave with nonce
    """
    arr = (ctypes.c_char * (len(args) + CIPHER_NONCE_SIZE))()
    add_to_sig_data(arr, data=args)
    add_nonce_to_sig_data(arr, pos=len(args))
    sig, sig_len = sign_data(_CONF["current_user_priv_key"], arr, len(arr))
    return sig, sig_len

