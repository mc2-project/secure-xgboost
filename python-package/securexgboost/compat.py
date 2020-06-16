# coding: utf-8
# pylint: disable= invalid-name,  unused-import
"""For compatibility"""

from __future__ import absolute_import

import sys


PY3 = (sys.version_info[0] == 3)

if PY3:
    # pylint: disable=invalid-name, redefined-builtin
    STRING_TYPES = (str,)

    def py_str(x):
        """convert c string back to python string"""
        return x.decode('utf-8')
else:
    STRING_TYPES = (basestring,)  # pylint: disable=undefined-variable

    def py_str(x):
        """convert c string back to python string"""
        return x

try:
    import cPickle as pickle   # noqa
except ImportError:
    import pickle              # noqa


# pandas
try:
    from pandas import DataFrame
    from pandas import MultiIndex
    PANDAS_INSTALLED = True
except ImportError:

    # pylint: disable=too-few-public-methods
    class MultiIndex(object):
        """ dummy for pandas.MultiIndex """

    # pylint: disable=too-few-public-methods
    class DataFrame(object):
        """ dummy for pandas.DataFrame """

    PANDAS_INSTALLED = False

# dt
try:
    import datatable
    if hasattr(datatable, "Frame"):
        DataTable = datatable.Frame
    else:
        DataTable = datatable.DataTable
    DT_INSTALLED = True
except ImportError:

    # pylint: disable=too-few-public-methods
    class DataTable(object):
        """ dummy for datatable.DataTable """

    DT_INSTALLED = False

# cudf
try:
    from cudf import DataFrame as CUDF_DataFrame
    from cudf import Series as CUDF_Series
    from cudf import MultiIndex as CUDF_MultiIndex
    from cudf import concat as CUDF_concat
    CUDF_INSTALLED = True
except ImportError:
    CUDF_DataFrame = object
    CUDF_Series = object
    CUDF_MultiIndex = object
    CUDF_INSTALLED = False
    CUDF_concat = None

# sklearn
try:
    from sklearn.base import BaseEstimator
    from sklearn.base import RegressorMixin, ClassifierMixin
    from sklearn.preprocessing import LabelEncoder
    try:
        from sklearn.model_selection import KFold, StratifiedKFold
    except ImportError:
        from sklearn.cross_validation import KFold, StratifiedKFold

    SKLEARN_INSTALLED = True

    XGBModelBase = BaseEstimator
    XGBRegressorBase = RegressorMixin
    XGBClassifierBase = ClassifierMixin

    XGBKFold = KFold
    XGBStratifiedKFold = StratifiedKFold
    XGBLabelEncoder = LabelEncoder
except ImportError:
    SKLEARN_INSTALLED = False

    # used for compatibility without sklearn
    XGBModelBase = object
    XGBClassifierBase = object
    XGBRegressorBase = object

    XGBKFold = None
    XGBStratifiedKFold = None
    XGBLabelEncoder = None

# dask
try:
    import dask
    from dask import delayed
    from dask import dataframe as dd
    from dask import array as da
    from dask.distributed import Client, get_client
    from dask.distributed import comm as distributed_comm
    from dask.distributed import wait as distributed_wait
    from distributed import get_worker as distributed_get_worker

    DASK_INSTALLED = True
except ImportError:
    dd = None
    da = None
    Client = None
    delayed = None
    get_client = None
    distributed_comm = None
    distributed_wait = None
    distributed_get_worker = None
    dask = None

    DASK_INSTALLED = False

