# Copyright 2015 gRPC authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The Python implementation of the GRPC RemoteAttestation server."""

from concurrent import futures
import logging

import grpc

#  import rpc.remote_pb2
#  import rpc.remote_pb2_grpc
from .rpc import remote_pb2
from .rpc import remote_pb2_grpc
from rpc_utils import *
import os
import sys
import traceback
from .core import RemoteAPI as remote_api

# c_bst_ulong corresponds to bst_ulong defined in xgboost/c_api.h
c_bst_ulong = ctypes.c_uint64


import threading
import types

class Command(object):
    """
    Commands submitted for execution to remote server
    """
    def __init__(self):
        self.reset()

    def reset(self):
        self._func = None
        self._params = None
        self._ret = None
        self._usernames = []
        self._signatures = []
        self._sig_lengths = []
        self._retrieved = []

    def submit(self, func, params, username):
        if self._func is None:
            self._func = func
            self._params = params
        else:
            assert self._func == func
        self._usernames.append(username)
        self._signatures.append(params.signature)
        self._sig_lengths.append(params.sig_len)

    def is_ready(self):
        for user in globals()["all_users"]:
            if user not in self._usernames:
                return False
        return True

    def invoke(self):
        self._ret = self._func(self._params, self._usernames, self._signatures, self._sig_lengths)

    def result(self, username):
        self._retrieved.append(username)
        ret = self._ret
        if self.is_complete():
            self.reset()
        return ret

    def is_complete(self):
        for user in globals()["all_users"]:
            if user not in self._retrieved:
                return False
        return True


def handle_exception():
    e = sys.exc_info()
    print("Error type: " + str(e[0]))
    print("Error value: " + str(e[1]))
    traceback.print_tb(e[2])

    status = remote_pb2.Status(status=-1, exception=str(e[1]))
    return status


class RemoteServicer(remote_pb2_grpc.RemoteServicer):

    def __init__(self, enclave, condition, command):
        self.enclave = enclave
        self.condition = condition
        self.command = command

    def _synchronize(self, func, params):
        username = params.username

        self.condition.acquire() 
        self.command.submit(func, params, username)
        if self.command.is_ready():
            self.command.invoke()
            ret = self.command.result(username)
            self.condition.notifyAll()
        else:
            self.condition.wait()
            ret = self.command.result(username)
        self.condition.release()
        return ret

    def rpc_get_remote_report_with_pubkey(self, request, context):
        """
        Calls get_remote_report_with_pubkey()
        """
        try:
            # Get report from enclave
            pem_key, pem_key_size, remote_report, remote_report_size = remote_api.get_remote_report_with_pubkey(request)

            status = remote_pb2.Status(status=0)
            return remote_pb2.Report(pem_key=pem_key, pem_key_size=pem_key_size, remote_report=remote_report, remote_report_size=remote_report_size, status=status)
        except:
            status = handle_exception()
            return remote_pb2.Report(status=status)

    def rpc_get_remote_report_with_pubkey_and_nonce(self, request, context):
        pem_key, key_size, nonce, nonce_size, remote_report, remote_report_size = remote_api.get_remote_report_with_pubkey_and_nonce(request)

        return remote_pb2.Report(pem_key=pem_key, key_size=key_size,
            nonce=nonce, nonce_size=nonce_size,
            remote_report=remote_report, remote_report_size=remote_report_size)

    # FIXME implement the library call within class RemoteAPI
    def rpc_add_client_key(self, request, context):
        """
        Sends encrypted symmetric key, signature over key, and filename of data that was encrypted using the symmetric key
        """
        try:
            # Get encrypted symmetric key, signature, and filename from request
            enc_sym_key = request.enc_sym_key
            key_size = request.key_size
            signature = request.signature
            sig_len = request.sig_len

            # Get a reference to the existing enclave
            result = self.enclave._add_client_key(enc_sym_key, key_size, signature, sig_len)

            return remote_pb2.Status(status=result)
        except:
            status = handle_exception()
            return status

    # FIXME implement the library call within class RemoteAPI
    def rpc_add_client_key_with_certificate(self, request, context):
        """
        Calls add_client_key_with_certificate()
        """
        try:
            # Get encrypted symmetric key, signature, and certificate from request
            certificate = request.certificate
            enc_sym_key = request.enc_sym_key
            key_size = request.key_size
            signature = request.signature
            sig_len = request.sig_len

            # Get a reference to the existing enclave
            result = self.enclave._add_client_key_with_certificate(certificate, enc_sym_key, key_size, signature, sig_len)

            return remote_pb2.Status(status=result)
        except:
            status = handle_exception()
            return status

    def rpc_get_enclave_symm_key(self, request, context):
        """
        Calls get_remote_report_with_pubkey()
        """
        try:
            # Get report from enclave
            enc_key, enc_key_size = remote_api.get_enclave_symm_key(request)
            enc_key_proto = pointer_to_proto(enc_key, enc_key_size + CIPHER_IV_SIZE + CIPHER_TAG_SIZE)

            status = remote_pb2.Status(status=0)
            return remote_pb2.EnclaveKey(key=enc_key_proto, size=enc_key_size, status=status)
        except:
            status = handle_exception()
            return remote_pb2.Report(status=status)

    def rpc_XGDMatrixCreateFromEncryptedFile(self, request, context):
        """
        Create DMatrix from encrypted file
        """
        try:
            dmatrix_handle = self._synchronize(remote_api.XGDMatrixCreateFromEncryptedFile, request)
            status = remote_pb2.Status(status=0)
            return remote_pb2.Name(name=dmatrix_handle, status=status)
        except:
            status = handle_exception()
            return remote_pb2.Name(name=None, status=status)

    def rpc_XGBoosterSetParam(self, request, context):
        """
        Set booster parameter
        """
        try:
            _ = self._synchronize(remote_api.XGBoosterSetParam, request)
            return remote_pb2.Status(status=0)
        except:
            status = handle_exception()
            return status

    def rpc_XGBoosterCreate(self, request, context):
        """
        Create a booster
        """
        try:
            booster_handle = self._synchronize(remote_api.XGBoosterCreate, request)
            status = remote_pb2.Status(status=0)
            return remote_pb2.Name(name=booster_handle, status=status)
        except:
            status = handle_exception()
            return remote_pb2.Name(status=status)

    def rpc_XGBoosterUpdateOneIter(self, request, context):
        """
        Update model for one iteration
        """
        try:
            _ = self._synchronize(remote_api.XGBoosterUpdateOneIter, request)
            return remote_pb2.Status(status=0)
        except:
            status = handle_exception()
            return status

    def rpc_XGBoosterPredict(self, request, context):
        """
        Get encrypted predictions
        """
        try:
            enc_preds, num_preds = self._synchronize(remote_api.XGBoosterPredict, request)
            enc_preds_proto = pointer_to_proto(enc_preds, num_preds * ctypes.sizeof(ctypes.c_float) + CIPHER_IV_SIZE + CIPHER_TAG_SIZE)
            status = remote_pb2.Status(status=0)
            return remote_pb2.Predictions(predictions=enc_preds_proto, num_preds=num_preds, status=status)

        except:
            status = handle_exception()
            return remote_pb2.Predictions(status=status)

    def rpc_XGBoosterSaveModel(self, request, context):
        """
        Save model to encrypted file
        """
        try:
            _ = self._synchronize(remote_api.XGBoosterSaveModel, request)
            return remote_pb2.Status(status=0)

        except:
            status = handle_exception()
            return status

    def rpc_XGBoosterLoadModel(self, request, context):
        """
        Load model from encrypted file
        """
        try:
            _ = self._synchronize(remote_api.XGBoosterLoadModel, request)
            return remote_pb2.Status(status=0)

        except:
            status = handle_exception()
            return status

    def rpc_XGBoosterDumpModelEx(self, request, context):
        """
        Get encrypted model dump
        """
        try:
            length, sarr = self._synchronize(remote_api.XGBoosterDumpModelEx, request)
            status = remote_pb2.Status(status=0)
            return remote_pb2.Dump(sarr=sarr, length=length, status=status)

        except:
            status = handle_exception()
            return remote_pb2.Dump(status=status)

    def rpc_XGBoosterDumpModelExWithFeatures(self, request, context):
        """
        Get encrypted model dump with features
        """
        try:
            length, sarr = self._synchronize(remote_api.XGBoosterDumpModelExWithFeatures, request)
            status = remote_pb2.Status(status=0)
            return remote_pb2.Dump(sarr=sarr, length=length, status=status)

        except:
            status = handle_exception()
            return remote_pb2.Dump(status=status)

    def rpc_XGBoosterGetModelRaw(self, request, context):
        """
        Get encrypted raw model dump
        """
        try:
            length, sarr = self._synchronize(remote_api.XGBoosterGetModelRaw, request)
            status = remote_pb2.Status(status=0)
            return remote_pb2.Dump(sarr=sarr, length=length, status=status)

        except:
            status = handle_exception()
            return remote_pb2.Dump(status=status)

    def rpc_XGDMatrixNumCol(self, request, context):
        """
        Get number of columns in DMatrix
        """
        try:
            ret = self._synchronize(remote_api.XGDMatrixNumCol, request)
            status = remote_pb2.Status(status=0)
            return remote_pb2.Integer(value=ret, status=status)

        except:
            status = handle_exception()
            return remote_pb2.Integer(status=status)

    def rpc_XGDMatrixNumRow(self, request, context):
        """
        Get number of rows in DMatrix
        """
        try:
            ret = self._synchronize(remote_api.XGDMatrixNumRow, request)
            status = remote_pb2.Status(status=0)
            return remote_pb2.Integer(value=ret, status=status)

        except:
            status = handle_exception()
            return remote_pb2.Integer(status=status)

def serve(enclave, num_workers=10, all_users=[]):
    condition = threading.Condition()
    command = Command()
    globals()["all_users"] = all_users

    rpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=num_workers))
    remote_pb2_grpc.add_RemoteServicer_to_server(RemoteServicer(enclave, condition, command), rpc_server)
    rpc_server.add_insecure_port('[::]:50051')
    rpc_server.start()
    rpc_server.wait_for_termination()

