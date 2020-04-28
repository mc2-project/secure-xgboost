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
import numpy as np
from .core import RemoteAPI as server

# c_bst_ulong corresponds to bst_ulong defined in xgboost/c_api.h
c_bst_ulong = ctypes.c_uint64

class RemoteServicer(remote_pb2_grpc.RemoteServicer):

    def __init__(self, enclave):
        self.enclave = enclave

    # FIXME implement the library call within class RemoteAPI
    def rpc_get_remote_report_with_pubkey(self, request, context):
        """
        Calls get_remote_report_with_public_key()
        """
        # Get report from enclave
        pem_key, key_size, remote_report, remote_report_size = self.enclave.get_report()

        return remote_pb2.Report(pem_key=pem_key, key_size=key_size, remote_report=remote_report, remote_report_size=remote_report_size)

    # FIXME implement the library call within class RemoteAPI
    def rpc_add_client_key(self, request, context):
        """
        Sends encrypted symmetric key, signature over key, and filename of data that was encrypted using the symmetric key
        """
        # Get encrypted symmetric key, signature, and filename from request
        enc_sym_key = request.enc_sym_key
        key_size = request.key_size
        signature = request.signature
        sig_len = request.sig_len

        # Get a reference to the existing enclave
        result = self.enclave._add_client_key(enc_sym_key, key_size, signature, sig_len)

        return remote_pb2.Status(status=result)

    # FIXME implement the library call within class RemoteAPI
    def rpc_add_client_key_with_certificate(self, request, context):
        """
        Calls add_client_key_with_certificate()
        """
        # Get encrypted symmetric key, signature, and certificate from request
        certificate = request.certificate
        enc_sym_key = request.enc_sym_key
        key_size = request.key_size
        signature = request.signature
        sig_len = request.sig_len

        # Get a reference to the existing enclave
        result = self.enclave._add_client_key_with_certificate(certificate, enc_sym_key, key_size, signature, sig_len)

        return remote_pb2.Status(status=result)

    def rpc_XGDMatrixCreateFromEncryptedFile(self, request, context):
        """
        Create DMatrix from encrypted file
        """
        try:
            dmatrix_handle = server.XGDMatrixCreateFromEncryptedFile(
                    filenames=list(request.filenames),
                    usernames=list(request.usernames),
                    silent=request.silent)
            return remote_pb2.Name(name=dmatrix_handle)
        except:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Name(name=None)

    def rpc_XGBoosterSetParam(self, request, context):
        """
        Set booster parameter
        """
        try:
            server.XGBoosterSetParam(
                    booster_handle=request.booster_handle,
                    key=request.key,
                    value=request.value)
            return remote_pb2.Status(status=0)
        except:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Status(status=-1)

    def rpc_XGBoosterCreate(self, request, context):
        """
        Create a booster
        """
        try:
            booster_handle = server.XGBoosterCreate(
                            cache=list(request.cache),
                            length=request.length)
            return remote_pb2.Name(name=booster_handle)
        except:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])
    
            return remote_pb2.Name(name=None)

    def rpc_XGBoosterUpdateOneIter(self, request, context):
        """
        Update model for one iteration
        """
        try:
            server.XGBoosterUpdateOneIter(request.booster_handle,
                    request.dtrain_handle,
                    request.iteration)
            return remote_pb2.Status(status=0)
        except:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Status(status=-1)

    def rpc_XGBoosterPredict(self, request, context):
        """
        Get encrypted predictions
        """
        try:
            enc_preds, num_preds = server.XGBoosterPredict(request.booster_handle,
                    request.dmatrix_handle,
                    request.option_mask,
                    request.ntree_limit,
                    request.username)
            enc_preds_proto = pointer_to_proto(enc_preds, num_preds * ctypes.sizeof(ctypes.c_float) + CIPHER_IV_SIZE + CIPHER_TAG_SIZE)
            return remote_pb2.Predictions(predictions=enc_preds_proto, num_preds=num_preds, status=0)

        except Exception as e:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Predictions(predictions=None, num_preds=None, status=-1)

    def rpc_XGBoosterSaveModel(self, request, context):
        """
        Save model to encrypted file
        """
        try:
            server.XGBoosterSaveModel(request.booster_handle,
                    request.filename,
                    request.username)
            return remote_pb2.Status(status=0)

        except Exception as e:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Status(status=-1)

    def rpc_XGBoosterLoadModel(self, request, context):
        """
        Load model from encrypted file
        """
        try:
            server.XGBoosterLoadModel(request.booster_handle,
                    request.filename,
                    request.username)
            return remote_pb2.Status(status=0)

        except Exception as e:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Status(status=-1)

    def rpc_XGBoosterDumpModelEx(self, request, context):
        """
        Get encrypted model dump
        """
        try:
            length, sarr = server.XGBoosterDumpModelEx(request.booster_handle,
                    request.fmap,
                    request.with_stats,
                    request.dump_format)
            return remote_pb2.Dump(sarr=sarr, length=length, status=0)

        except Exception as e:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Dump(sarr=None, length=None, status=-1)

    def rpc_XGBoosterDumpModelExWithFeatures(self, request, context):
        """
        Get encrypted model dump with features
        """
        try:
            length, sarr = server.XGBoosterDumpModelExWithFeatures(request.booster_handle,
                    request.flen,
                    request.fname,
                    request.ftype,
                    request.with_stats,
                    request.dump_format)
            return remote_pb2.Dump(sarr=sarr, length=length, status=0)

        except Exception as e:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Dump(sarr=None, length=None, status=-1)

    def rpc_XGBoosterGetModelRaw(self, request, context):
        """
        Get encrypted raw model dump
        """
        try:
            length, sarr = server.XGBoosterGetModelRaw(request.booster_handle,
                    request.username)
            return remote_pb2.Dump(sarr=sarr, length=length, status=0)

        except Exception as e:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Dump(sarr=None, length=None, status=-1)

    def rpc_XGDMatrixNumCol(self, request, context):
        """
        Get number of columns in DMatrix
        """
        try:
            ret = server.XGDMatrixNumCol(request.name)
            return remote_pb2.Integer(value=ret)

        except Exception as e:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Integer(value=None)

    def rpc_XGDMatrixNumRow(self, request, context):
        """
        Get number of rows in DMatrix
        """
        try:
            ret = server.XGDMatrixNumRow(request.dmatrix_handle)
            return remote_pb2.Integer(value=ret)

        except Exception as e:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_pb2.Integer(value=None)

def serve(enclave):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    remote_pb2_grpc.add_RemoteServicer_to_server(RemoteServicer(enclave), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

