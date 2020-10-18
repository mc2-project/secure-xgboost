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
from .rabit import RemoteAPI as rabit_remote_api

# c_bst_ulong corresponds to bst_ulong defined in xgboost/c_api.h
c_bst_ulong = ctypes.c_uint64

import threading
import types

_USERS = []

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
        self._seq_num = None
        self._usernames = []
        self._signatures = []
        self._sig_lengths = []
        self._retrieved = []
        self._error = None

    def submit(self, func, params, username):
        if self._func is None:
            self._func = func
            self._params = params
            self._seq_num = params.seq_num
        elif self._func != func:
            self.reset()
            self._error = "Mismatched commands. Please resubmit the command, and ensure each party submits the same command."
            raise Exception(self._error)
        elif self._seq_num != params.seq_num:
            self.reset()
            self._error = "Mismatched command sequence number. Please reset all clients and the server."
            raise Exception(self._error)

        # If a party re-submits the same command, then update its parameters
        if username in self._usernames:
            index = self._usernames.index(username)
            self._signatures[index] = params.signature
            self._sig_lengths[index] = params.sig_len
        else:
            self._usernames.append(username)
            self._signatures.append(params.signature)
            self._sig_lengths.append(params.sig_len)

    def is_ready(self):
        for user in _USERS:
            if user not in self._usernames:
                return False
        return True

    def invoke(self):
        if not globals()["is_orchestrator"]:
            # Returns <return_value>, signature, sig_len
            self._ret = self._func(self._params, self._usernames, self._signatures, self._sig_lengths)
        else: # We're the RPC orchestrator
            node_ips = globals()["nodes"]
            seq_num = self._seq_num
            signers = self._usernames
            signatures = self._signatures
            sig_lengths = self._sig_lengths
            channels = []
            for channel_addr in node_ips:
                channels.append(grpc.insecure_channel(channel_addr))
        
            # Store futures in a list
            # Futures hold the result of asynchronous calls to each gRPC server
            futures = []
        
            for channel in channels:
                stub = remote_pb2_grpc.RemoteStub(channel)
        
                # Asynchronous calls to start job on each node
                if self._func == rabit_remote_api.RabitInit:
                    response_future = stub.rpc_RabitInit.future(remote_pb2.RabitParams(
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == rabit_remote_api.RabitFinalize:
                    response_future = stub.rpc_RabitFinalize.future(remote_pb2.RabitParams(
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGDMatrixCreateFromEncryptedFile:
                    dmatrix_attrs = self._params.attrs
                    response_future = stub.rpc_XGDMatrixCreateFromEncryptedFile.future(remote_pb2.DMatrixAttrsRequest(
                        attrs=dmatrix_attrs,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths,
                        ))
                elif self._func == remote_api.XGBoosterSetParam:
                    booster_param = self._params.booster_param
                    response_future = stub.rpc_XGBoosterSetParam.future(remote_pb2.BoosterParamRequest(
                        booster_param=booster_param,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGBoosterCreate:
                    attrs = self._params.attrs
                    response_future = stub.rpc_XGBoosterCreate.future(remote_pb2.BoosterAttrsRequest(
                        attrs=attrs,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGBoosterUpdateOneIter:
                    booster_update_params = self._params.booster_update_params
                    response_future = stub.rpc_XGBoosterUpdateOneIter.future(remote_pb2.BoosterUpdateParamsRequest(
                        booster_update_params = booster_update_params,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGBoosterSaveModel:
                    save_model_params = self._params.save_model_params
                    response_future = stub.rpc_XGBoosterSaveModel.future(remote_pb2.SaveModelParamsRequest(
                        save_model_params = save_model_params,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGBoosterLoadModel:
                    load_model_params = self._params.load_model_params
                    response_future = stub.rpc_XGBoosterLoadModel.future(remote_pb2.LoadModelParamsRequest(
                        load_model_params=load_model_params,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGBoosterDumpModelEx:
                    dump_model_params = self._params.dump_model_params 
                    response_future = stub.rpc_XGBoosterDumpModelEx.future(remote_pb2.DumpModelParamsRequest(
                        dump_model_params=dump_model_params,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGBoosterDumpModelExWithFeatures:
                    dump_model_with_features_params = self._params.dump_model_with_features_params
                    response_future = stub.rpc_XGBoosterDumpModelExWithFeatures.future(remote_pb2.DumpModelWithFeaturesParamsRequest(
                        dump_model_with_features_params=dump_model_with_features_params,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGBoosterGetModelRaw:
                    model_raw_params = self._params.model_raw_params
                    response_future = stub.rpc_XGBoosterGetModelRaw.future(remote_pb2.ModelRawParamsRequest(
                        model_raw_params=model_raw_params,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGDMatrixNumRow:
                    name = self._params.name
                    response_future = stub.rpc_XGDMatrixNumRow.future(remote_pb2.NumRowRequest(
                        name=name,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGDMatrixNumCol:
                    name = self._params.name
                    response_future = stub.rpc_XGDMatrixNumCol.future(remote_pb2.NumColRequest(
                        name=name,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                elif self._func == remote_api.XGBoosterPredict:
                    predict_params = self._params.predict_params
                    response_future = stub.rpc_XGBoosterPredict.future(remote_pb2.PredictParamsRequest(
                        predict_params=predict_params,
                        seq_num=seq_num,
                        signers=signers,
                        signatures=signatures,
                        sig_lengths=sig_lengths
                        ))
                futures.append(response_future)
        
            results = []
            for future in futures:
                results.append(future.result())

            statuses = [result.status.status for result in results]
            
            # Check for error
            error = False
            exception = None
            if -1 in statuses:
                exceptions = [result.status.exception for result in results]
                error = True
                i = statuses.index(-1)
                exception = exceptions[i]

            # Collect all signatures
            master_signature = None
            master_sig_len = None

            if self._func != remote_api.XGBoosterPredict:
                sig_protos = []
                sig_lens = []
                for result in results:
                    sig_protos.append(result.signature)
                    sig_lens.append(result.sig_len)

                # If we return only one signature, return the signature from the master enclave
                master_signature = sig_protos[0]
                master_sig_len = sig_lens[0]
                
            # Set return value
            if self._func == rabit_remote_api.RabitInit:
                if error:
                    self._ret = remote_pb2.Status(status=-1, exception=exception)
                else:
                    # FIXME: add signatures
                    self._ret = remote_pb2.Status(status=0)
            elif self._func == rabit_remote_api.RabitFinalize:
                if error:
                    self._ret = remote_pb2.Status(status=-1, exception=exception)
                else:
                    # FIXME: add signatures
                    self._ret = remote_pb2.Status(status=0)
            elif self._func == remote_api.XGDMatrixCreateFromEncryptedFile:
                if error:
                    self._ret = (None, None, None, remote_pb2.Status(status=-1, exception=exception)) 
                else:
                    dmatrix_handles = [result.name for result in results]
                    if dmatrix_handles.count(dmatrix_handles[0]) == len(dmatrix_handles):
                        # Every enclave returned the same handle string
                        self._ret = (dmatrix_handles[0], master_signature, master_sig_len, remote_pb2.Status(status=0))
                    else:
                        self._ret = (None, None, None, remote_pb2.Status(status=-1, exception="ERROR: Inconsistent dmatrix handles returned by enclaves in XGDMatrixCreateFromEncryptedFile call"))
            elif self._func == remote_api.XGBoosterSetParam:
                if error:
                    self._ret = (None, None, remote_pb2.Status(status=-1, exception=exception))
                else:
                    self._ret = (master_signature, master_sig_len, remote_pb2.Status(status=0))
            elif self._func == remote_api.XGBoosterCreate:
                if error:
                    self._ret = (None, None, None, remote_pb2.Status(status=-1, exception=exception)) 
                else:
                    bst_handles = [result.name for result in results]
                    if bst_handles.count(bst_handles[0]) == len(bst_handles):
                        # Every enclave returned the same booster handle string
                        self._ret = (bst_handles[0], master_signature, master_sig_len, remote_pb2.Status(status=0))
                    else:
                        self._ret = (None, None, None, remote_pb2.Status(status=-1, exception="ERROR: Inconsistent booster handles returned by enclaves in XGBoosterCreate call"))
            elif self._func == remote_api.XGBoosterUpdateOneIter:
                if error:
                    self._ret = (None, None, remote_pb2.Status(status=-1, exception=exception))
                else:
                    self._ret = (master_signature, master_sig_len, remote_pb2.Status(status=0))
            elif self._func == remote_api.XGBoosterSaveModel:
                if error:
                    self._ret = (None, None, remote_pb2.Status(status=-1, exception=exception))
                else:
                    self._ret = (master_signature, master_sig_len, remote_pb2.Status(status=0))
            elif self._func == remote_api.XGBoosterLoadModel:
                if error:
                    self._ret = (None, None, remote_pb2.Status(status=-1, exception=exception))
                else:
                    self._ret = (master_signature, master_sig_len, remote_pb2.Status(status=0))
            elif self._func == remote_api.XGBoosterDumpModelEx:
                if error:
                    self._ret = (None, None, None, None, remote_pb2.Status(status=-1, exception=exception)) 
                else:
                    sarrs = [result.sarr for result in results]
                    lengths = [result.length for result in results]
                    if lengths.count(lengths[0]) == len(lengths):
                        # Every enclave returned the same length
                        # We cannot check if the dumps are the same because they are encrypted
                        self._ret = (lengths[0], sarrs[0], master_signature, master_sig_len, remote_pb2.Status(status=0))
                    else:
                        self._ret = (None, None, None, None, remote_pb2.Status(status=-1, exception="ERROR: Inconsistent results from enclaves in XGBoosterDumpModelEx call"))
            elif self._func == remote_api.XGBoosterDumpModelExWithFeatures:
                if error:
                    self._ret = (None, None, None, None, remote_pb2.Status(status=-1, exception=exceptions)) 
                else:
                    sarrs = [result.sarr for result in results]
                    lengths = [result.length for result in results]
                    if lengths.count(lengths[0]) == len(lengths):
                        # Every enclave returned the same length
                        # We cannot check if the dumps are the same because they are encrypted
                        self._ret = (lengths[0], sarrs[0], master_signature, master_sig_len, remote_pb2.Status(status=0))
                    else:
                        self._ret = (None, None, None, None, remote_pb2.Status(status=-1, exception="ERROR: Inconsistent results from enclaves in XGBoosterDumpModelExWithFeatures call"))
            elif self._func == remote_api.XGBoosterGetModelRaw:
                if error:
                    self._ret = (None, None, None, None, remote_pb2.Status(status=-1, exception=exceptions)) 
                else:
                    sarrs = [result.sarr for result in results]
                    lengths = [result.length for result in results]
                    if lengths.count(lengths[0]) == len(lengths):
                        # Every enclave returned the same length
                        # We cannot check if the dumps are the same because they are encrypted
                        self._ret = (lengths[0], sarrs[0], master_signature, master_sig_len, remote_pb2.Status(status=0))
                    else:
                        self._ret = (None, None, None, None, remote_pb2.Status(status=-1, exception="ERROR: Inconsistent results from enclaves in XGBoosterGetModelRaw call"))
            elif self._func == remote_api.XGDMatrixNumRow:
                if error:
                    self._ret = (None, None, None, remote_pb2.Status(status=-1, exception=exception)) 
                else:
                    num_rows = [result.value for result in results]
                    if num_rows.count(num_rows[0]) == len(num_rows):
                        # Each enclave agrees on the number of rows in the DMatrix
                        self._ret = (num_rows[0], master_signature, master_sig_len, remote_pb2.Status(status=0))
                    else:
                        self._ret = (None, None, None, remote_pb2.Status(status=-1, exception="ERROR: Inconsistent numbers from enclaves in XGDMatrixNumRow call")) 
            elif self._func == remote_api.XGDMatrixNumCol:
                if error:
                    self._ret = (None, None, None, remote_pb2.Status(status=-1, exception=exception)) 
                else:
                    num_cols = [result.value for result in results]
                    if num_cols.count(num_cols[0]) == len(num_cols):
                        # Each enclave agrees on the number of columns in the DMatrix
                        self._ret = (num_cols[0], master_signature, master_sig_len, remote_pb2.Status(status=0))
                    else:
                        self._ret = (None, None, None, remote_pb2.Status(status=-1, exception="ERROR: Inconsistent numbers from enclaves in XGDMatrixNumCol call"))
            elif self._func == remote_api.XGBoosterPredict:
                if error: 
                    self._ret = (None, None, None, None, remote_pb2.Status(status=-1, exception=exception)) 
                else:
                    enc_preds_ret = []
                    num_preds_ret = []
                    sig_protos_ret = []
                    sig_lens_ret = []

                    for result in results:
                        # Collect encrypted predictions
                        enc_preds_ret.extend(result.predictions)
                        num_preds_ret.extend(result.num_preds)

                        # Collect signatures
                        sig_protos_ret.extend(result.signatures)
                        sig_lens_ret.extend(result.sig_lens)
                        
                    if len(enc_preds_ret) == len(num_preds_ret):
                        self._ret = (enc_preds_ret, num_preds_ret, sig_protos_ret, sig_lens_ret, remote_pb2.Status(status=0))
                    else:
                        self._ret = (None, None, None, None, remote_pb2.Status(status=-1, exception="ERROR: Inconsistent results in XGBoosterPredict call"))
            else:
                raise NotImplementedError

    def result(self, username):
        if self._error:
            raise Exception(self._error)
        self._retrieved.append(username)
        ret = self._ret
        if self.is_complete():
            self.reset()
        return ret

    def is_complete(self):
        for user in _USERS:
            if user not in self._retrieved:
                return False
        return True


def handle_exception():
    e = sys.exc_info()
    print("Error type: " + str(e[0]))
    print("Error value: " + str(e[1]))
    traceback.print_tb(e[2])

    return remote_pb2.Status(status=-1, exception=str(e[1]))


class RemoteServicer(remote_pb2_grpc.RemoteServicer):

    def __init__(self, condition, command):
        self.condition = condition
        self.command = command

    def _synchronize(self, func, params):
        username = params.username

        self.condition.acquire() 
        try:
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
        except:
            self.condition.notifyAll()
            self.condition.release()
            raise Exception(self.command._error)

    def _serialize(self, func, params):
        self.condition.acquire() 
        ret = func(params) 
        self.condition.release()
        return ret

    def rpc_get_remote_report_with_pubkey_and_nonce(self, request, context):
        try:
            if not globals()["is_orchestrator"]:
                pem_key, key_size, nonce, nonce_size, remote_report, remote_report_size = self._serialize(remote_api.get_remote_report_with_pubkey_and_nonce, request)
                return remote_pb2.Report(pem_key=pem_key, pem_key_size=key_size,
                    nonce=nonce, nonce_size=nonce_size,
                    remote_report=remote_report, remote_report_size=remote_report_size)
            else:
                node_ips = globals()["nodes"]
                master_enclave_ip = node_ips[0]
                with grpc.insecure_channel(master_enclave_ip) as channel:
                    stub = remote_pb2_grpc.RemoteStub(channel)
                    response = stub.rpc_get_remote_report_with_pubkey_and_nonce(remote_pb2.Status(status=0))

                return response
        except:
            status = handle_exception()
            return remote_pb2.Report(status=status)

    def rpc_add_client_key_with_certificate(self, request, context):
        """
        Calls add_client_key_with_certificate()
        """
        try:
            certificate = request.certificate
            enc_sym_key = request.enc_sym_key
            key_size = request.key_size
            signature = request.signature
            sig_len = request.sig_len

            # Get encrypted symmetric key, signature, and certificate from request
            if not globals()["is_orchestrator"]:
                # Get a reference to the existing enclave
                self._serialize(remote_api.add_client_key_with_certificate, request)
                # self.enclave._add_client_key_with_certificate(certificate, enc_sym_key, key_size, signature, sig_len)
                status = remote_pb2.Status(status=0)
                return remote_pb2.StatusMsg(status=status)
            else:
                node_ips = globals()["nodes"]
                channels = []
                for channel_addr in node_ips:
                    channels.append(grpc.insecure_channel(channel_addr))

                futures = []
                for channel in channels:
                    stub = remote_pb2_grpc.RemoteStub(channel)
                    # The transmitted data is encrypted with the public key of rank 0 enclave
                    response_future = stub.rpc_add_client_key_with_certificate.future(remote_pb2.DataMetadata(
                        certificate=certificate,
                        enc_sym_key=enc_sym_key,
                        key_size=key_size,
                        signature=signature,
                        sig_len=sig_len))

                    futures.append(response_future)

                results = []
                for future in futures:
                    results.append(future.result())

                return_codes = [result.status.status for result in results]
                if sum(return_codes) == 0:
                    status = remote_pb2.Status(status=0)
                    return remote_pb2.StatusMsg(status=status)
                else:
                    error_status = remote_pb2.Status(status=-1, exception="ERROR: A node threw an error trying to add the client key and certificate")
                    return remote_pb2.StatusMsg(status=error_status)
        except:
            status = handle_exception()
            return remote_pb2.StatusMsg(status=status)

    def rpc_get_enclave_symm_key(self, request, context):
        """
        Get enclave symmetric key 
        """
        try:
            username = request.username

            if not globals()["is_orchestrator"]:
                # Get symmetric key from enclave
                enc_key, enc_key_size = self._serialize(remote_api.get_enclave_symm_key, request)
                enc_key_proto = pointer_to_proto(enc_key, enc_key_size + CIPHER_IV_SIZE + CIPHER_TAG_SIZE)

                status = remote_pb2.Status(status=0)
                return remote_pb2.EnclaveKey(key=enc_key_proto, size=enc_key_size, status=status)
            else:
                node_ips = globals()["nodes"]
                master_enclave_ip = node_ips[0]
                with grpc.insecure_channel(master_enclave_ip) as channel:
                    stub = remote_pb2_grpc.RemoteStub(channel)
                    response = stub.rpc_get_enclave_symm_key(remote_pb2.Name(username=username))

                return response

        except:
            status = handle_exception()
            return remote_pb2.EnclaveKey(status=status)

    def rpc_XGDMatrixCreateFromEncryptedFile(self, request, context):
        """
        Create DMatrix from encrypted file
        """
        try:
            if globals()["is_orchestrator"]:
                dmatrix_handle, sig_proto, sig_len, status = self._synchronize(remote_api.XGDMatrixCreateFromEncryptedFile, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                dmatrix_handle, sig, sig_len = remote_api.XGDMatrixCreateFromEncryptedFile(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.Name(name=dmatrix_handle, signature=sig_proto, sig_len=sig_len, status=status)
        except:
            status = handle_exception()
            return remote_pb2.Name(name=None, status=status)

    def rpc_XGBoosterSetParam(self, request, context):
        """
        Set booster parameter
        """
        try:
            if globals()["is_orchestrator"]:
                sig_proto, sig_len, status = self._synchronize(remote_api.XGBoosterSetParam, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                sig, sig_len = remote_api.XGBoosterSetParam(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.StatusMsg(status=status, signature=sig_proto, sig_len=sig_len)
        except:
            status = handle_exception()
            return remote_pb2.StatusMsg(status=status)

    def rpc_XGBoosterCreate(self, request, context):
        """
        Create a booster
        """
        try:
            if globals()["is_orchestrator"]:
                booster_handle, sig_proto, sig_len, status = self._synchronize(remote_api.XGBoosterCreate, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                booster_handle, sig, sig_len = remote_api.XGBoosterCreate(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.Name(name=booster_handle, status=status, signature=sig_proto, sig_len=sig_len)
        except:
            status = handle_exception()
            return remote_pb2.Name(status=status)

    def rpc_XGBoosterUpdateOneIter(self, request, context):
        """
        Update model for one iteration
        """
        try:
            if globals()["is_orchestrator"]:
                sig_proto, sig_len, status = self._synchronize(remote_api.XGBoosterUpdateOneIter, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                sig, sig_len = remote_api.XGBoosterUpdateOneIter(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.StatusMsg(status=status, signature=sig_proto, sig_len=sig_len)
        except:
            status = handle_exception()
            return remote_pb2.StatusMsg(status=status)

    def rpc_XGBoosterPredict(self, request, context):
        """
        Get encrypted predictions
        """
        try:
            enc_preds_list, num_preds_list = [], []
            if globals()["is_orchestrator"]:
                # With a cluster, we'll obtain a set of predictions for each node in the cluster
                # If we're the orchestrator, this list should already be in proto form
                enc_preds_proto_list, num_preds_list, sig_proto_list, sig_len_list, status = self._synchronize(remote_api.XGBoosterPredict, request)
            else:
                # If we're not the orchestrator, we're just running this on our partition of the data
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                enc_preds, num_preds, sig, sig_len = remote_api.XGBoosterPredict(request, signers, signatures, sig_lengths)
                enc_preds_proto = pointer_to_proto(enc_preds, num_preds * ctypes.sizeof(ctypes.c_float) + CIPHER_IV_SIZE + CIPHER_TAG_SIZE)
                enc_preds_proto_list = [enc_preds_proto]
                num_preds_list = [num_preds]
                sig_proto = pointer_to_proto(sig, sig_len)
                sig_proto_list = [sig_proto]
                sig_len_list = [sig_len]
                status = remote_pb2.Status(status=0)
            return remote_pb2.Predictions(predictions=enc_preds_proto_list, num_preds=num_preds_list, status=status, signatures=sig_proto_list, sig_lens=sig_len_list)
        except:
            status = handle_exception()
            return remote_pb2.Predictions(status=status)

    # FIXME: save model only for rank 0 enclave
    def rpc_XGBoosterSaveModel(self, request, context):
        """
        Save model to encrypted file
        """
        try:
            if globals()["is_orchestrator"]:
                sig_proto, sig_len, status = self._synchronize(remote_api.XGBoosterSaveModel, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                sig, sig_len = remote_api.XGBoosterSaveModel(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.StatusMsg(status=status, signature=sig_proto, sig_len=sig_len)
        except:
            status = handle_exception()
            return remote_pb2.StatusMsg(status=status)

    def rpc_XGBoosterLoadModel(self, request, context):
        """
        Load model from encrypted file
        """
        try:
            if globals()["is_orchestrator"]:
                sig_proto, sig_len, status = self._synchronize(remote_api.XGBoosterLoadModel, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                sig, sig_len = remote_api.XGBoosterLoadModel(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.StatusMsg(status=status, signature=sig_proto, sig_len=sig_len)
        except:
            status = handle_exception()
            return remote_pb2.StatusMsg(status=status)

    def rpc_XGBoosterDumpModelEx(self, request, context):
        """
        Get encrypted model dump
        """
        try:
            if globals()["is_orchestrator"]:
                length, sarr, sig_proto, sig_len, status = self._synchronize(remote_api.XGBoosterDumpModelEx, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                length, sarr, sig, sig_len = remote_api.XGBoosterDumpModelEx(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.Dump(sarr=sarr, length=length, status=status, signature=sig_proto, sig_len=sig_len)
        except:
            status = handle_exception()
            return remote_pb2.Dump(status=status)

    def rpc_XGBoosterDumpModelExWithFeatures(self, request, context):
        """
        Get encrypted model dump with features
        """
        try:
            if globals()["is_orchestrator"]:
                length, sarr, sig_proto, sig_len, status = self._synchronize(remote_api.XGBoosterDumpModelExWithFeatures, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                length, sarr, sig, sig_len = remote_api.XGBoosterDumpModelExWithFeatures(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.Dump(sarr=sarr, length=length, status=status, signature=sig_proto, sig_len=sig_len)
        except:
            status = handle_exception()
            return remote_pb2.Dump(status=status)

    def rpc_XGBoosterGetModelRaw(self, request, context):
        """
        Get encrypted raw model dump
        """
        try:
            if globals()["is_orchestrator"]:
                length, sarr, sig_proto, sig_len, status = self._synchronize(remote_api.XGBoosterGetModelRaw, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                length, sarr, sig, sig_len = remote_api.XGBoosterGetModelRaw(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.Dump(sarr=sarr, length=length, status=status, signature=sig_proto, sig_len=sig_len)
        except:
            status = handle_exception()
            return remote_pb2.Dump(status=status)

    def rpc_XGDMatrixNumCol(self, request, context):
        """
        Get number of columns in DMatrix
        """
        try:
            if globals()["is_orchestrator"]:
                ret, sig_proto, sig_len, status = self._synchronize(remote_api.XGDMatrixNumCol, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                ret, sig, sig_len = remote_api.XGDMatrixNumCol(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.Integer(value=ret, status=status, signature=sig_proto, sig_len=sig_len)
        except:
            status = handle_exception()
            return remote_pb2.Integer(status=status)

    def rpc_XGDMatrixNumRow(self, request, context):
        """
        Get number of rows in DMatrix
        """
        try:
            if globals()["is_orchestrator"]:
                ret, sig_proto, sig_len, status = self._synchronize(remote_api.XGDMatrixNumRow, request)
            else:
                signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                ret, sig, sig_len = remote_api.XGDMatrixNumRow(request, signers, signatures, sig_lengths)
                sig_proto = pointer_to_proto(sig, sig_len)
                status = remote_pb2.Status(status=0)
            return remote_pb2.Integer(value=ret, status=status, signature=sig_proto, sig_len=sig_len)
        except:
            status = handle_exception()
            return remote_pb2.Integer(status=status)

    def rpc_RabitInit(self, request, context):
        """
        Initialize rabit
        """
        try:
            if globals()["is_orchestrator"]:
                status = self._synchronize(rabit_remote_api.RabitInit, request)
            else:
                #  signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                rabit_remote_api.RabitInit(request)
                status = remote_pb2.Status(status=0)
            return remote_pb2.StatusMsg(status=status)
        except:
            status = handle_exception()
            return status


    def rpc_RabitFinalize(self, request, context):
        """
        Notify rabit tracker that everything is done
        """
        try:
            if globals()["is_orchestrator"]:
                status = self._synchronize(rabit_remote_api.RabitFinalize, request)
            else:
                #  signers, signatures, sig_lengths = get_signers_signatures_sig_lengths(request)
                rabit_remote_api.RabitFinalize(request)
                status = remote_pb2.Status(status=0)
            return remote_pb2.StatusMsg(status=status)
        except:
            status = handle_exception()
            return status


def serve(all_users=[], nodes=[], nodes_port=50051, num_workers=10, port=50051):
    """
    Launch the RPC server.

    Parameters
    ----------
    all_users : list
        list of usernames participating in the joint computation
    nodes : list
        list of IP addresses of nodes in the cluster. Passing in this argument means that this RPC server is the RPC orchestrator
    nodes_port : int
        port of each RPC server in cluster 
    num_workers : int
        number of threads to use
    port : int
        port on which to start this RPC server 
    """
    condition = threading.Condition()
    command = Command()
    _USERS.extend(all_users)

    # Sort node IPs to ensure that first element in list is rank 0
    # Above is true because of how tracker assigns ranks
    # Nodes will be passed in if this is the orchestrator
    # FIXME: ensure that the IPs passed in as `nodes` to this function are the same as in hosts.config
    if nodes == []:
        # This is a node in the cluster, i.e. not an orchestrator
        globals()["is_orchestrator"] = False
    else:
        nodes.sort()
        nodes = [addr + ":" + str(nodes_port) for addr in nodes]
        globals()["nodes"] = nodes
        globals()["is_orchestrator"] = True

        print("Hello from the orchestrator!")

    rpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=num_workers))
    remote_pb2_grpc.add_RemoteServicer_to_server(RemoteServicer(condition, command), rpc_server)
    rpc_server.add_insecure_port('[::]:' + str(port))
    rpc_server.start()
    rpc_server.wait_for_termination()

