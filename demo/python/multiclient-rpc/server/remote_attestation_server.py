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

import remote_attestation_pb2
import remote_attestation_pb2_grpc
from rpc_utils import *
import os
import sys
import traceback
import numpy as np
import securexgboost as xgb

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../../"

def xgb_load_train_predict():
    """
    This code will have been agreed upon by all parties before being run.
    """
    # FIXME: this shouldn't be hardcoded
    train_enc_1 = HOME_DIR + "demo/python/multiclient-rpc/data/c1_train.enc"
    train_enc_2 = HOME_DIR + "demo/python/multiclient-rpc/data/c2_train.enc"
    dtrain = xgb.DMatrix({"user1": train_enc_1, "user2": train_enc_2}, encrypted=True)

    print("Creating test matrix")
    test_enc = HOME_DIR + "demo/python/multiclient-rpc/data/test.enc"
    dtest = xgb.DMatrix({"user2": test_enc}, encrypted=True) 

    # Set training parameters
    params = {
            "tree_method": "hist",
            "n_gpus": "0",
            "objective": "binary:logistic",
            "min_child_weight": "1",
            "gamma": "0.1",
            "max_depth": "3",
            "verbosity": "1" 
    }

    # Train
    num_rounds = 10
    booster = xgb.train(params, dtrain, num_rounds, evals=[(dtrain, "train"), (dtest, "u2_test")])

    enc_preds, num_preds = booster.predict(dtest, username="user2")
    return enc_preds, num_preds

class RemoteAttestationServicer(remote_attestation_pb2_grpc.RemoteAttestationServicer):

    # FIXME: this function is a duplicate of the one below to maintain backwards compatibility
    def GetAttestation(self, request, context):
        """
        Calls get_remote_report_with_public_key()
        """
        # Get a reference to the existing enclave
        enclave_reference = xgb.Enclave(create_enclave=False)

        # Get report from enclave
        enclave_reference.get_remote_report_with_pubkey()
        pem_key, key_size, remote_report, remote_report_size = enclave_reference.get_report_attrs()

        return remote_attestation_pb2.Report(pem_key=pem_key, key_size=key_size, remote_report=remote_report, remote_report_size=remote_report_size)

    def rpc_get_remote_report_with_pubkey(self, request, context):
        """
        Calls get_remote_report_with_public_key()
        """
        # Get a reference to the existing enclave
        enclave_reference = xgb.Enclave(create_enclave=False)

        # Get report from enclave
        enclave_reference.get_remote_report_with_pubkey()
        pem_key, key_size, remote_report, remote_report_size = enclave_reference.get_report_attrs()

        return remote_attestation_pb2.Report(pem_key=pem_key, key_size=key_size, remote_report=remote_report, remote_report_size=remote_report_size)

    def SendKey(self, request, context):
        """
        Sends encrypted symmetric key, signature over key, and filename of data that was encrypted using the symmetric key
        """
        # Get encrypted symmetric key, signature, and filename from request
        enc_sym_key = request.enc_sym_key
        key_size = request.key_size
        signature = request.signature
        sig_len = request.sig_len

        crypto_utils = xgb.CryptoUtils()
        result = crypto_utils.add_client_key(enc_sym_key, key_size, signature, sig_len)

        return remote_attestation_pb2.Status(status=result)

    def rpc_add_client_key_with_certificate(self, request, context):
        """
        Calls CryptoUtils.add_client_key_with_certificate()
        """
        # Get encrypted symmetric key, signature, and certificate from request
        certificate = request.certificate
        enc_sym_key = request.enc_sym_key
        key_size = request.key_size
        signature = request.signature
        sig_len = request.sig_len

        crypto_utils = xgb.CryptoUtils()
        result = crypto_utils.add_client_key_with_certificate(certificate, enc_sym_key, key_size, signature, sig_len)

        return remote_attestation_pb2.Status(status=result)

    def SendDMatrixAttrs(self, request, context):
        """
        Receives the path of a dmatrix from the client and creates the dmatrix on the server side
        """
        print("Received request to create DMatrix with path: " + request.data)
        data = request.data
        encrypted = request.encrypted 
        label = list(request.label)
        if not len(label):
            label = None
        missing = request.missing
        weight = list(request.weight)
        if not len(weight):
            weight = None
        silent = request.silent
        feature_names = list(request.feature_names)
        if not len(feature_names):
            feature_names = None
        feature_types = list(request.feature_types)
        if not len(feature_types):
            feature_types = None
        nthread = request.nthread
        try:
            dmatrix = xgb.DMatrix(data=data, \
                    encrypted=encrypted, \
                    label=label, \
                    missing=missing, \
                    weight=weight, \
                    silent=silent, \
                    feature_names=feature_names, \
                    feature_types=feature_types, \
                    nthread=nthread)
            return remote_attestation_pb2.Name(name=dmatrix.handle.value)
        except:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_attestation_pb2.Name(name=None)


    def SendBoosterAttrs(self, request, context):
        """
        Receives the path of a dmatrix from the client and creates the dmatrix on the server side
        """
        print("Received request to create Booster with params: " + request.params)
        params = request
        if not len(params):
            params = None
        cache = request.cache
        model_file = request.model_file
        try:
            dmatrix = xgb.Booster(params=params, \
                    cache=cache, \
                    model_file=model_file)
            return remote_attestation_pb2.Name(name=dmatrix.handle.value.decode("utf-8"))
        except:
            e = sys.exc_info()
            print("Error type: " + str(e[0]))
            print("Error value: " + str(e[1]))
            traceback.print_tb(e[2])

            return remote_attestation_pb2.Name(name=None)

    def SignalStart(self, request, context):
        """
        Signal to RPC server that client is ready to start
        """
        signal = request.status
        if signal == 1:
            try:
                enc_preds, num_preds = xgb_load_train_predict()

                # Serialize encrypted predictions
                enc_preds_proto = pointer_to_proto(enc_preds, num_preds * 8)

                return remote_attestation_pb2.Predictions(predictions=enc_preds_proto, num_preds=num_preds, status=1)
            except Exception as e:
                print(e)
                return remote_attestation_pb2.Predictions(predictions=None, num_preds=None, status=0)
        else:
            return remote_attestation_pb2.Predictions(predictions=None, num_preds=None, status=0)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    remote_attestation_pb2_grpc.add_RemoteAttestationServicer_to_server(RemoteAttestationServicer(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig()
    serve()
