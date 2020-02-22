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
import securexgboost as xgb

HOME_DIR = os.getcwd() + "/../../../../"

def xgb_load_train_predict():
    """
    This code will have been agreed upon by all parties before being run.
    """
    print("Creating training matrix")
    dtrain = xgb.DMatrix(HOME_DIR + "demo/enclave/remote-control/client/train.enc", encrypted=True)

    print("Creating test matrix")
    dtest = xgb.DMatrix(HOME_DIR + "demo/enclave/remote-control/client/test.enc", encrypted=True) 

    print("Creating Booster")
    booster = xgb.Booster(cache=(dtrain, dtest))

    print("Beginning Training")

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
    booster.set_param(params)
    print("All parameters set")

    # Train and evaluate
    n_trees = 10
    for i in range(n_trees):
        booster.update(dtrain, i)
        print(booster.eval_set([(dtrain, "train"), (dtest, "test")], i))

    enc_preds, num_preds = booster.predict(dtest)
    return enc_preds, num_preds

class RemoteAttestationServicer(remote_attestation_pb2_grpc.RemoteAttestationServicer):

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
