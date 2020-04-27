"""The Python implementation of the GRPC Remote Attestation client."""

from __future__ import print_function
import logging

import grpc
import base64

import remote_attestation_pb2
import remote_attestation_pb2_grpc

import securexgboost as xgb
import argparse
import os
from rpc_utils import *

DIR = os.path.dirname(os.path.realpath(__file__))
HOME_DIR = DIR + "/../../../../"

def run(channel_addr, key_path, keypair):
    """
    The client will make 4 calls to the server that will run computation
    1. A call to retrieve the attestation report from the server. The client will use this report
    to verify that the it can trust the server.
    2. A call to send the symmetric key used to encrypt the data to the server.
    3. A call to commence computation.
    """
    xgb.set_user("user1")

    # Initialized the RPC API
    # rpc_server = xgb.RPCServer(channel_addr)

    # Get remote report from enclave
    # response = rpc_server.get_remote_report()

    # pem_key = response.pem_key
    # key_size = response.key_size
    # remote_report = response.remote_report
    # remote_report_size = response.remote_report_size
    # print("Report received from remote enclave")

    # Verify report
    enclave_reference = xgb.Enclave(create_enclave=False)
    enclave_reference.get_remote_report_with_pubkey()
    # enclave_reference.set_report_attrs(pem_key, key_size, remote_report, remote_report_size)
    # enclave_reference.verify_remote_report_and_set_pubkey()
    print("Report successfully verified")

    pem_key, key_size, _, _ = enclave_reference.get_report_attrs()
    # Encrypt and sign symmetric key used to encrypt data
    key_file = open(key_path, 'rb')
    sym_key = key_file.read() # The key will be type bytes
    key_file.close()

    crypto_utils = xgb.CryptoUtils()

    # Encrypt symmetric key
    enc_sym_key, enc_sym_key_size = crypto_utils.encrypt_data_with_pk(sym_key, len(sym_key), pem_key, key_size)
    print("Encrypted symmetric key")

    # Sign encrypted symmetric key
    sig, sig_len = crypto_utils.sign_data(keypair, enc_sym_key, enc_sym_key_size) 
    print("Signed ciphertext")

    # FIXME add with cert
    # Send data key to the server
    crypto_utils.add_client_key(enc_sym_key, enc_sym_key_size, sig, sig_len)
    # response = rpc_server.send_data_key(enc_sym_key, enc_sym_key_size, sig, sig_len)
    print("Symmetric key for data sent to server")
    # TODO: do this instead 
    # response = crypto_utils.add_client_key(enc_sym_key, key_size, signature, sig_len)
 
    print("Creating training matrix")
    dtrain = xgb.DMatrix({"user1": HOME_DIR + "demo/data/agaricus.txt.train.enc"}, encrypted=True)
    if not dtrain:
        print("Error creating dtrain")
        return
    print("dtrain: " + dtrain.handle.value.decode("utf-8"))

    print("Creating test matrix")
    dtest = xgb.DMatrix({"user1": HOME_DIR + "demo/data/agaricus.txt.test.enc"}, encrypted=True)
    if not dtest:
        print("Error creating dtest")
        return
    print("dtest: " + dtest.handle.value.decode("utf-8"))

    # return

    print("Beginning Training")

    # Set training parameters
    params = {
            "tree_method": "hist",
            "n_gpus": "0",
            "objective": "binary:logistic",
            "min_child_weight": "1",
            "gamma": "0.1",
            "max_depth": "3",
            "verbosity": "0" 
    }

    # Train and evaluate
    num_rounds = 5 
    booster = xgb.train(params, dtrain, num_rounds)

    print("booster: " + booster.handle.value.decode("utf-8"))

    booster.save_model(HOME_DIR + "/demo/python/remote-control/client/modelfile.model", "user1")

    booster = xgb.Booster(cache=[dtrain, dtest])
    booster.load_model(HOME_DIR + "/demo/python/remote-control/client/modelfile.model", "user1")

    # Get encrypted predictions
    print("\n\nModel Predictions: ")
    predictions, num_preds = booster.predict(dtest)

    key_file = open(key_path, 'rb')
    sym_key = key_file.read() # The key will be type bytes
    key_file.close()

    # Decrypt predictions
    print(crypto_utils.decrypt_predictions(sym_key, predictions, num_preds))

    # Get fscores of model
    print("\n\nModel Feature Importance: ")
    print(booster.get_fscore(sym_key))
     
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip-addr", help="server IP address", required=True)
    parser.add_argument("--key", help="path to key used to encrypt data on client", required=True)
    parser.add_argument("--keypair", help="path to keypair for signing data", required=True)

    args = parser.parse_args()

    channel_addr = str(args.ip_addr) + ":50051" 
    os.environ["RA_CHANNEL_ADDR"] = channel_addr

    logging.basicConfig()
    run(channel_addr, str(args.key), str(args.keypair))
