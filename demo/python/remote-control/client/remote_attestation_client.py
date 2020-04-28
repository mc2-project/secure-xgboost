"""The Python implementation of the GRPC Remote Attestation client."""

from __future__ import print_function
import logging

import grpc
import base64

import securexgboost as xgb
import argparse
import os

DIR = os.path.dirname(os.path.realpath(__file__))
HOME_DIR = DIR + "/../../../../"

def run(channel_addr, sym_key_file, pub_key_file):

    xgb.init_user("user1", sym_key_file, pub_key_file)

    # Remote attestation
    print("Remote attestation")
    enclave_reference = xgb.Enclave()
    enclave_reference.get_report()
    # enclave_reference.verify_report()
    print("Report successfully verified")

    print("Send private key to enclave")
    enclave_reference.add_key()

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
    print("Training...")
    booster = xgb.train(params, dtrain, num_rounds)

    print("booster: " + booster.handle.value.decode("utf-8"))

    booster.save_model(HOME_DIR + "/demo/python/remote-control/client/modelfile.model", "user1")

    booster = xgb.Booster(cache=[dtrain, dtest])
    booster.load_model(HOME_DIR + "/demo/python/remote-control/client/modelfile.model", "user1")

    # Get encrypted predictions
    print("\n\nModel Predictions: ")
    predictions, num_preds = booster.predict(dtest, decrypt=False)

    # Decrypt predictions
    print(booster.decrypt_predictions(predictions, num_preds))

    # Get fscores of model
    print("\n\nModel Feature Importance: ")
    print(booster.get_fscore())
     
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
