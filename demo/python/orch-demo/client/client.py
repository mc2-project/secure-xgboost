"""The Python implementation of the GRPC Remote Attestation client."""

from __future__ import print_function
import securexgboost as xgb
import argparse
import os

DIR = os.path.dirname(os.path.realpath(__file__))
HOME_DIR = DIR + "/../../../../"
username = "user1"

def run(channel_addr, sym_key_file, priv_key_file, cert_file):
    xgb.init_user(username, sym_key_file, priv_key_file, cert_file)

    # Remote attestation
    print("Remote attestation")
    enclave_reference = xgb.Enclave(addr=channel_addr)

    # TODO: Add support for Rabit Init for interenclave attestation
    print("Rabit Init")
    xgb.rabit.init()

    # Note: Simulation mode does not support attestation
    # pass in `verify=False` to attest()
    # TODO: Return public key of rank 0 enclave to client
    print("Attesting...")
    enclave_reference.attest(verify=False)
    print("Report successfully verified")
    
    print("Send private key to enclave")
    enclave_reference.add_key()
    
    print("Creating training matrix")
    dtrain = xgb.DMatrix({username: HOME_DIR + "demo/data/agaricus.txt.train.enc"}, encrypted=True)
    if not dtrain:
        print("Error creating dtrain")
        return
    print("dtrain: " + dtrain.handle.value.decode("utf-8"))
    
    print("Creating test matrix")
    dtest = xgb.DMatrix({username: HOME_DIR + "demo/data/agaricus.txt.test.enc"}, encrypted=True)
    if not dtest:
        print("Error creating dtest")
        return
    print("dtest: " + dtest.handle.value.decode("utf-8"))
    
    print("Beginning Training")
    
    # Set training parameters
    params = {
            "tree_method": "hist",
            "n_gpus": "0",
            "objective": "binary:logistic",
            "min_child_weight": "1",
            "gamma": "0.1",
            "max_depth": "3",
            "verbosity": "3" 
    }
    
    # Train and evaluate
    num_rounds = 5 
    print("Training...")
    booster = xgb.train(params, dtrain, num_rounds)
    
    print("booster: " + booster.handle.value.decode("utf-8"))
    
    booster.save_model(HOME_DIR + "demo/python/orch-demo/client/modelfile.model", username)
    print("Saved model")
    #  
    #  # Get encrypted predictions
    #  print("\n\nModel Predictions: ")
    #  predictions, num_preds = booster.predict(dtest, decrypt=False)
    #  
    #  # Decrypt predictions
    #  print(booster.decrypt_predictions_list(predictions, num_preds))
    #  
    # Get fscores of model
    print("\n\nModel Feature Importance: ")
    print(booster.get_fscore())
     
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip-addr", help="orchestrator IP address", required=True)
    parser.add_argument("--symmkey", help="path to symmetrix key used to encrypt data on client", required=True)
    parser.add_argument("--privkey", help="path to user's private key for signing data", required=True)
    parser.add_argument("--cert", help="path to user's public key certificate", required=True)

    args = parser.parse_args()

    channel_addr = str(args.ip_addr) + ":50051" 
    run(channel_addr, str(args.symmkey), str(args.privkey), str(args.cert))
