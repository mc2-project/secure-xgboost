import securexgboost as xgb
import os

OE_ENCLAVE_FLAG_RELEASE = 0
OE_ENCLAVE_FLAG_DEBUG = 1
OE_ENCLAVE_FLAG_SIMULATE = 2

print("Creating enclave")
DIR = os.path.dirname(os.path.realpath(__file__))
HOME_DIR = DIR + "/../../../"

flags = OE_ENCLAVE_FLAG_RELEASE

# Uncomment below for enclave debug mode
#  flags |= OE_ENCLAVE_FLAG_DEBUG

# Uncomment below for enclave simulation mode
#  flags |= OE_ENCLAVE_FLAG_SIMULATE

enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed", flags=(flags))
crypto = xgb.CryptoUtils()

# Remote Attestation
print("Remote attestation")
enclave.get_remote_report_with_pubkey()
enclave.verify_remote_report_and_set_pubkey()

print("Creating training matrix")
dtrain = xgb.DMatrix(HOME_DIR + "demo/data/agaricus.txt.train.enc", encrypted=True)

print("Creating test matrix")
dtest = xgb.DMatrix(HOME_DIR + "demo/data/agaricus.txt.test.enc", encrypted=True) 

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
booster = xgb.train(params, dtrain, num_rounds, evals=[(dtrain, "train"), (dtest, "test")])

# Get encrypted predictions
print("\n\nModel Predictions: ")
predictions, num_preds = booster.predict(dtest)

key_file = open(HOME_DIR +  "demo/python/" + "key_zeros.txt", 'rb')
sym_key = key_file.read() # The key will be type bytes
key_file.close()

# Decrypt predictions
print(crypto.decrypt_predictions(sym_key, predictions, num_preds))

# Get fscores of model
print("\n\nModel Feature Importance: ")
print(booster.get_fscore(sym_key))
