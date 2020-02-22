import securexgboost as xgb
import os

OE_ENCLAVE_FLAG_DEBUG = 1
OE_ENCLAVE_FLAG_SIMULATE = 2

print("Creating enclave")

HOME_DIR = os.getcwd() + "/../../../"

# Uncomment below for enclave simulation mode
#  enclave = xgb.Enclave(HOME_DIR + "enclave/build/xgboost_enclave.signed", flags=(OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE))
enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed", flags=(OE_ENCLAVE_FLAG_DEBUG))

# Remote Attestation
# print("Remote attestation")
# enclave.get_remote_report_with_pubkey()
# enclave.verify_remote_report_and_set_pubkey()

rabit_args = {
        "DMLC_NUM_WORKER": os.environ.get("DMLC_NUM_WORKER"),
        "DMLC_NUM_SERVER": os.environ.get("DMLC_NUM_SERVER"),
        "DMLC_TRACKER_URI": os.environ.get("DMLC_TRACKER_URI"),
        "DMLC_TRACKER_PORT": os.environ.get("DMLC_TRACKER_PORT"),
        "DMLC_ROLE": os.environ.get("DMLC_ROLE"),
        "DMLC_NODE_HOST": os.environ.get("DMLC_NODE_HOST")
}

rargs = [str.encode(str(k) + "=" + str(v)) for k, v in rabit_args.items()]

xgb.rabit.init(rargs)

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
        "verbosity": "1" 
}

# Train and evaluate
num_rounds = 5 
booster = xgb.train(params, dtrain, num_rounds, evals=[(dtrain, "train"), (dtest, "test")])

# Get encrypted predictions
print("\n\nModel Predictions: ")
predictions, num_preds = booster.predict(dtest)

key_file = open("../key_zeros.txt", 'rb')
sym_key = key_file.read() # The key will be type bytes
key_file.close()

crypto = xgb.CryptoUtils()

# Decrypt predictions
print(crypto.decrypt_predictions(sym_key, predictions, num_preds))

xgb.rabit.finalize()
