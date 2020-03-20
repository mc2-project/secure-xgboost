import securexgboost as xgb
import os

print("Creating enclave")
DIR = os.path.dirname(os.path.realpath(__file__))
HOME_DIR = DIR + "/../../../"

enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed")

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
booster.save_model(DIR + "/demo_model.model")

# Get encrypted predictions
print("True Labels: ")
print(dtest.get_float_info("label")[:20])
print("\nModel Predictions: ")
predictions, num_preds = booster.predict(dtest)

key_file = open("../key_zeros.txt", 'rb')
sym_key = key_file.read() # The key will be type bytes
key_file.close()

crypto = xgb.CryptoUtils()

# Decrypt predictions
print(crypto.decrypt_predictions(sym_key, predictions, num_preds)[:20])

xgb.rabit.finalize()
