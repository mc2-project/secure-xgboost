import securexgboost as xgb
import os

DIR = os.path.dirname(os.path.realpath(__file__))
HOME_DIR = DIR + "/../../../"
SYM_KEY_FILE = DIR + "/../../data/key_zeros.txt"
PRIVATE_KEY_FILE = HOME_DIR + "config/user1.pem"
CERT_FILE = HOME_DIR + "config/user1.crt"

username = "user1"
print("Creating enclave")
xgb.init_client(user_name=username, sym_key_file=SYM_KEY_FILE, priv_key_file=PRIVATE_KEY_FILE, cert_file=CERT_FILE)
xgb.init_server(enclave_image=HOME_DIR + "build/enclave/xgboost_enclave.signed", client_list=[username])

# Remote Attestation
print("Remote attestation")
# Note: Simulation mode does not support attestation
# pass in `verify=False` to attest()
xgb.attest()

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

print("Creating training matrix from encrypted file")
dtrain = xgb.DMatrix({username: HOME_DIR + "demo/data/agaricus.txt.train.enc"})

print("Creating test matrix from encrypted file")
dtest = xgb.DMatrix({username: HOME_DIR + "demo/data/agaricus.txt.test.enc"})

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
print("\n\nModel Predictions: ")
predictions, num_preds = booster.predict(dtest, decrypt=False)

# Decrypt predictions
print(booster.decrypt_predictions(predictions, num_preds)[:20])

xgb.rabit.finalize()
