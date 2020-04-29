import securexgboost as xgb
import os

username = "user1"
DIR = os.path.dirname(os.path.realpath(__file__))
HOME_DIR = DIR + "/../../../"
SYM_KEY_FILE = DIR + "/../../data/key_zeros.txt"
PUB_KEY_FILE = DIR + "/../../data/keypair.pem"

xgb.init_user(username, SYM_KEY_FILE, PUB_KEY_FILE)

print("Creating enclave")
enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed")

# Remote Attestation
print("Remote attestation")
enclave.attest(verify=False)

print("Send private key to enclave")
enclave.add_key()

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
        "verbosity": "0" 
}

# Train and evaluate
num_rounds = 5 
booster = xgb.train(params, dtrain, num_rounds, evals=[(dtrain, "train"), (dtest, "test")])

# Save model to a file
booster.save_model(HOME_DIR + "/demo/python/basic/modelfile.model")

# Get encrypted predictions
print("\n\nModel Predictions: ")
predictions, num_preds = booster.predict(dtest, decrypt=False)

# Decrypt predictions
print(booster.decrypt_predictions(predictions, num_preds))

# Get fscores of model
print("\n\nModel Feature Importance: ")
print(booster.get_fscore())
