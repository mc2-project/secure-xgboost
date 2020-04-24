import securexgboost as xgb
import os

xgb.set_user("user1")
print("Creating enclave")
DIR = os.path.dirname(os.path.realpath(__file__))
HOME_DIR = DIR + "/../../../"
SYM_KEY_FILE = DIR + "/../../data/key_zeros.txt"
PUB_KEY_FILE = DIR + "/../../data/keypair.pem"

enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed")
crypto = xgb.CryptoUtils()

# Remote Attestation
print("Remote attestation")
enclave.get_remote_report_with_pubkey()
# NOTE: Verification will fail in simulation mode
# Comment out this line for testing the code in simulation mode
# enclave.verify_remote_report_and_set_pubkey()

print("Send private key to enclave")
enclave_pem_key, enclave_key_size, _, _ = enclave.get_report_attrs()
sym_key = None
with open(SYM_KEY_FILE, "rb") as keyfile:
    sym_key = keyfile.read()
# Encrypt the symmetric key using the enclave's public key
enc_sym_key, enc_sym_key_size = crypto.encrypt_data_with_pk(sym_key, len(sym_key), 
                                                            enclave_pem_key, enclave_key_size)
# Sign the encrypted symmetric key (so enclave can verify it came from the client)
sig, sig_size = crypto.sign_data(PUB_KEY_FILE, enc_sym_key, enc_sym_key_size)
# Send the encrypted key to the enclave
crypto.add_client_key(enc_sym_key, enc_sym_key_size, sig, sig_size)

print("Creating training matrix")
dtrain = xgb.DMatrix({"user1": HOME_DIR + "demo/data/agaricus.txt.train.enc"}, encrypted=True)

print("Creating test matrix")
dtest = xgb.DMatrix({"user1": HOME_DIR + "demo/data/agaricus.txt.test.enc"}, encrypted=True) 

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

# Decrypt predictions
print(crypto.decrypt_predictions(sym_key, predictions, num_preds))

# Get fscores of model
print("\n\nModel Feature Importance: ")
print(booster.get_fscore(sym_key))
