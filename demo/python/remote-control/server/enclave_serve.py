import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../../"

print("Creating enclave")

enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed", log_verbosity=0)
print("Waiting for remote attestation...")
xgb.serve(enclave)
