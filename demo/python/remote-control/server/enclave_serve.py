import securexgboost as xgb
from remote_attestation_server import serve
import os

OE_ENCLAVE_FLAG_DEBUG = 1
OE_ENCLAVE_FLAG_SIMULATE = 2

HOME_DIR = os.getcwd() + "/../../../../"

print("Creating enclave")

# Uncomment for simulation mode
# enclave = xgb.Enclave(HOME_DIR + "enclave/build/xgboost_enclave.signed", flags=(OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE))

# Uncomment for hardware mode
enclave = xgb.Enclave(HOME_DIR + "enclave/build/xgboost_enclave.signed", flags=(OE_ENCLAVE_FLAG_DEBUG))
print("Waiting for remote attestation...")
serve()
