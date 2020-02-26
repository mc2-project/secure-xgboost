import securexgboost as xgb
from remote_attestation_server import serve
import os

OE_ENCLAVE_FLAG_RELEASE = 0
OE_ENCLAVE_FLAG_DEBUG = 1
OE_ENCLAVE_FLAG_SIMULATE = 2

HOME_DIR = os.getcwd() + "/../../../../"

flags = OE_ENCLAVE_FLAG_RELEASE

# Uncomment below for enclave debug mode
#  flags |= OE_ENCLAVE_FLAG_DEBUG

# Uncomment below for enclave simulation mode
#  flags |= OE_ENCLAVE_FLAG_SIMULATE


print("Creating enclave")

enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed", flags=(flags))
print("Waiting for remote attestation...")
serve()
