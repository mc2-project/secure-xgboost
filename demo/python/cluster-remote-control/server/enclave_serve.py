import securexgboost as xgb
from remote_attestation_server import serve
import os

OE_ENCLAVE_FLAG_RELEASE = 0
OE_ENCLAVE_FLAG_DEBUG = 1
OE_ENCLAVE_FLAG_SIMULATE = 2

HOME_DIR = os.getcwd() + "/../../../../"

flags = OE_ENCLAVE_FLAG_RELEASE

# Uncomment below for enclave debug mode
flags |= OE_ENCLAVE_FLAG_DEBUG

# Uncomment below for enclave simulation mode
#  flags |= OE_ENCLAVE_FLAG_SIMULATE


print("Creating enclave")

enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed", flags=(flags))

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

print("Waiting for remote attestation...")
serve()
