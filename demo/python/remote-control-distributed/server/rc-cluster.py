import securexgboost as xgb
import os

OE_ENCLAVE_FLAG_RELEASE = 0
OE_ENCLAVE_FLAG_DEBUG = 1
OE_ENCLAVE_FLAG_SIMULATE = 2

print("Creating enclave")

HOME_DIR = os.getcwd() + "/../../../../"

flags = OE_ENCLAVE_FLAG_RELEASE

# Uncomment below for enclave debug mode
flags |= OE_ENCLAVE_FLAG_DEBUG

# Uncomment below for enclave simulation mode
#  flags |= OE_ENCLAVE_FLAG_SIMULATE

enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed", flags=(flags))
crypto = xgb.CryptoUtils()

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
#  crypto.sync_client_key()

#  print("Creating training matrix")
#  dtrain = xgb.DMatrix(HOME_DIR + "demo/python/remote-control-distributed/client/train.enc", encrypted=True)
#  
#  print("Creating test matrix")
#  dtest = xgb.DMatrix(HOME_DIR + "demo/python/remote-control-distributed/client/test.enc", encrypted=True) 
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

if xgb.rabit.get_rank() == 0:
    booster.save_model("demo_model.model")

xgb.rabit.finalize()
