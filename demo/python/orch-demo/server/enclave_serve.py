import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../../"

log = open("log.txt", "w+")
enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed", log_verbosity=3)
print("Waiting for client...", file=log)
xgb.serve(enclave, all_users=["user1"])
