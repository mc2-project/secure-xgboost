import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../../"


enclave = xgb.Enclave(HOME_DIR + "build/enclave/xgboost_enclave.signed", log_verbosity=0)
print("Waiting for client...")
xgb.serve(enclave, all_users=["user1", "user2"], nodes=["172.31.15.184"])
