import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../../"

xgb.init(enclave_image=HOME_DIR + "build/enclave/xgboost_enclave.signed", log_verbosity=0)
print("Waiting for clients...")
xgb.serve(all_users=["user1", "user2"])
