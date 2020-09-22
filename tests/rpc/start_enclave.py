import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../"

xgb.init_server(enclave_image=HOME_DIR + "build/enclave/xgboost_enclave.signed", usernames=["user1"])

# Start RPC server
xgb.serve(all_users=["user1"], port=50051)
