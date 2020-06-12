import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../../"

xgb.serve(all_users=["user1"], nodes=["127.0.0.1"], port=50052)
