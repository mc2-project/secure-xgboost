import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../../"

with open("../hosts.config") as f:
    nodes = f.readlines()
nodes = [x.strip().split(":")[0] for x in nodes]

print("Waiting for client...")
xgb.serve(all_users=["user1", "user2"], nodes=nodes, port=50051)
