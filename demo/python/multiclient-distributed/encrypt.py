import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../"

# Encrypt files for user 1
KEY_FILE = "data/key1.txt"

xgb.generate_client_key(KEY_FILE)
xgb.encrypt_file(HOME_DIR + "demo/data/1_2agaricus.txt.train", "data/u1_train.enc", KEY_FILE)
xgb.encrypt_file(HOME_DIR + "demo/data/agaricus.txt.test", "data/u1_test.enc", KEY_FILE)

# Encrypt files for user 2
KEY_FILE = "data/key2.txt"

xgb.generate_client_key(KEY_FILE)
xgb.encrypt_file(HOME_DIR + "demo/data/2_2agaricus.txt.train", "data/u2_train.enc", KEY_FILE)
xgb.encrypt_file(HOME_DIR + "demo/data/agaricus.txt.test", "data/u2_test.enc", KEY_FILE)
