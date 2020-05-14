import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../../"
KEY_FILE = "key.txt"

xgb.generate_client_key(KEY_FILE)
xgb.encrypt_file(HOME_DIR + "demo/data/agaricus.txt.train", "../data/train.enc", KEY_FILE)
xgb.encrypt_file(HOME_DIR + "demo/data/agaricus.txt.test", "../data/test.enc", KEY_FILE)
