import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../../"
KEY_FILE = "key2.txt"

xgb.generate_client_key(KEY_FILE)
xgb.encrypt_file(HOME_DIR + "demo/data/2_2agaricus.txt.train", HOME_DIR + "demo/python/multiclient-rpc/data/c2_train.enc", KEY_FILE)
xgb.encrypt_file(HOME_DIR + "demo/data/agaricus.txt.test", HOME_DIR + "demo/python/multiclient-rpc/data/c2_test.enc", KEY_FILE)
