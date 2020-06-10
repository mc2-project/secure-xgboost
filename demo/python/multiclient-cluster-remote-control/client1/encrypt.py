import securexgboost as xgb
import os

HOME_DIR = os.path.dirname(os.path.realpath(__file__)) + "/../../../../"
KEY_FILE = "key1.txt"

xgb.generate_client_key(KEY_FILE)
xgb.encrypt_file(HOME_DIR + "demo/data/1_2agaricus.txt.train", HOME_DIR + "demo/python/multiclient-remote-control/data/c1_train.enc", KEY_FILE)
xgb.encrypt_file(HOME_DIR + "demo/data/agaricus.txt.test", HOME_DIR + "demo/python/multiclient-remote-control/data/c1_test.enc", KEY_FILE)
