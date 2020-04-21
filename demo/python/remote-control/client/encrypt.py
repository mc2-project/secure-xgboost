import securexgboost as xgb
import os

HOME_DIR = os.getcwd() + "/../../../../"
KEY_FILE = "key.txt"

xgb.CryptoUtils.generate_client_key(KEY_FILE)
xgb.CryptoUtils.encrypt_file(HOME_DIR + "demo/data/agaricus.txt.train", "train.enc", KEY_FILE)
xgb.CryptoUtils.encrypt_file(HOME_DIR + "demo/data/agaricus.txt.test", "test.enc", KEY_FILE)
